"""Actual TLS proofs, durable CAS and interrupted original consumption recovery."""
from contextlib import closing,contextmanager
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch
from zrotext_native_candidate import OriginalReplyCheckpoint,OriginalReplyError
from zrotext_native_candidate import sealed_candidate as s
import test_original_reply as reply
import test_sealed_http as http


class DurableReplyTests(unittest.TestCase):
    client_with=http.SealedHttpTests.client_with
    permit=http.SealedHttpTests.permit
    respond=reply.OriginalReplyTests.respond
    reply_with=reply.OriginalReplyTests.reply_with

    @classmethod
    def setUpClass(cls):
        http.SealedHttpTests.setUpClass.__func__(cls);cls.original=reply.fixture()

    def setUp(self):
        http.SealedHttpTests.setUp(self)
        self.scope,self.custody,self.history=reply.material(self.original)
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)/'reply.sqlite'
        self.store=OriginalReplyCheckpoint.create(self.path,reply.decode(self.original['rootPin']),reply.decode(self.original['fingerprint']),
                            scope=self.scope,accepted_history=self.history,comparison_ms=self.now)
        self.client=self.durable()

    def reopen(self,**changes):
        args=dict(scope=self.scope);args.update(changes)
        return OriginalReplyCheckpoint(self.path,reply.decode(self.original['rootPin']),reply.decode(self.original['fingerprint']),**args)

    def durable(self):return self.reply_with(accepted_history=None,checkpoint=self.reopen())

    def snapshot(self):return self.reopen().snapshot(scope=self.scope,comparison_ms=self.now)

    def consumption(self):
        request=dict(request_id=str(uuid.UUID(int=900)),event_id=reply.text(reply.decode(self.original['event'])),active_request_id=None,descriptor=None)
        result=dict(event_id=request['event_id'],consumption_id=request['request_id'],disposition='owner_review',active_request_id=None,action=None)
        return request,result

    def test_successor_survives_restart_old_proof_and_clock_refused(self):
        self.now=10001;self.respond('current',reply.proof(self.original,version=3));self.client.current()
        revision,comparison,history=self.snapshot();self.assertEqual((revision,comparison,len(history)),(2,10001,3))
        restarted=self.durable();self.respond('current',reply.proof(self.original))
        with self.assertRaises(OriginalReplyError):restarted.current()
        self.assertEqual(self.snapshot()[:2],(2,10001))
        self.now=10000
        with self.assertRaises(OriginalReplyError):self.durable()

    def test_plaintext_waits_for_both_committed_proofs(self):
        self.respond('read',reply.read_result(self.original));self.respond('current',reply.proof(self.original))
        self.assertEqual(self.client.read(reply.decode(self.original['event'])),self.original['text'])
        self.assertEqual(self.snapshot()[0],3)
        self.assertEqual(len(self.durable()._history),2)

    def test_two_concurrent_clients_only_one_cas_winner(self):
        other=self.durable();self.respond('current',reply.proof(self.original));self.client.current()
        self.respond('current',reply.proof(self.original))
        with self.assertRaises(OriginalReplyError) as caught:other.current()
        self.assertEqual(caught.exception.state,'unavailable');self.assertEqual(self.snapshot()[0],2)
        request,_=self.consumption();self.respond('current',reply.proof(self.original))
        with self.assertRaises(OriginalReplyError):other.consume(request)
        self.assertNotIn('consume',[json.loads(c[3])['method'] for c in self.calls])

    def test_simultaneous_writers_cannot_both_commit_expected_revision(self):
        gate=threading.Barrier(2)
        def write():
            store=self.reopen();revision,_,history=store.snapshot(scope=self.scope,comparison_ms=self.now);gate.wait(timeout=10)
            try:return store.accept(history,scope=self.scope,expected_revision=revision,comparison_ms=self.now)[0]
            except s.SealedError:return None
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:write(),range(2)))
        self.assertEqual(results.count(2),1);self.assertEqual(results.count(None),1);self.assertEqual(self.snapshot()[0],2)

    def test_same_version_clock_commits_and_consume_status_have_fences(self):
        request,result=self.consumption()
        for method,value in [('current',reply.proof(self.original)),('consume',result),('current',reply.proof(self.original))]:self.respond(method,value)
        self.assertEqual(self.client.consume(request),result);self.assertEqual(self.snapshot()[0],3)
        restarted=self.durable()
        for method,value in [('current',reply.proof(self.original)),('status',result),('current',reply.proof(self.original))]:self.respond(method,value)
        self.assertEqual(restarted.status(request['request_id']),result);self.assertEqual(self.snapshot()[0],5)
        self.assertEqual([json.loads(c[3])['method'] for c in self.calls],['current','consume','current','current','status','current'])

    def test_postcommit_failure_is_unknown_after_consume_and_explicit_reopen_recovers(self):
        request,result=self.consumption();store=self.client._checkpoint;real=store._connection;commits=[]
        class Proxy:
            def __init__(self,db):self.db=db
            def __getattr__(self,name):return getattr(self.db,name)
            def commit(self):
                self.db.commit();commits.append(1)
                if len(commits)==2:raise OSError('synthetic lost commit acknowledgement')
        @contextmanager
        def uncertain(*args,**kwargs):
            with real(*args,**kwargs) as db:yield Proxy(db)
        for method,value in [('current',reply.proof(self.original)),('consume',result),('current',reply.proof(self.original))]:self.respond(method,value)
        with patch.object(store,'_connection',uncertain):
            with self.assertRaises(OriginalReplyError) as caught:self.client.consume(request)
        self.assertEqual(caught.exception.state,'unknown');self.assertEqual(self.snapshot()[0],3)
        restarted=self.durable()
        for method,value in [('current',reply.proof(self.original)),('status',result),('current',reply.proof(self.original))]:self.respond(method,value)
        self.assertEqual(restarted.status(request['request_id']),result)
        self.assertEqual(sum(json.loads(c[3])['method']=='consume' for c in self.calls),1)

    def test_postcommit_expiry_releases_no_plaintext_and_requires_reopen(self):
        real=self.client._checkpoint.accept;count=[]
        def delayed(*args,**kwargs):
            value=real(*args,**kwargs);count.append(1)
            if len(count)==2:self.now=20000
            return value
        self.respond('read',reply.read_result(self.original));self.respond('current',reply.proof(self.original))
        with patch.object(self.client._checkpoint,'accept',delayed):
            with self.assertRaises(OriginalReplyError):self.client.read(reply.decode(self.original['event']))
        self.assertEqual(self.snapshot()[0],3)

    def test_postcommit_observation_is_durable_before_returned_authority(self):
        real=self.client._checkpoint.accept;count=[]
        def delayed(*args,**kwargs):
            value=real(*args,**kwargs);count.append(1)
            if len(count)==1:self.now=11000
            return value
        self.respond('current',reply.proof(self.original))
        with patch.object(self.client._checkpoint,'accept',delayed):authority=self.client.current()
        self.assertEqual((authority['now_ms'],self.client._last),(11000,11000))
        self.assertEqual(self.snapshot()[:2],(3,11000));self.now=10500
        with self.assertRaises(OriginalReplyError):self.durable()

    def test_final_comparison_commit_failure_releases_no_plaintext(self):
        real=self.client._checkpoint.accept;count=[]
        def failed(*args,**kwargs):
            count.append(1)
            if len(count)==3:raise OSError('synthetic final comparison refusal')
            value=real(*args,**kwargs)
            if len(count)==2:self.now=11000
            return value
        self.respond('read',reply.read_result(self.original));self.respond('current',reply.proof(self.original))
        with patch.object(self.client._checkpoint,'accept',failed):
            with self.assertRaises(OriginalReplyError):self.client.read(reply.decode(self.original['event']))
        self.assertEqual(self.snapshot()[:2],(3,10000))

    def test_final_comparison_lost_commit_after_consumption_is_unknown(self):
        real=self.client._checkpoint.accept;count=[];request,result=self.consumption()
        def uncertain(*args,**kwargs):
            value=real(*args,**kwargs);count.append(1)
            if len(count)==2:self.now=11000
            if len(count)==3:raise OSError('synthetic final comparison acknowledgement loss')
            return value
        for method,value in [('current',reply.proof(self.original)),('consume',result),('current',reply.proof(self.original))]:self.respond(method,value)
        with patch.object(self.client._checkpoint,'accept',uncertain):
            with self.assertRaises(OriginalReplyError) as caught:self.client.consume(request)
        self.assertEqual(caught.exception.state,'unknown');self.assertEqual(self.snapshot()[:2],(4,11000))
        self.now=10500
        with self.assertRaises(OriginalReplyError):self.durable()
        self.assertEqual(sum(json.loads(c[3])['method']=='consume' for c in self.calls),1)

    def test_missing_foreign_scope_tampered_history_and_recreate_refused(self):
        with self.assertRaises(Exception):OriginalReplyCheckpoint.create(self.path,reply.decode(self.original['rootPin']),reply.decode(self.original['fingerprint']),scope=self.scope,accepted_history=self.history,comparison_ms=self.now)
        foreign=dict(self.scope,read_grant=bytes([99])*16)
        with self.assertRaises(s.SealedError):self.reopen(scope=foreign)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE manifests SET signed=? WHERE version=2',(reply.decode(self.original['successor']),));db.commit()
        with self.assertRaises(s.SealedError):self.reopen()
        self.path.unlink()
        with self.assertRaises(s.SealedError):self.reopen()
        self.assertFalse(self.path.exists())

    def test_process_death_before_commit_rolls_back_manifest_and_clock_together(self):
        # Exercise accept's actual commit boundary in another process. No Python
        # finally/rollback executes: SQLite recovers the uncommitted transaction.
        program='''
import base64,json,os,sys
from contextlib import contextmanager
from zrotext_native_candidate import OriginalReplyCheckpoint
from zrotext_native_candidate import sealed_candidate as s
data=json.load(sys.stdin);scope={k:(v if k=='peer' else bytes.fromhex(v)) for k,v in data['scope'].items()}
store=OriginalReplyCheckpoint(data['path'],bytes.fromhex(data['pin']),bytes.fromhex(data['fingerprint']),scope=scope)
revision,_,history=store.snapshot(scope=scope,comparison_ms=10001)
last=s._bound(s._manifests,history[-1]);next_token=s._accept(s._manifests,s._parse_manifest(base64.b64decode(data['successor']),last.trust,10001))
real=store._connection
class Proxy:
 def __init__(self,db):self.db=db
 def __getattr__(self,name):return getattr(self.db,name)
 def commit(self):os._exit(23)
@contextmanager
def interrupted(*args,**kwargs):
 with real(*args,**kwargs) as db:yield Proxy(db)
store._connection=interrupted
store.accept(list(history)+[next_token],scope=scope,expected_revision=revision,comparison_ms=10001)
'''
        data=dict(path=str(self.path),pin=reply.decode(self.original['rootPin']).hex(),fingerprint=reply.decode(self.original['fingerprint']).hex(),
                  scope={k:v.hex() if type(v) is bytes else v for k,v in self.scope.items()},successor=self.original['successor'])
        result=subprocess.run([sys.executable,'-c',program],input=json.dumps(data),text=True,capture_output=True)
        self.assertEqual(result.returncode,23,result.stderr);revision,comparison,history=self.snapshot()
        self.assertEqual((revision,comparison,len(history)),(1,10000,2))


if __name__=='__main__':unittest.main()
