"""Real SQLite contact CAS and fresh maintained TypeScript signed evidence."""
import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import subprocess
import sys
import unittest
from unittest.mock import patch

from zrotext_native_candidate import contact_history as h
from zrotext_native_candidate import contact_integrity as c
from zrotext_native_candidate import checkpoint_store as cp
from test_contact_integrity import fixture,material,decode


class HistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'contacts.db';self.root=Path(self.temp.name)/'root.db'
        f=self.f;self.first,self.second,self.old,self.new=material(f)
        self.pin=decode(f['rootPin']);self.fp=decode(f['fingerprint']);self.ident=decode(f['contact'])
        self.store=cp.CheckpointStore(self.root,self.pin,self.fp)
        self.store.accept_manifest(decode(f['manifest']),0,10000)
        self.scope=dict(contact=self.ident,routing_digest=decode(f['routing']))
        fields={k:c.verify_contact_field01(decode(f[k]),self.new if k=='replacement' else self.old,**self.scope) for k in ('name','notes','replacement')}
        mutations={k:c.verify_contact_mutation01(decode(f[k]),self.old if k=='create' else self.new,**self.scope) for k in ('create','update','clear')}
        self.initial=c.verify_contact_transition01(None,mutations['create'],[fields['name'],fields['notes']])
        self.changed=c.verify_contact_transition01(self.initial,mutations['update'],[fields['replacement']])
        self.final=c.verify_contact_transition01(self.changed,mutations['clear'],[])
    def open(self,**kw):
        v=h.ContactHistory(self.path,self.pin,self.fp,origin=self.f['origin'],maximum_records=1,root_history_path=self.root,**kw)
        self.addCleanup(v.close);return v
    def create(self):return self.open(create=True)
    def accept(self,adapter,expected=None,transition=None,statement=None):
        return adapter.accept(expected=expected,transition=transition or self.initial,statement=statement or self.old)
    def advance(self):self.store.accept_manifest(decode(self.f['nextManifest']),1,10000)
    def test_restart_full_chain_idempotence_terminal_reduction_and_metadata_only(self):
        a=self.create();self.assertEqual(a.lookup(self.ident),dict(kind='unavailable',reason='unobserved'))
        first=self.accept(a);self.assertEqual(first['kind'],'accepted_local_history')
        self.assertIs(a.lookup(self.ident)['token'],first['token'])
        same=self.accept(a,first['token']);self.assertIs(first['token'],same['token'])
        a.close();a=self.open();old=a.lookup(self.ident);self.advance()
        changed=self.accept(a,old['token'],self.changed,self.new)
        final=self.accept(a,changed['token'],self.final,self.new)
        self.assertEqual(final['metadata']['revision'],3)
        final['metadata']['revision']=99;self.assertEqual(a.lookup(self.ident)['metadata']['revision'],3)
        reduced=a.mark_unavailable(expected=final['token']);self.assertEqual(reduced['reason'],'local_stop')
        self.assertIs(a.mark_unavailable(expected=reduced['token'])['token'],reduced['token'])
        with self.assertRaises(h.ContactHistoryError):self.accept(a,reduced['token'])
        a.close();a=self.open();self.assertEqual(a.lookup(self.ident)['reason'],'local_stop')
        with closing(sqlite3.connect(self.path)) as db, db:
            payload=db.execute('SELECT payload FROM contacts').fetchone()[0]
            self.assertEqual(set(json.loads(payload)),{'schema','state','contactId'})
            self.assertEqual(json.loads(db.execute('SELECT payload FROM header').fetchone()[0])['count'],1)
    def test_exact_tokens_and_concurrent_database_cas(self):
        a=self.create();first=self.accept(a);b=self.open();other=b.lookup(self.ident)
        with self.assertRaises(h.ContactHistoryError):a.mark_unavailable(expected=other['token'])
        with self.assertRaises(h.ContactHistoryError):self.accept(a,None)
        self.advance();self.accept(a,first['token'],self.changed,self.new)
        with self.assertRaises(h.ContactHistoryError):b.mark_unavailable(expected=other['token'])
        with self.assertRaises(h.ContactHistoryError):self.accept(a,first['token'],self.changed,self.new)
        self.assertEqual(b.lookup(self.ident)['metadata']['revision'],2)
    def test_missing_or_rolled_back_root_evidence_allows_only_reduction(self):
        a=self.create();first=self.accept(a);self.advance();changed=self.accept(a,first['token'],self.changed,self.new)
        a.close()
        with closing(sqlite3.connect(self.root)) as db, db:db.execute('DELETE FROM manifests WHERE revision=2')
        a=self.open();unavailable=a.lookup(self.ident);self.assertEqual(unavailable['reason'],'history_missing')
        with self.assertRaises(h.ContactHistoryError):self.accept(a,unavailable['token'],self.final,self.new)
        a.close();self.root.unlink();a=self.open(reduction_only=True)
        self.assertEqual(a.lookup(self.ident)['reason'],'reduction_only')
        a.mark_unavailable(expected=a.lookup(self.ident)['token'])
        with self.assertRaises(h.ContactHistoryError):self.open()
    def test_corrupt_rows_and_headers_are_not_cleared(self):
        a=self.create();self.accept(a);a.close()
        with closing(sqlite3.connect(self.path)) as db, db:
            original=db.execute('SELECT payload FROM contacts').fetchone()[0]
            db.execute('UPDATE contacts SET payload=?',(original[:-1]+',"unknown":true}',))
        with self.assertRaises(h.ContactHistoryError):self.open(reduction_only=True)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertIn('unknown',db.execute('SELECT payload FROM contacts').fetchone()[0])
            db.execute('UPDATE contacts SET payload=?',(original,))
            header=json.loads(db.execute('SELECT payload FROM header').fetchone()[0]);header['count']=0
            db.execute('UPDATE header SET payload=?',(h._dump(header),))
        with self.assertRaises(h.ContactHistoryError):self.open()
    def test_forged_brands_skipped_revisions_and_wrong_statement(self):
        a=self.create()
        for transition,statement in (({},self.old),(self.initial,{}),(self.initial,self.new)):
            with self.assertRaises(h.ContactHistoryError):a.accept(expected=None,transition=transition,statement=statement)
        first=self.accept(a);self.advance()
        with self.assertRaises(h.ContactHistoryError):self.accept(a,first['token'],self.final,self.new)
    def test_postcommit_root_change_requires_recheck(self):
        a=self.create();original=a._connection
        @contextmanager
        def connection(*args,**kwargs):
            with original(*args,**kwargs) as db:yield db
            self.advance()
        with patch.object(a,'_connection',connection):result=self.accept(a)
        self.assertEqual(result,dict(kind='recorded_needs_recheck'))
        self.assertEqual(a.lookup(self.ident)['metadata']['revision'],1)
    def test_postcommit_close_is_unknown_and_restart_reconciles(self):
        a=self.create();original=a._connection
        @contextmanager
        def connection(*args,**kwargs):
            with original(*args,**kwargs) as db:yield db
            a.close()
        with patch.object(a,'_connection',connection):result=self.accept(a)
        self.assertEqual(result,dict(kind='write_unknown'))
        self.assertEqual(self.open().lookup(self.ident)['metadata']['revision'],1)
    def test_close_during_final_root_comparison_retains_unknown_outcome(self):
        a=self.create();original=a._root_snapshot;calls=0
        def snapshot():
            nonlocal calls
            result=original();calls+=1
            if calls==4:a.close()
            return result
        with patch.object(a,'_root_snapshot',snapshot):result=self.accept(a)
        self.assertEqual(result,dict(kind='write_unknown'))
        self.assertEqual(self.open().lookup(self.ident)['metadata']['revision'],1)
    def test_close_after_metadata_read_refuses_every_early_lookup_result(self):
        def check(adapter):
            original=adapter._connection
            @contextmanager
            def connection(*args,**kwargs):
                with original(*args,**kwargs) as db:yield db
                adapter.close()
            with patch.object(adapter,'_connection',connection),self.assertRaises(h.ContactHistoryError):adapter.lookup(self.ident)
        check(self.create())
        a=self.open();self.accept(a);a.close()
        check(self.open(reduction_only=True))
        a=self.open();a.mark_unavailable(expected=a.lookup(self.ident)['token']);check(a)
    def test_busy_lifetime_and_adapter_capacity(self):
        a=self.create()
        with a._busy:
            with self.assertRaises(h.ContactHistoryError):a.lookup(self.ident)
        others=[self.open() for _ in range(3)]
        with self.assertRaises(h.ContactHistoryError):self.open()
        for item in others:item.close()
        with patch.object(a,'_born',a._born-1801):
            with self.assertRaises(h.ContactHistoryError):a.lookup(self.ident)
        self.assertTrue(a._closed)
    def test_missing_and_mismatched_database_never_reinitialized(self):
        with self.assertRaises(h.ContactHistoryError):self.open()
        self.assertFalse(self.path.exists())
        a=self.create();a.close()
        with self.assertRaises(h.ContactHistoryError):h.ContactHistory(self.path,self.pin,self.fp,origin='https://other.invalid',maximum_records=1,root_history_path=self.root)
        self.assertEqual(self.open().lookup(self.ident)['reason'],'unobserved')


    def test_two_real_concurrent_reductions_have_one_exact_cas_winner(self):
        a=self.create();first=self.accept(a);b=self.open();second=b.lookup(self.ident)
        start=threading.Barrier(2)
        def reduce(adapter,token):
            start.wait()
            try:return adapter.mark_unavailable(expected=token)['reason']
            except h.ContactHistoryError:return 'refused'
        with ThreadPoolExecutor(max_workers=2) as executor:
            x=executor.submit(reduce,a,first['token']);y=executor.submit(reduce,b,second['token'])
            self.assertEqual(sorted([x.result(),y.result()]),['local_stop','refused'])

    def test_full_capacity_and_max_revision_terminal_reduction(self):
        a=self.create();self.accept(a);a.close()
        with closing(sqlite3.connect(self.path)) as db,db:
            row=json.loads(db.execute('SELECT payload FROM contacts').fetchone()[0]);row['revision']=2**63-1
            db.execute('UPDATE contacts SET payload=?',(h._dump(row),))
        a=self.open(reduction_only=True);self.assertEqual(a.mark_unavailable(expected=a.lookup(self.ident)['token'])['reason'],'local_stop');a.close()
        with closing(sqlite3.connect(self.path)) as db,db:
            other=bytes([9])*16;row=dict(schema=1,state='unavailable',contactId=other)
            db.execute('UPDATE contacts SET id=?,payload=?',(other,h._dump(row)))
        a=self.open()
        with self.assertRaises(h.ContactHistoryError):self.accept(a)
        self.assertEqual(a.lookup(self.ident)['reason'],'unobserved')

    def test_root_clock_regression_and_corrupt_signatures_never_positive(self):
        a=self.create();self.accept(a)
        with closing(sqlite3.connect(self.root)) as db,db:db.execute('UPDATE manifests SET comparison=9999')
        self.assertEqual(a.lookup(self.ident)['reason'],'history_missing')
        with closing(sqlite3.connect(self.root)) as db,db:
            raw=bytearray(decode(self.f['manifest']));raw[-1]^=1
            db.execute('UPDATE manifests SET comparison=10000,signed=?',(raw,))
        self.assertEqual(a.lookup(self.ident)['reason'],'history_missing')

    def test_process_loss_before_and_after_commit_reconciles_actual_database(self):
        a=self.create();a.close()
        program='''
import json,os,sys
from contextlib import contextmanager
from test_contact_integrity import material,decode
from zrotext_native_candidate import contact_integrity as c, contact_history as h
f=json.load(sys.stdin);_,_,old,_=material(f)
scope=dict(contact=decode(f['contact']),routing_digest=decode(f['routing']))
fields=[c.verify_contact_field01(decode(f[k]),old,**scope) for k in ('name','notes')]
mutation=c.verify_contact_mutation01(decode(f['create']),old,**scope)
transition=c.verify_contact_transition01(None,mutation,fields)
a=h.ContactHistory(sys.argv[1],decode(f['rootPin']),decode(f['fingerprint']),origin=f['origin'],maximum_records=1,root_history_path=sys.argv[2])
original=a._connection
class Proxy:
 def __init__(self,db):self.db=db
 def __getattr__(self,k):return getattr(self.db,k)
 def commit(self):
  if sys.argv[3]=='before':os._exit(53)
  self.db.commit();os._exit(54)
@contextmanager
def connection(*args,**kw):
 with original(*args,**kw) as db:yield Proxy(db)
a._connection=connection
a.accept(expected=None,transition=transition,statement=old)
'''
        for stage,code,kind in [('before',53,'unavailable'),('after',54,'accepted_local_history')]:
            result=subprocess.run([sys.executable,'-c',program,str(self.path),str(self.root),stage],input=json.dumps(self.f),text=True,capture_output=True,cwd=Path(__file__).resolve().parent)
            self.assertEqual(result.returncode,code,result.stderr)
            a=self.open();self.assertEqual(a.lookup(self.ident)['kind'],kind);a.close()


if __name__=='__main__':unittest.main()
