"""Durable original ciphertext, independent authority and explicit CAS."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing,contextmanager
from pathlib import Path
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import compose02 as c,sealed_candidate as s,SoftwareSigner
from zrotext_native_candidate.outbound02_journal import OutboundJournal02
from zrotext_native_candidate.outbound_journal import OutboundJournal
from test_compose02 import produce,inputs,decode,consume
from test_sealed_candidate import signed


class Outbound02Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=produce()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'outbound.db'
        self.store=self.restore()
        self.args=inputs(self.f,SoftwareSigner(ec.derive_private_key(5,ec.SECP256R1())))
        self.args.update(require_hardware=False)
        self.intent=bytes([53])*16

    def restore(self):return OutboundJournal02(self.path,decode(self.f['rootPin']),decode(self.f['fingerprint']))

    def call(self,store=None,**changes):
        args=dict(self.args,intent_id=self.intent,expected_revision=0,current_manifest=self.args['manifest'])
        args.update(changes)
        return (store or self.store).compose_or_replay(**args)

    def successor(self,mutate=None):
        raw=bytearray(decode(self.f['manifest'])[:-64]);raw[29:37]=(2).to_bytes(8,'big')
        raw[53:85]=s.manifest_identity(self.args['manifest'])['digest']
        if mutate:mutate(raw)
        pin=s.enroll_root02(decode(self.f['rootPin']),decode(self.f['fingerprint']))
        return s.verify_manifest02(signed(raw,7,'ZTSE/manifest/v2'),s.advance_trust02(pin,self.args['manifest']),10000)

    def test_restart_exact_replay_uses_no_rng_or_sign_and_ts_opens(self):
        revision,first=self.call();self.assertEqual(revision,1)
        self.assertEqual(consume(self.f,first),dict(verified=True,openedRecipients=2))
        restored=self.restore()
        with patch.object(c.os,'urandom') as draw,patch.object(SoftwareSigner,'sign') as sign:
            revision,second=self.call(restored,expected_revision=restored.revision(),now_ms=10001)
            self.assertEqual((revision,second),(2,first));draw.assert_not_called();sign.assert_not_called()

    def test_current_successor_revalidates_without_recomposing_old_prefix(self):
        _,first=self.call()
        with patch.object(c,'_compose') as compose:
            _,second=self.call(expected_revision=1,current_manifest=self.successor(),now_ms=10001)
            self.assertEqual(second,first);compose.assert_not_called()

    def test_conflicts_expiry_clock_and_stale_cas_refuse_before_crypto(self):
        self.call()
        for change in ({'expected_revision':0},{'content':'different'},{'intent_id':bytes([54])*16},
                       {'now_ms':20000},{'now_ms':9999},{'message_id':bytes([55])*16},
                       {'current_manifest':s.Evidence()},{'intent_id':bytes(16)},
                       {'require_hardware':True}):
            with self.subTest(change=change),patch.object(c,'_compose') as compose:
                with self.assertRaises(s.SealedError):self.call(**dict({'expected_revision':1},**change))
                compose.assert_not_called()
        self.assertEqual(self.store.revision(),1)

    def test_current_signer_revoked_and_reader_expired_refuse(self):
        self.call()
        def revoke(raw):raw[151+149*3+148]=2  # role5 signing record
        def expire(raw):raw[151+149+140:151+149+148]=(10001).to_bytes(8,'big')
        for change in (revoke,expire):
            live=self.successor(change)
            with patch.object(c,'_compose') as compose,self.assertRaises(s.SealedError):
                self.call(expected_revision=1,current_manifest=live,now_ms=10002)
            compose.assert_not_called()

    def test_persisted_comparison_and_current_fork_refuse(self):
        self.call(now_ms=11000)
        with self.assertRaisesRegex(s.SealedError,'comparison rollback'):
            self.call(expected_revision=1,now_ms=10001)
        raw=bytearray(decode(self.f['manifest'])[:-64]);raw[37:45]=(9001).to_bytes(8,'big')
        pin=s.enroll_root02(decode(self.f['rootPin']),decode(self.f['fingerprint']))
        fork=s.verify_manifest02(signed(raw,7,'ZTSE/manifest/v2'),pin,11000)
        with patch.object(c,'_compose') as compose,self.assertRaisesRegex(s.SealedError,'current lineage'):
            self.call(expected_revision=1,now_ms=11000,current_manifest=fork)
        compose.assert_not_called();self.assertEqual(self.store.revision(),1)

    def test_racing_cas_has_one_commit_and_sign(self):
        stores=[self.store,self.restore()]
        def attempt(store):
            try:return self.call(store)
            except s.SealedError:return None
        with patch.object(c,'_compose',wraps=c._compose) as compose,ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(attempt,stores))
        self.assertEqual(sum(v is not None for v in results),1);self.assertEqual(compose.call_count,1)
        self.assertEqual(self.store.revision(),1)

    def test_write_failure_rolls_back_both_ciphertext_and_revision(self):
        with closing(sqlite3.connect(self.path,isolation_level=None)) as db:
            db.execute("CREATE TRIGGER refuse BEFORE UPDATE ON state BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.DatabaseError):self.call()
        with closing(sqlite3.connect(self.path)) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM outbound').fetchone()[0],0)
        self.assertEqual(self.store.revision(),0)

    def test_lost_result_after_commit_recovers_original_bytes(self):
        original=self.store._connection
        class LostResult:
            def __init__(self,db):self.db=db
            def __getattr__(self,name):return getattr(self.db,name)
            def commit(self):self.db.commit();raise RuntimeError('lost result')
        @contextmanager
        def connection():
            with original() as db:yield LostResult(db)
        self.store._connection=connection
        with self.assertRaises(RuntimeError):self.call()
        restored=self.restore()
        with closing(sqlite3.connect(self.path)) as db:raw=db.execute('SELECT envelope FROM outbound').fetchone()[0]
        with patch.object(c,'_compose') as compose:
            self.assertEqual(self.call(restored,expected_revision=restored.revision())[1].envelope,raw)
            compose.assert_not_called()

    def test_process_exit_before_commit_exposes_no_record(self):
        script='''
import json,os,sys
from pathlib import Path
from contextlib import contextmanager
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import SoftwareSigner
from zrotext_native_candidate.outbound02_journal import OutboundJournal02
from test_compose02 import decode,inputs
f=json.loads(sys.stdin.read());store=OutboundJournal02(sys.argv[1],decode(f['rootPin']),decode(f['fingerprint']))
original=store._connection
class Crash:
 def __init__(self,db):self.db=db
 def __getattr__(self,name):return getattr(self.db,name)
 def commit(self):os._exit(74)
@contextmanager
def connection():
 with original() as db:yield Crash(db)
store._connection=connection
a=inputs(f,SoftwareSigner(ec.derive_private_key(5,ec.SECP256R1())))
store.compose_or_replay(intent_id=bytes([53])*16,expected_revision=0,current_manifest=a['manifest'],require_hardware=False,**a)
'''
        result=subprocess.run([sys.executable,'-c',script,str(self.path)],input=json.dumps(self.f),text=True,
                              cwd=Path(__file__).parent,capture_output=True)
        self.assertEqual(result.returncode,74,result.stderr)
        self.assertEqual(self.restore().revision(),0)
        with closing(sqlite3.connect(self.path)) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM outbound').fetchone()[0],0)

    def test_corrupt_envelope_and_foreign_format_refuse(self):
        self.call()
        with closing(sqlite3.connect(self.path,isolation_level=None)) as db:db.execute('UPDATE outbound SET envelope=?',(bytes(557),))
        with self.assertRaises(s.SealedError),patch.object(c,'_compose') as compose:self.call(expected_revision=1)
        compose.assert_not_called()
        with self.assertRaises(s.SealedError):OutboundJournal(self.path,decode(self.f['rootPin']),decode(self.f['fingerprint']))


if __name__=='__main__':unittest.main()
