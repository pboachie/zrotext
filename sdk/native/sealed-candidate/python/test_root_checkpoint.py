"""Signed rotation corpus, atomic local durability and independent approvals."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing,contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from zrotext_native_candidate import RootCheckpointStore,SealedError,CheckpointStore
from zrotext_native_candidate import sealed_candidate as s

ROOT=Path(__file__).resolve().parents[4]
decode=lambda value:base64.b64decode(value,validate=True)


class RootCheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=json.loads((ROOT/'sdk/typescript/test/vectors/draft02-rotation.json').read_text())

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'roots.db';f=self.fixture
        self.pin=decode(f['old_root_pin_b64']);self.fingerprint=decode(f['old_root_fingerprint_b64'])
        self.approvals={2:decode(f['new_root_point_b64'])};self.now=f['now_ms']
        self.old=decode(f['old_manifest_b64']);self.new=decode(f['new_manifest_b64']);self.transition=decode(f['transition_b64'])
        self.store=self.open();self.store.accept_manifest(self.old,0,self.now)

    def open(self,approvals=None):
        return RootCheckpointStore(self.path,self.pin,self.fingerprint,approved_roots=self.approvals if approvals is None else approvals)

    def rotate(self,store=None):return (store or self.store).accept_transition(self.transition,self.new,1,self.now)

    def test_original_signed_chain_matches_ts_and_restores_generation_two(self):
        self.rotate()
        revision,token=self.open().snapshot(self.now)
        identity=s.manifest_identity(token)
        reference=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('verify-root-transition.mjs'))],
            input=json.dumps(self.fixture),encoding='utf-8'))
        self.assertEqual((revision,identity['generation'],identity['version']),(2,reference['generation'],reference['version']))
        self.assertEqual(identity['digest'],decode(reference['digest']))

    def test_restore_requires_independent_successor_root_approval_again(self):
        self.rotate()
        with self.assertRaises(SealedError):self.open({})
        with self.assertRaises(SealedError):self.open({2:self.pin[-65:]})
        with self.assertRaises(SealedError):
            RootCheckpointStore(self.path,decode(self.fixture['new_root_pin_b64']),decode(self.fixture['new_root_fingerprint_b64']),approved_roots={})

    def test_approval_buffers_are_captured_and_new_root_is_not_learned_from_transition(self):
        raw=bytearray(self.approvals[2]);approved=self.open({2:raw});raw[:]=bytes(65)
        self.rotate(approved)
        self.assertEqual(s.manifest_identity(approved.snapshot(self.now)[1])['generation'],2)

    def test_incomplete_pair_bad_signature_and_wrong_anchor_do_not_advance(self):
        for transition,genesis in ((self.transition[:-1]+bytes([self.transition[-1]^1]),self.new),
                                   (self.transition,self.old),(self.transition,self.new[:-1]+bytes([self.new[-1]^1]))):
            with self.assertRaises(SealedError):self.store.accept_transition(transition,genesis,1,self.now)
            self.assertEqual(self.store.snapshot(self.now)[0],1)
        with self.assertRaises(SealedError):self.store.accept_manifest(self.new,1,self.now)

    def test_competing_connections_only_one_rotation_wins(self):
        other=self.open()
        def attempt(store):
            try:self.rotate(store);return True
            except SealedError:return False
        with ThreadPoolExecutor(max_workers=2) as pool:self.assertEqual(sorted(pool.map(attempt,(self.store,other))),[False,True])
        self.assertEqual(self.open().snapshot(self.now)[0],2)

    def test_corrupt_or_missing_transition_cannot_become_genesis_reset(self):
        self.rotate()
        with closing(sqlite3.connect(self.path,isolation_level=None)) as db:db.execute('UPDATE checkpoints SET transition=NULL WHERE revision=2')
        with self.assertRaises(SealedError):self.open()

    def test_database_failure_and_clock_regression_leave_old_checkpoint(self):
        with self.assertRaises(SealedError):self.store.accept_transition(self.transition,self.new,1,self.now-1)
        with closing(sqlite3.connect(self.path,isolation_level=None)) as db:
            db.execute("CREATE TRIGGER refuse BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected'); END")
        with self.assertRaises(sqlite3.DatabaseError):self.rotate()
        self.assertEqual(self.store.snapshot(self.now)[0],1)

    def test_process_exit_before_commit_leaves_no_transition_half(self):
        script='''
from contextlib import contextmanager
import json,base64,os,sys
from zrotext_native_candidate import RootCheckpointStore
f=json.load(sys.stdin);b=base64.b64decode
store=RootCheckpointStore(sys.argv[1],b(f['old_root_pin_b64']),b(f['old_root_fingerprint_b64']),approved_roots={2:b(f['new_root_point_b64'])})
original=store._connection
class Crash:
    def __init__(self,db):self.db=db
    def __getattr__(self,name):return getattr(self.db,name)
    def commit(self):os._exit(74)
@contextmanager
def connection():
    with original() as db:yield Crash(db)
store._connection=connection
store.accept_transition(b(f['transition_b64']),b(f['new_manifest_b64']),1,f['now_ms'])
'''
        env=dict(os.environ,PYTHONPATH=str(Path(__file__).parent))
        child=subprocess.run([sys.executable,'-c',script,str(self.path)],input=json.dumps(self.fixture),encoding='utf-8',env=env,capture_output=True)
        self.assertEqual(child.returncode,74,child.stderr)
        self.assertEqual(self.open().snapshot(self.now)[0],1)

    def test_profile03_and_plain_checkpoint_formats_are_not_implicitly_migrated(self):
        fixture=json.loads((ROOT/'protocol/v1/vectors/sealed-profile03-sdk-outbound-01.json').read_text())
        with self.assertRaisesRegex(SealedError,'profile02 checkpoint required'):
            self.store.accept_manifest(decode(fixture['manifest03_b64']),1,self.now)
        plain=Path(self.temp.name)/'plain.db';CheckpointStore(plain,self.pin,self.fingerprint)
        with self.assertRaisesRegex(SealedError,'foreign root checkpoint'):
            RootCheckpointStore(plain,self.pin,self.fingerprint,approved_roots=self.approvals)


if __name__=='__main__':unittest.main()
