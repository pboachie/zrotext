"""Atomic journal acceptance, independent restore, races and crash rollback."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

import election03 as election
import sealed_candidate as s
from election_journal import ElectionJournal
from checkpoint_store import CheckpointStore
from test_election03 import produce, decode, record
from test_sealed_candidate import signed


class JournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = produce()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'journal.db'
        self.pin = decode(self.fixture['rootPin'])
        self.fingerprint = decode(self.fixture['fingerprint'])
        self.store = ElectionJournal(self.path, self.pin, self.fingerprint)
        self.store.accept_manifest(decode(self.fixture['signed02']), 0, 10000)
        self.expectations = dict(expected_core=decode(self.fixture['core']), accepted_record=record(self.fixture['accepted']),
            device_signing_point=decode(self.fixture['deviceSigningPoint']), owner_approval_point=decode(self.fixture['ownerApprovalPoint']))
        self.commit = dict(expected_revision=1, signed03=decode(self.fixture['signed03']), bundle=decode(self.fixture['bundle']), **self.expectations)

    def counts(self):
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            return tuple(db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] for table in ('manifests', 'election'))

    def test_restart_reverifies_original_evidence_and_opens_real_ts_candidate(self):
        self.store.accept_election(**self.commit)
        restored = ElectionJournal(self.path, self.pin, self.fingerprint)
        revision, manifest, proof = restored.snapshot_election(30000, **self.expectations)
        self.assertEqual(revision, 2)
        custody = s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(self.fixture['readerScalar']), 'big'), ec.SECP256R1()))
        opened = election.open_elected_outbound03(raw=decode(self.fixture['envelope']), manifest=manifest, proof=proof,
            current_authority=record(self.fixture['authority']), custody=custody, expected_message_id=decode(self.fixture['message']),
            expected_peer='+12', now_ms=30000, require_hardware=False)
        self.assertEqual(opened.text, self.fixture['bodyText'])
        with self.assertRaises(s.SealedError):
            restored.snapshot(30000)

    def test_two_connections_have_exactly_one_cas_winner(self):
        other = ElectionJournal(self.path, self.pin, self.fingerprint)
        def attempt(store):
            try:
                store.accept_election(**self.commit)
                return True
            except s.SealedError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(attempt, (self.store, other))), [False, True])
        self.assertEqual(self.counts(), (2, 1))

    def test_invalid_evidence_and_direct_profile03_leave_no_partial_election(self):
        changed = dict(self.commit, bundle=self.commit['bundle'][:-1] + bytes([self.commit['bundle'][-1] ^ 1]))
        with self.assertRaises(s.SealedError):
            self.store.accept_election(**changed)
        with self.assertRaises(s.SealedError):
            self.store.accept_manifest(self.commit['signed03'], 1, 10000)
        self.assertEqual(self.counts(), (1, 0))
        with self.assertRaises(s.SealedError):
            self.store.snapshot_election(30000, **self.expectations)

    def test_failure_after_manifest_insert_rolls_back_both_records(self):
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute("CREATE TRIGGER refuse_election BEFORE INSERT ON election BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END")
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.accept_election(**self.commit)
        self.assertEqual(self.counts(), (1, 0))

    def test_process_exit_before_commit_preserves_previous_checkpoint(self):
        # Intercept commit only after both production inserts; no test hook in source.
        script = '''
import os, sqlite3, sys
from contextlib import contextmanager
from election_journal import ElectionJournal
from test_election03 import produce, decode, record
f = produce()
store = ElectionJournal(sys.argv[1], decode(f['rootPin']), decode(f['fingerprint']))
original = store._connection
class CrashAtCommit:
    def __init__(self, db): self.db = db
    def __getattr__(self, name): return getattr(self.db, name)
    def commit(self): os._exit(73)
@contextmanager
def connection():
    with original() as db: yield CrashAtCommit(db)
store._connection = connection
store.accept_election(expected_revision=1, signed03=decode(f['signed03']), bundle=decode(f['bundle']), expected_core=decode(f['core']), accepted_record=record(f['accepted']), device_signing_point=decode(f['deviceSigningPoint']), owner_approval_point=decode(f['ownerApprovalPoint']))
'''
        # Producer signatures are randomized: the child's new original02 must
        # be its own journal predecessor, rather than substituted into ours.
        script = script.replace("original = store._connection", "store.accept_manifest(decode(f['signed02']), 0, 10000)\noriginal = store._connection")
        child_path = Path(self.temp.name) / 'crash.db'
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).parent))
        child = subprocess.run([sys.executable, '-c', script, str(child_path)], env=env, capture_output=True)
        self.assertEqual(child.returncode, 73, child.stderr.decode())
        with closing(sqlite3.connect(child_path)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM manifests').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM election').fetchone()[0], 0)

    def test_independent_expectation_substitution_and_corruption_refuse(self):
        self.store.accept_election(**self.commit)
        for key in self.expectations:
            changed = dict(self.expectations)
            if key == 'accepted_record':
                changed[key] = dict(changed[key], newBindingGeneration=8)
            else:
                changed[key] = bytes([changed[key][0] ^ 1]) + changed[key][1:]
            with self.subTest(key=key), self.assertRaises(s.SealedError):
                self.store.snapshot_election(30000, **changed)
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute('UPDATE election SET bundle=?', (bytes(628),))
        with self.assertRaises(s.SealedError):
            self.store.snapshot_election(30000, **self.expectations)

    def test_missing_election_cannot_reset_trust_and_root_mismatch_refuses(self):
        self.store.accept_election(**self.commit)
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute('DELETE FROM election')
        with self.assertRaises(s.SealedError):
            self.store.snapshot_election(30000, **self.expectations)
        with self.assertRaises(s.SealedError):
            self.store.accept_manifest(decode(self.fixture['signed02']), 2, 30000)
        with self.assertRaises(s.SealedError):
            ElectionJournal(self.path, self.pin, bytes(32))

    def test_storage_does_not_renew_current_permission_or_accept_clock_rollback(self):
        self.store.accept_election(**self.commit)
        with self.assertRaises(s.SealedError):
            self.store.snapshot_election(9999, **self.expectations)
        _, manifest, proof = self.store.snapshot_election(60000, **self.expectations)
        with self.assertRaises(s.SealedError):
            election.require_current_election03(proof, manifest, record(self.fixture['authority']), 60000)

    def test_manifest_successor_requires_same_independent_election_and_restores(self):
        self.store.accept_election(**self.commit)
        raw = bytearray(self.commit['signed03'][:-64])
        raw[6] = 3
        raw[31:39] = (3).to_bytes(8, 'big')
        raw[55:87] = s.sha(self.commit['signed03'][:-64])
        successor = signed(raw, 7, 'ZTSE/manifest/v3')
        with self.assertRaises(s.SealedError):
            self.store.accept_manifest(successor, 2, 30000)
        self.store.accept_manifest(successor, 2, 30000, election_expectations=self.expectations)
        revision, manifest, proof = self.store.snapshot_election(30000, **self.expectations)
        self.assertEqual(revision, 3)
        authority = record(self.fixture['authority'])
        authority.update(manifestVersion=3, manifestDigest=s.sha(successor[:-64]))
        self.assertEqual(election.require_current_election03(proof, manifest, authority, 30000)['manifestVersion'], 3)

    def test_plain_checkpoint_and_deleted_schema_never_migrate_or_reset(self):
        plain = Path(self.temp.name) / 'plain.db'
        CheckpointStore(plain, self.pin, self.fingerprint)
        with self.assertRaises(sqlite3.DatabaseError):
            ElectionJournal(plain, self.pin, self.fingerprint)
        self.store.accept_election(**self.commit)
        with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
            db.execute('DROP TABLE election')
        with self.assertRaises(sqlite3.DatabaseError):
            ElectionJournal(self.path, self.pin, self.fingerprint)


if __name__ == '__main__':
    unittest.main()
