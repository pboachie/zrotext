"""Native platform evidence and crash/concurrency checkpoint tests, no live service."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import base64
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from cng_custody import CngUnavailable, HardwareRecipient, probe_platform
from checkpoint_store import CheckpointStore
import sealed_candidate as sealed

ROOT = Path(__file__).resolve().parents[4]


def b64(s):
    return base64.b64decode(s, validate=True)


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='zrotext-checkpoint-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'checkpoint.sqlite'
        self.vector = json.loads((ROOT / 'protocol/v1/vectors/sealed-profile03-sdk-outbound-01.json').read_text())
        self.store = self.reopen()

    def reopen(self):
        return CheckpointStore(self.path, b64(self.vector['root_pin_b64']), b64(self.vector['root_fingerprint_b64']))

    def test_signed_predecessor_chain_survives_restart_and_exact_cas(self):
        v = self.vector
        self.assertEqual(self.store.snapshot(10000), (0, None))
        self.store.accept_manifest(b64(v['manifest02_b64']), 0, 10000)
        reopened = self.reopen()
        revision, old = reopened.snapshot(30000)
        self.assertEqual(revision, 1)
        self.assertEqual(sealed.manifest_identity(old)['digest'], b64(v['manifest02_digest_b64']))
        reopened.accept_manifest(b64(v['manifest03_b64']), 1, 30000)
        revision, current = self.reopen().snapshot(30000)
        self.assertEqual(revision, 2)
        self.assertEqual(sealed.manifest_identity(current)['digest'], b64(v['manifest03_digest_b64']))
        with self.assertRaisesRegex(sealed.SealedError, 'CAS'):
            reopened.accept_manifest(b64(v['successor03_b64']), 1, 30000)
        with self.assertRaisesRegex(sealed.SealedError, 'clock rollback'):
            reopened.snapshot(29999)

    def test_competing_successors_have_one_atomic_winner(self):
        v = self.vector
        self.store.accept_manifest(b64(v['manifest02_b64']), 0, 10000)
        stores = [self.reopen(), self.reopen()]
        def attempt(store):
            try:
                store.accept_manifest(b64(v['manifest03_b64']), 1, 30000)
                return 'accepted'
            except sealed.SealedError:
                return 'refused'
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, stores))
        self.assertCountEqual(results, ['accepted', 'refused'])
        self.assertEqual(self.reopen().snapshot(30000)[0], 2)

    def test_transaction_crash_rolls_back_and_corrupt_signature_never_restores(self):
        v = self.vector
        self.store.accept_manifest(b64(v['manifest02_b64']), 0, 10000)
        script = "import sqlite3,sys,os; d=sqlite3.connect(sys.argv[1]); d.execute('BEGIN IMMEDIATE'); d.execute('DELETE FROM manifests'); os._exit(0)"
        import sys
        subprocess.run([sys.executable, '-c', script, str(self.path)], check=True)
        self.assertEqual(self.reopen().snapshot(30000)[0], 1)
        with closing(sqlite3.connect(self.path)) as db:
            raw = bytearray(b64(v['manifest02_b64'])); raw[-1] ^= 1
            db.execute('UPDATE manifests SET signed=?', (raw,))
            db.commit()
        with self.assertRaises(sealed.SealedError):
            self.reopen()

    def test_unverified_profile03_genesis_and_foreign_database_refuse(self):
        with self.assertRaisesRegex(sealed.SealedError, 'original02'):
            self.store.accept_manifest(b64(self.vector['manifest03_b64']), 0, 30000)
        self.assertEqual(self.store.snapshot(30000), (0, None))
        foreign = Path(self.tmp.name) / 'foreign.sqlite'
        with closing(sqlite3.connect(foreign)) as db:
            db.execute('CREATE TABLE untouched (value INTEGER)')
            db.commit()
        with self.assertRaisesRegex(sealed.SealedError, 'foreign checkpoint'):
            CheckpointStore(foreign, b64(self.vector['root_pin_b64']), b64(self.vector['root_fingerprint_b64']))

    def test_database_cannot_replace_independently_compared_root(self):
        different = bytearray(b64(self.vector['root_pin_b64']))
        different[5] ^= 1
        compared = sealed.sha(sealed.label('ZTSE/root-pin/v2') + different)
        with self.assertRaisesRegex(sealed.SealedError, 'root binding'):
            CheckpointStore(self.path, different, compared)
        self.assertEqual(self.store.snapshot(10000), (0, None))


class HardwareTests(unittest.TestCase):
    def test_claimed_hardware_flag_is_not_provider_qualification(self):
        class Fake:
            hardware = True
        with self.assertRaises(sealed.SealedError):
            sealed.require_protected_custody(Fake())
        if os.name != 'nt':
            with self.assertRaises(CngUnavailable):
                probe_platform()

    @unittest.skipUnless(os.name == 'nt', 'Windows TPM provider only; not hardware acceptance')
    def test_actual_hardware_key_reopens_decrypts_ts_ciphertext_and_cleans_up(self):
        # Hosted Windows runners may lack a TPM. Only a missing provider/algorithm
        # can skip: once creation is attempted any later failure fails the test.
        try:
            probe_platform()
        except CngUnavailable as error:
            self.skipTest(f'No hardware provider: {error.operation}; no protected acceptance')
        # Keep receipt outside TemporaryDirectory so a failed cleanup preserves it.
        fd, receipt_path = tempfile.mkstemp(prefix='zrotext-cng-pending-', suffix='.json')
        os.close(fd)
        def record(name):
            with open(receipt_path, 'w', encoding='utf-8') as receipt:
                json.dump({'pending_alias': name}, receipt)
                receipt.flush(); os.fsync(receipt.fileno())
        key = HardwareRecipient.create(record)
        deleted = False
        try:
            public = key.public_point()
            self.assertIs(sealed.require_protected_custody(key), key)
            fixture = json.loads(subprocess.check_output(['node', str(Path(__file__).with_name('produce-fixture.mjs')),
                '--recipient-point', public.hex()], cwd=ROOT, encoding='utf-8'))
            self.assertNotIn('archiveScalar', fixture)
            pin = sealed.enroll_root02(b64(fixture['rootPin']), b64(fixture['fingerprint']))
            historical = sealed.verify_manifest02(b64(fixture['manifest']), pin, fixture['now'])
            with tempfile.TemporaryDirectory(prefix='zrotext-cng-checkpoint-') as folder:
                store = CheckpointStore(Path(folder) / 'checkpoint.sqlite', b64(fixture['rootPin']), b64(fixture['fingerprint']))
                store.accept_manifest(b64(fixture['manifest']), 0, fixture['now'])
                _, current = store.snapshot(fixture['now'])
                with HardwareRecipient.open(key.name, public) as reopened:
                    text = sealed.open_archive_protected02(b64(fixture['inbound']), historical, current, reopened,
                        account=b64(fixture['account']), device=b64(fixture['device']), line=b64(fixture['line']),
                        peer='+12', reader_id=b64(fixture['reader']), now_ms=fixture['now'])
                    self.assertEqual(text, fixture['text'])
            with self.assertRaises(sealed.SealedError):
                HardwareRecipient.open(key.name, b'\x04' + bytes(64))
            with self.assertRaisesRegex(sealed.SealedError, 'public binding'):
                HardwareRecipient.open(key.name, b64(fixture['manifest'])[85:150])
        finally:
            key.delete()
            deleted = True
            with open(receipt_path, 'w', encoding='utf-8') as receipt:
                json.dump({'owned_test_key_deleted': deleted}, receipt)
                receipt.flush(); os.fsync(receipt.fileno())
        with self.assertRaises(CngUnavailable):
            HardwareRecipient.open(key.name, public)


if __name__ == '__main__':
    unittest.main()
