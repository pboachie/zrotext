"""Native fresh composition independently consumed by maintained TS/HPKE."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import sqlite3
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from zrotext_native_candidate import compose03 as c
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate.cng_custody import CngUnavailable, probe_platform
from zrotext_native_candidate.cng_signing import HardwareSigner
from zrotext_native_candidate.outbound_journal import OutboundJournal
from test_election03 import produce, prepare, record, decode


def inputs(fixture, signer):
    manifest, proof, _ = prepare(fixture)
    m = s._bound(s._manifests, manifest)
    return dict(manifest=manifest,proof=proof,current_authority=record(fixture['authority']),now_ms=30000,
        message_id=decode(fixture['message']),observed_ms=30000,expires_ms=40000,peer='+12',content='Native composed 🌱',
        signer=signer,recipients=[(k.role,k.id) for k in m.keys if k.role in (1,2)])


def consume(fixture, result):
    data=json.dumps(dict(fixture=fixture,envelope=base64.b64encode(result.envelope).decode(),expectedText='Native composed 🌱'))
    return json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('consume-native03.mjs'))], input=data,encoding='utf-8'))


class CompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=produce()

    def setUp(self):
        self.args=inputs(self.fixture,c.SoftwareSigner(ec.derive_private_key(5,ec.SECP256R1())))
        self.args['require_hardware']=False

    def test_native_composition_opens_in_independent_ts_for_both_recipients(self):
        result=c.compose_outbound03(**self.args)
        self.assertEqual(consume(self.fixture,result),dict(verified=True,openedRecipients=2))
        self.assertEqual(result.envelope_digest,s.sha(result.envelope))
        self.assertEqual(result.unsigned_digest,s.sha(result.envelope[:-64]))

    def test_fresh_compositions_use_distinct_nonce_wraps_and_ciphertext(self):
        a,b=[s.parse_envelope(c.compose_outbound03(**self.args).envelope) for _ in range(2)]
        self.assertNotEqual(a.nonce,b.nonce)
        self.assertNotEqual(a.body,b.body)
        self.assertNotEqual(a.wraps[0][2],b.wraps[0][2])

    def test_invalid_authority_and_content_refuse_before_randomness_or_signing(self):
        variants=[dict(require_hardware=True),dict(require_hardware='false'),dict(message_id=bytes(16)),
            dict(now_ms=60000),dict(observed_ms=30001),dict(expires_ms=60001),dict(peer='+01'),dict(content=''),
            dict(content='\ufeffbad'),dict(content='bad\0'),dict(content='\ud800'),dict(content='x'*32769),
            dict(recipients=[self.args['recipients'][0]]),dict(recipients=self.args['recipients']*2),
            dict(current_authority=dict(self.args['current_authority'],bindingGeneration=99)),
            dict(signer=c.SoftwareSigner(ec.derive_private_key(8,ec.SECP256R1())))]
        for change in variants:
            with self.subTest(change=list(change)),patch.object(c.os,'urandom') as draw,patch.object(c.SoftwareSigner,'sign') as sign:
                with self.assertRaises(s.SealedError):
                    c.compose_outbound03(**dict(self.args,**change))
                draw.assert_not_called();sign.assert_not_called()

    def test_durable_replay_returns_exact_ciphertext_without_randomness_or_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'outbound.db'
            store=OutboundJournal(path,decode(self.fixture['rootPin']),decode(self.fixture['fingerprint']))
            first=store.compose_or_replay(**self.args)
            restored=OutboundJournal(path,decode(self.fixture['rootPin']),decode(self.fixture['fingerprint']))
            with patch.object(c.os,'urandom') as draw,patch.object(c.SoftwareSigner,'sign') as sign:
                second=restored.compose_or_replay(**dict(self.args,now_ms=30001))
                self.assertEqual(first,second);draw.assert_not_called();sign.assert_not_called()
            with self.assertRaises(s.SealedError):
                restored.compose_or_replay(**dict(self.args,content='changed'))
            with self.assertRaises(s.SealedError):
                restored.compose_or_replay(**dict(self.args,now_ms=60000))

    def test_concurrent_composition_has_one_ciphertext_and_one_sign_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'outbound.db'
            stores=[OutboundJournal(path,decode(self.fixture['rootPin']),decode(self.fixture['fingerprint'])) for _ in range(2)]
            with patch.object(c,'_compose',wraps=c._compose) as compose,ThreadPoolExecutor(max_workers=2) as pool:
                values=list(pool.map(lambda store:store.compose_or_replay(**self.args),stores))
                self.assertEqual(values[0],values[1]);self.assertEqual(compose.call_count,1)

    def test_failed_persistence_exposes_no_result_and_stored_corruption_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'outbound.db'
            store=OutboundJournal(path,decode(self.fixture['rootPin']),decode(self.fixture['fingerprint']))
            with closing(sqlite3.connect(path,isolation_level=None)) as db:
                db.execute("CREATE TRIGGER refuse BEFORE INSERT ON outbound BEGIN SELECT RAISE(ABORT, 'injected'); END")
            with self.assertRaises(sqlite3.DatabaseError):
                store.compose_or_replay(**self.args)
            with closing(sqlite3.connect(path,isolation_level=None)) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM outbound').fetchone()[0],0)
                db.execute('DROP TRIGGER refuse')
            store.compose_or_replay(**self.args)
            with closing(sqlite3.connect(path,isolation_level=None)) as db:
                db.execute('UPDATE outbound SET envelope=?',(bytes(557),))
            with self.assertRaises(s.SealedError),patch.object(c,'_compose') as compose:
                store.compose_or_replay(**self.args)
            compose.assert_not_called()

    def test_unknown_result_after_commit_replays_committed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'outbound.db'
            store=OutboundJournal(path,decode(self.fixture['rootPin']),decode(self.fixture['fingerprint']))
            original=store._connection
            class LostResult:
                def __init__(self,db):self.db=db
                def __getattr__(self,name):return getattr(self.db,name)
                def commit(self):
                    self.db.commit()
                    raise RuntimeError('simulated response loss after durable commit')
            @contextmanager
            def connection():
                with original() as db:yield LostResult(db)
            store._connection=connection
            with self.assertRaises(RuntimeError):
                store.compose_or_replay(**self.args)
            with closing(sqlite3.connect(path)) as db:
                committed=db.execute('SELECT envelope FROM outbound').fetchone()[0]
            restored=OutboundJournal(path,decode(self.fixture['rootPin']),decode(self.fixture['fingerprint']))
            with patch.object(c,'_compose') as compose:
                self.assertEqual(restored.compose_or_replay(**self.args).envelope,committed)
                compose.assert_not_called()

    @unittest.skipUnless(os.name=='nt','Windows Platform Crypto Provider required')
    def test_actual_tpm_signer_reopen_native_composition_and_exact_delete(self):
        try:
            probe_platform()
        except CngUnavailable as error:
            self.skipTest(str(error))
        receipt=Path(tempfile.gettempdir())/('zrotext-signing-pending-'+str(uuid.uuid4())+'.json')
        def pending(name):
            with receipt.open('x',encoding='utf-8') as f:
                json.dump({'alias':name,'state':'pending'},f);f.flush();os.fsync(f.fileno())
        key=HardwareSigner.create(pending)
        try:
            public=key.public_point()
            reopened=HardwareSigner.open(key.name,public)
            try:
                fixture=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('produce-election03.mjs')),
                    '--signer-point',public.hex()],encoding='utf-8'))
                result=c.compose_outbound03(**inputs(fixture,reopened))
                self.assertEqual(consume(fixture,result),dict(verified=True,openedRecipients=2))
            finally:
                reopened.close()
        finally:
            key.delete()
            with receipt.open('w',encoding='utf-8') as f:
                json.dump({'state':'deleted'},f);f.flush();os.fsync(f.fileno())


if __name__=='__main__':
    unittest.main()
