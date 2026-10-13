"""Profile02 native/public TS compatibility and protected signing."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import compose02 as c, sealed_candidate as s
from zrotext_native_candidate import SoftwareSigner, HardwareSigner, CngUnavailable, probe_platform


def produce(public=None):
    args=['node',str(Path(__file__).with_name('produce-fixture.mjs'))]
    if public is not None: args+=['--signer-point',public.hex()]
    return json.loads(subprocess.check_output(args,encoding='utf-8'))


def decode(value):return base64.b64decode(value,validate=True)


def inputs(f,signer):
    pin=s.enroll_root02(decode(f['rootPin']),decode(f['fingerprint']))
    manifest=s.verify_manifest02(decode(f['manifest']),pin,10000)
    return dict(manifest=manifest,now_ms=10000,message_id=bytes([49])*16,device_id=decode(f['device']),line_id=decode(f['line']),
        peer='+12',observed_ms=10000,expires_ms=20000,content='Native composed02 🌱',signer=signer,
        recipients=[(k.role,k.id,k.point) for k in s._bound(s._manifests,manifest).keys if k.role in (1,2)])


def consume(f,result):
    payload=dict(fixture=f,envelope=base64.b64encode(result.envelope).decode(),expectedText='Native composed02 🌱')
    return json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('consume-native02.mjs'))],input=json.dumps(payload),encoding='utf-8'))


class Compose02Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=produce()

    def setUp(self):
        self.args=inputs(self.fixture,SoftwareSigner(ec.derive_private_key(5,ec.SECP256R1())))
        self.args['require_hardware']=False

    def test_native_profile02_opens_both_recipients_in_independent_ts(self):
        result=c.compose_outbound02(**self.args)
        self.assertEqual(consume(self.fixture,result),dict(verified=True,openedRecipients=2))
        self.assertEqual(result.unsigned_digest,s.sha(result.envelope[:-64]))
        self.assertNotEqual(c.compose_outbound02(**self.args).envelope,result.envelope)

    def test_ten_negative_categories_match_maintained_ts_public_wrapper(self):
        r=self.args['recipients']
        cases=dict(identity=dict(message_id=bytes(15)),peer=dict(peer='+01'),time_range=dict(observed_ms=-1),
            intent_expiry=dict(expires_ms=10000),content=dict(content='\ufeffbad'),wrap_count=dict(recipients=r[:1]),
            recipient=dict(recipients=[r[0],r[0]]),recipient_key_id=dict(recipients=[(r[0][0],bytes(32),r[0][2]),r[1]]),
            authorization=dict(line_id=bytes(16)),key_material=dict(deterministicKeyMaterial={}))
        expected=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('consume-native02.mjs'))],
            input=json.dumps(dict(fixture=self.fixture,negativeCases=True)),encoding='utf-8'))
        self.assertEqual(expected['zero_candidate'],'accepted')
        for name,change in cases.items():
            with self.subTest(name=name),patch.object(c.os,'urandom') as draw:
                with self.assertRaises(c.SealedEnvelopeError) as caught:c.compose_outbound02(**dict(self.args,**change))
                self.assertEqual(caught.exception.code,expected[name]);self.assertEqual(expected[name],name);draw.assert_not_called()

    def test_profile02_zero_message_and_candidate_time_grammar_preserved(self):
        result=c.compose_outbound02(**dict(self.args,message_id=bytes(16),observed_ms=0,expires_ms=1))
        parsed=s.parse_envelope(result.envelope)
        self.assertEqual((parsed.message,parsed.observed,parsed.expires),(bytes(16),0,1))
        # This is candidate grammar parity, never a live authorization result.
        self.assertEqual(consume(self.fixture,result)['openedRecipients'],2)

    def test_protected_policy_and_rng_failure_refuse_without_partial_output(self):
        with self.assertRaises(c.SealedEnvelopeError) as error:c.compose_outbound02(**dict(self.args,require_hardware=True))
        self.assertEqual(error.exception.code,'signer')
        with patch.object(c.os,'urandom',side_effect=OSError('unavailable')):
            with self.assertRaises(c.SealedEnvelopeError) as error:c.compose_outbound02(**self.args)
        self.assertEqual(error.exception.code,'key_material')

    @unittest.skipUnless(os.name=='nt','Windows Platform Crypto Provider required')
    def test_actual_tpm_profile02_signing_and_independent_open(self):
        try:probe_platform()
        except CngUnavailable as error:self.skipTest(str(error))
        receipt=Path(tempfile.gettempdir())/('zrotext-signing02-pending-'+str(uuid.uuid4())+'.json')
        def pending(name):
            with receipt.open('x',encoding='utf-8') as f:json.dump({'alias':name,'state':'pending'},f);f.flush();os.fsync(f.fileno())
        key=HardwareSigner.create(pending)
        try:
            fixture=produce(key.public_point())
            self.assertEqual(consume(fixture,c.compose_outbound02(**inputs(fixture,key))),dict(verified=True,openedRecipients=2))
        finally:
            key.delete()
            with receipt.open('w',encoding='utf-8') as f:json.dump({'state':'deleted'},f);f.flush();os.fsync(f.fileno())


if __name__=='__main__':unittest.main()
