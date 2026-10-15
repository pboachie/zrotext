"""Protected contact production and independent maintained TS verification."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import contact_producer as p, contact_integrity as c, sealed_candidate as s
from zrotext_native_candidate import HardwareSigner, CngUnavailable, probe_platform
from installed_contact_producer_consumer import build,decode,encode,material
from test_contact_integrity import fixture


def interop(payload,mode=None):
    args=['node',str(Path(__file__).with_name('contact-producer-interop.mjs'))]
    if mode:args.append(mode)
    return json.loads(subprocess.check_output(args,input=json.dumps(payload),encoding='utf-8'))


class ProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def setUp(self):
        self.signer=p.SoftwareOwnerRootSigner(ec.derive_private_key(7,ec.SECP256R1()))
        self.old,self.new=material(self.f);v=c.parse_contact_field01(decode(self.f['name']))
        expected=dict(accountId=decode(self.f['account']),origin=self.f['origin'],rootFingerprint=decode(self.f['fingerprint']),contactId=decode(self.f['contact']),routingDigest=decode(self.f['routing']))
        self.args=dict(signer=self.signer,statement=self.old,expected=expected,field={k:v[k] for k in ('kind','sealRevision','requestId','encapsulation','ciphertext')},require_hardware=False)
    def test_complete_native_chain_verifies_in_maintained_typescript(self):
        result=interop(build(self.f,self.signer,require_hardware=False))
        self.assertEqual((result['verified'],result['fields'],result['transitions']),(True,3,4))
    def test_policy_scope_frames_and_domain_separation_refuse_before_sign(self):
        cases=[dict(require_hardware=True),dict(statement={}),dict(expected=self.args['expected']|dict(origin='https://other.invalid')),
            dict(field=self.args['field']|dict(encapsulation=b'\4'+bytes(64))),dict(field=self.args['field']|dict(ciphertext=bytes(16))),dict(cancel={})]
        for change in cases:
            with self.subTest(change=tuple(change)),patch.object(self.signer,'sign') as sign:
                with self.assertRaises(p.ContactProducerError):p.produce_contact_field01(**(self.args|change))
                sign.assert_not_called()
        wrong=p.SoftwareOwnerRootSigner(ec.derive_private_key(8,ec.SECP256R1()))
        with patch.object(wrong,'sign') as sign:
            with self.assertRaises(p.ContactProducerError):p.produce_contact_field01(**(self.args|dict(signer=wrong)))
            sign.assert_not_called()
        for domain in ('ZTSE/sign/v2','ZTSE/manifest/v2','ZT/contact-reader/authorization/v1'):
            with self.assertRaises(Exception):self.signer.sign(domain,bytes(304))
        with self.assertRaises(Exception):self.signer.sign(p.MUTATION_DOMAIN,c.encode_contact_field01({k:c.parse_contact_field01(decode(self.f['name']))[k] for k in c._FIELD}))
        with patch.object(self.signer,'sign',return_value=bytes(64)):
            with self.assertRaises(p.ContactProducerError):p.produce_contact_field01(**self.args)
    def test_pre_cancel_and_late_cancel_never_expose_signed_result(self):
        cancel=p.ContactCancellation();cancel.cancel()
        with patch.object(self.signer,'sign') as sign:
            with self.assertRaises(p.ContactProducerError):p.produce_contact_field01(**self.args,cancel=cancel)
            sign.assert_not_called()
        cancel=p.ContactCancellation();entered=threading.Event();release=threading.Event();finished=threading.Event();original=self.signer.sign
        def sign(*args):
            entered.set();release.wait(3)
            try:return original(*args)
            finally:finished.set()
        def abort():entered.wait(2);cancel.cancel()
        threading.Thread(target=abort,daemon=True).start()
        try:
            with patch.object(self.signer,'sign',sign):
                started=time.monotonic()
                with self.assertRaises(p.ContactProducerError):p.produce_contact_field01(**self.args,cancel=cancel)
                self.assertLess(time.monotonic()-started,1);self.assertFalse(finished.is_set())
                release.set();self.assertTrue(finished.wait(2))
        finally:release.set()
    def test_snapshots_and_invalid_transition_never_sign(self):
        first=p.produce_contact_field01(**self.args)
        mutation=c.parse_contact_mutation01(decode(self.f['create']));m={k:mutation[k] for k in c._MUTATION}
        expected=self.args['expected']|dict(legacyGeneration=0)
        with patch.object(self.signer,'sign') as sign:
            with self.assertRaises(p.ContactProducerError):p.produce_contact_transition01(signer=self.signer,statement=self.old,expected=expected,mutation=m,previous=None,
                previous_statement=None,replacement_fields=[first.verified],require_hardware=False)
            sign.assert_not_called()
        captured=bytearray(self.args['field']['ciphertext']);self.args['field']['ciphertext']=captured
        original=self.signer.sign
        def sign(domain,unsigned):captured[:]=bytes(len(captured));return original(domain,unsigned)
        with patch.object(self.signer,'sign',sign):result=p.produce_contact_field01(**self.args)
        self.assertNotEqual(c.parse_contact_field01(result.signed_bytes)['ciphertext'],bytes(captured))

    def test_unresolved_cancelled_workers_keep_all_four_admission_slots(self):
        release=threading.Event();entered=threading.Event();finished=threading.Condition();count=0;original=self.signer.sign
        def sign(*args):
            nonlocal count
            entered.set();release.wait(3)
            try:return original(*args)
            finally:
                with finished:count+=1;finished.notify_all()
        try:
            with patch.object(self.signer,'sign',sign):
                for _ in range(4):
                    entered.clear();cancel=p.ContactCancellation()
                    threading.Thread(target=lambda:(entered.wait(2),cancel.cancel()),daemon=True).start()
                    with self.assertRaises(p.ContactProducerError):p.produce_contact_field01(**self.args,cancel=cancel)
                entered.clear()
                with self.assertRaises(p.ContactProducerError):p.produce_contact_field01(**self.args)
                self.assertFalse(entered.is_set());release.set()
                with finished:self.assertTrue(finished.wait_for(lambda:count==4,2))
        finally:release.set()
        deadline=time.monotonic()+2
        while p._admission._value!=4 and time.monotonic()<deadline:time.sleep(0.001)
        self.assertEqual(p.produce_contact_field01(**self.args).kind,'produced_historical_integrity')

    def test_deadline_suppresses_late_output_and_releases_only_settled_work(self):
        release=threading.Event();entered=threading.Event();finished=threading.Event();real=time.monotonic;offset=[0];original=self.signer.sign
        def sign(*args):
            entered.set();release.wait(3)
            try:return original(*args)
            finally:finished.set()
        def expire():entered.wait(2);offset[0]=11
        try:
            with patch.object(self.signer,'sign',sign),patch.object(p.time,'monotonic',lambda:real()+offset[0]):
                threading.Thread(target=expire,daemon=True).start()
                with self.assertRaises(p.ContactProducerError):p.produce_contact_field01(**self.args)
                self.assertFalse(finished.is_set());release.set();self.assertTrue(finished.wait(2))
        finally:release.set()

    @unittest.skipUnless(os.name=='nt','Windows Platform Crypto Provider required')
    def test_actual_tpm_root_signs_contact_chain_with_exact_owned_cleanup(self):
        try:probe_platform()
        except CngUnavailable as error:self.skipTest(str(error))
        receipt=Path(tempfile.gettempdir())/('zrotext-contact-root-pending-'+str(uuid.uuid4())+'.json')
        def pending(alias):
            with receipt.open('x',encoding='utf-8') as output:json.dump(dict(alias=alias,state='pending'),output);output.flush();os.fsync(output.fileno())
        key=p.OwnerRootSigner.create(pending)
        try:
            f=dict(self.f);template=interop(dict(fixture=f,point=encode(key.public_point())),'--root-template')
            f.update(rootPin=template['rootPin'],fingerprint=template['fingerprint'])
            # Fixture-only enrollment signing. The public root capability remains
            # restricted to contact commitments; it cannot sign these domains.
            def fixture_sign(domain,unsigned):return unsigned+key._sign_digest(s.sha(s.label(domain)+len(unsigned).to_bytes(4,'big')+unsigned))
            unsigned=decode(template['manifestUnsigned']);f['manifest']=encode(fixture_sign('ZTSE/manifest/v2',unsigned))
            successor=bytearray(unsigned);successor[29:37]=(2).to_bytes(8,'big');successor[53:85]=s.sha(unsigned)
            f['nextManifest']=encode(fixture_sign('ZTSE/manifest/v2',bytes(successor)))
            statements=interop(dict(fixture=f),'--statement-template')
            f['statement']=encode(fixture_sign('ZT/contact-reader/authorization/v1',decode(statements['statementUnsigned'])))
            f['nextStatement']=encode(fixture_sign('ZT/contact-reader/authorization/v1',decode(statements['nextStatementUnsigned'])))
            result=interop(build(f,key,require_hardware=True));self.assertEqual((result['fields'],result['transitions']),(3,4))
            with self.assertRaises(s.SealedError):HardwareSigner.sign(key,'ZTSE/sign/v2',bytes(493))
            with self.assertRaises(Exception):key.sign('ZTSE/manifest/v2',unsigned)
        finally:
            key.delete()
            with receipt.open('w',encoding='utf-8') as output:json.dump(dict(state='deleted'),output);output.flush();os.fsync(output.fileno())


if __name__=='__main__':unittest.main()
