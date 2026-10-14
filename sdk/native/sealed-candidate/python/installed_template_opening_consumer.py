"""Actual TLS and isolated installed current-template opening boundaries."""
import base64
import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate import encrypted_template as t
from zrotext_native_candidate.owner_template_save import OwnerTemplateClient
from zrotext_native_candidate.template_opening import OwnerTemplateOpening,TemplateOpeningError

spec=importlib.util.spec_from_file_location('opening_owner_fixture',Path(__file__).with_name('installed_owner_template_consumer.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
dec=helper.dec

class TemplateOpeningTlsTests(unittest.TestCase):
    fixture=None
    current=helper.OwnerTemplateTests.current
    session=helper.OwnerTemplateTests.session
    respond=helper.OwnerTemplateTests.respond
    def setUp(self):
        helper.OwnerTemplateTests.setUp(self)
        self.key=s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(dec(self.fixture['archiveScalar']),'big'),ec.SECP256R1()))
    def make(self,**changes):
        base=dict(read_current=self.current,current_session=self.session,enabled=True)
        self.persistence=OwnerTemplateClient(self.origin,self.binding,dec(self.fixture['scope']['templateId']),consume_ciphertext_review=lambda _:None,**base)
        base.update(changes)
        return OwnerTemplateOpening(self.origin,self.binding,dec(self.fixture['scope']['templateId']),client=self.persistence,**base)
    def open(self):return self.client.open_latest(self.key,require_protected=False)
    def test_actual_tls_fresh_current_preview_repeated_and_immutable(self):
        self.respond();result=self.open();self.assertEqual(dict(result['preview']),self.fixture['preview']);self.assertFalse(result['requestAcknowledged']);self.assertFalse(result['matchesPending'])
        self.assertEqual(result['encryptedDigest'],s.sha(dec(self.fixture['envelope'])).hex())
        with self.assertRaises(TypeError):result['preview']['estimate']['segments']=99
        self.respond();self.assertEqual(self.open(),result);self.assertEqual(len(self.calls),2)
        for method,path,headers,body in self.calls:
            self.assertEqual(method,'GET');self.assertEqual(headers['Cookie'],self.cookie);self.assertEqual(headers['x-zrotext-csrf'],self.csrf);self.assertEqual(body,b'')
    def test_protected_default_and_unqualified_provider_fail_before_dispatch(self):
        with self.assertRaises(TemplateOpeningError):self.client.open_latest(self.key)
        self.assertEqual(self.calls,[]);self.client=self.make()
        with self.assertRaises(TemplateOpeningError):self.client.open_latest(object(),require_protected=False)
        self.assertEqual(self.calls,[])
    def test_post_decrypt_authority_loss_never_returns_plaintext(self):
        original=t.open_encrypted_template
        def changed(*args,**kwargs):
            content=original(*args,**kwargs);self.live=False;return content
        self.respond()
        with patch('zrotext_native_candidate.template_opening.t.open_encrypted_template',side_effect=changed):
            with self.assertRaises(TemplateOpeningError):self.open()
        self.assertEqual(len(self.calls),1)
    def test_shadowed_child_methods_cannot_substitute_snapshot_or_close(self):
        self.persistence.read_latest=lambda:dict(preview='forged');self.persistence.close=lambda:None
        self.respond();self.assertEqual(dict(self.open()['preview']),self.fixture['preview']);self.client.close()
        with self.assertRaises(Exception):OwnerTemplateClient.read_latest(self.persistence)
        self.assertEqual(len(self.calls),1)
    def test_cancel_during_custody_retains_admission_and_suppresses_plaintext(self):
        entered=threading.Event();release=threading.Event();errors=[];original=s.SoftwareRecipient.exchange
        def held(key,ephemeral):entered.set();release.wait(2);return original(key,ephemeral)
        def run():
            try:self.open()
            except TemplateOpeningError as error:errors.append(error.code)
        self.respond()
        with patch.object(s.SoftwareRecipient,'exchange',held):
            thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(1));self.client.invalidate();thread.join(1)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,['closed'])
            with self.assertRaises(TemplateOpeningError) as caught:self.open()
            self.assertEqual(caught.exception.code,'busy');release.set()
        self.assertEqual(len(self.calls),1)
    def test_redirect_and_bad_authentication_do_not_retry_or_publish(self):
        altered=bytearray(dec(self.fixture['envelope']));altered[-1]^=1
        for body,status in ((b'',302),(bytes(altered),200)):
            self.client=self.make();before=len(self.calls);self.respond(body,status,{'Location':'/different'})
            with self.assertRaises(TemplateOpeningError):self.open()
            self.assertEqual(len(self.calls),before+1)

    @unittest.skipUnless(os.name=='nt','Windows PCP unavailable on this platform')
    def test_actual_protected_provider_and_closed_lease_before_publication(self):
        from zrotext_native_candidate.cng_custody import HardwareRecipient,CngUnavailable,probe_platform
        try:probe_platform()
        except CngUnavailable as error:self.skipTest('No hardware provider: '+error.operation)
        fd,path=tempfile.mkstemp(prefix='zrotext-opening-cng-',suffix='.json');os.close(fd)
        def receipt(value):
            with open(path,'w',encoding='utf-8') as file:json.dump(value,file);file.flush();os.fsync(file.fileno())
        key=HardwareRecipient.create(lambda name:receipt(dict(pending_alias=name)))
        try:
            self.fixture=json.loads(subprocess.check_output(['node',str(self.producer),'--recipient-point',key.public_point().hex()],encoding='utf-8'))
            self.assertNotIn('archiveScalar',self.fixture);self.manifest,self.binding=helper.materials(self.fixture)
            self.client.close();self.client=self.make();self.addCleanup(self.client.close);self.respond()
            self.assertEqual(dict(self.client.open_latest(key)['preview']),self.fixture['preview'])
            self.client.close();self.client=self.make();self.addCleanup(self.client.close)
            with HardwareRecipient.open(key.name,key.public_point()) as reopened:
                original=t.open_encrypted_template
                def revoked(*args,**kwargs):
                    value=original(*args,**kwargs);reopened.close();return value
                self.respond()
                with patch('zrotext_native_candidate.template_opening.t.open_encrypted_template',side_effect=revoked):
                    with self.assertRaises(TemplateOpeningError):self.client.open_latest(reopened)
        finally:key.delete();receipt(dict(owned_test_key_deleted=True))

if __name__=='__main__':
    import zrotext_native_candidate as n
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    TemplateOpeningTlsTests.fixture=json.load(sys.stdin)
    TemplateOpeningTlsTests.producer=Path(sys.argv[1]).resolve()
    result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(TemplateOpeningTlsTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print(json.dumps(dict(installed=True,template_opening_tls=result.testsRun,skipped=len(result.skipped),protected_opening=not result.skipped)))
