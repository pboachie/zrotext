"""Independent maintained TS template bytes and native protected recipient use."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate import encrypted_template as t


def decode(value):return base64.b64decode(value,validate=True)


def fixture(public=None):
    args=['node',str(Path(__file__).with_name('template-interop.mjs'))]
    if public is not None:args+=['--recipient-point',public.hex()]
    return json.loads(subprocess.check_output(args,encoding='utf-8'))


def material(f):
    root=s.enroll_root02(decode(f['rootPin']),decode(f['fingerprint']))
    manifest=s.verify_manifest02(decode(f['manifest']),root,f['now'])
    scope={k:v if type(v) is int else decode(v) for k,v in f['scope'].items()}
    custody=s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(f['archiveScalar']),'big'),ec.SECP256R1())) if 'archiveScalar' in f else None
    return manifest,scope,custody


class TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()

    def setUp(self):self.manifest,self.scope,self.custody=material(self.f)

    def test_maintained_ts_envelope_opens_with_exact_aad_content_and_preview(self):
        envelope=decode(self.f['envelope'])
        self.assertEqual(t.encrypted_template_aad(self.scope),decode(self.f['aad']))
        self.assertEqual(t.open_encrypted_template(self.manifest,self.scope,10000,self.custody,envelope,require_protected=False),self.f['content'])
        self.assertEqual(t.open_encrypted_template_bytes(self.manifest,self.scope,10000,self.custody,envelope,require_protected=False),decode(self.f['canonical']))
        self.assertEqual(t.preview_encrypted_template(self.f['content']),self.f['preview'])
        self.assertEqual(t.encrypted_template_digest(envelope),s.sha(envelope))

    def test_native_fresh_envelopes_open_in_independent_maintained_ts(self):
        one=t.seal_encrypted_template(self.manifest,self.scope,10000,self.f['content'])
        two=t.seal_encrypted_template(self.manifest,self.scope,10000,self.f['content'])
        self.assertNotEqual(one[222:287],two[222:287]);self.assertNotEqual(one,two)
        for envelope in (one,two):
            result=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('template-interop.mjs')),'--consume'],
                input=json.dumps(dict(fixture=self.f,envelope=base64.b64encode(envelope).decode(),expectedCanonical=self.f['canonical'])),encoding='utf-8'))
            self.assertTrue(result['verified']);self.assertEqual(result['preview'],self.f['preview'])
            self.assertEqual(decode(result['digest']),t.encrypted_template_digest(envelope))

    def test_canonical_contract_and_sms_estimates_match_ts_vectors(self):
        for v in self.f['vectors']:
            if v.get('refused'):
                with self.assertRaises(t.TemplateError):t.canonical_template_bytes(v['template'],v['values'])
            else:
                self.assertEqual(t.canonical_template_bytes(v['template'],v['values']),decode(v['canonical']))
                self.assertEqual(t.template_digest(v['template'],v['values']),v['digest'])
        for v in self.f['estimates']:
            if v.get('refused'):
                with self.assertRaises(t.TemplateError):t.estimate_segments(v['text'])
            else:self.assertEqual(t.estimate_segments(v['text']),v['estimate'])
        self.assertEqual(t.canonical_template_bytes('\ud83c\udf31',{}),t.canonical_template_bytes('🌱',{}))

    def test_bounds_reserved_identifiers_and_output_are_closed(self):
        for template,values in [('x'*4097,{}),('\ud800',{}),('x',{'name':'\udfff'}),('x',{str(i):'v' for i in range(33)}),
                                ('x',{'prototype':'v'}),('x',{'a':1}),('x',{'a'*33:'v'}),('x',{f'k{i}':'v'*512 for i in range(9)})]:
            with self.assertRaises(t.TemplateError):t.canonical_template_bytes(template,values)
        for content in [dict(template='{{missing}}',values={}),dict(template='{{a}}'*17,values={'a':'x'*512}),dict(template='\t',values={})]:
            with self.assertRaises(t.TemplateError):t.preview_encrypted_template(content)

    def test_scope_current_authority_and_role_refuse_before_randomness(self):
        for field in self.scope:
            scope=dict(self.scope);value=scope[field]
            scope[field]=value+1 if type(value) is int else bytes([value[0]^1])+value[1:]
            with self.assertRaises(t.TemplateError):t.open_encrypted_template(self.manifest,scope,10000,self.custody,decode(self.f['envelope']),require_protected=False)
        for change in ({'accountId':bytes(16)},{'revision':129},{'revision':True},{'expiresMs':10000},{'expiresMs':10000+30*86400000+1},
                       {'readerId':bytes([99])*32},{'deviceId':bytes([99])*16},{'trustGeneration':2}):
            scope=dict(self.scope,**change)
            with patch.object(t,'_wrap',side_effect=AssertionError('randomness before authority')) as wrapped:
                with self.assertRaises(t.TemplateError):t.seal_encrypted_template(self.manifest,scope,10000,self.f['content'])
                wrapped.assert_not_called()

    def test_tamper_truncation_and_authenticated_noncanonical_plaintext_refused(self):
        envelope=decode(self.f['envelope'])
        variants=[envelope[:-1],envelope+b'x',envelope[:287]+bytes(4)+envelope[291:]]
        for at in (0,100,222,250,len(envelope)-1):
            altered=bytearray(envelope);altered[at]^=1;variants.append(altered)
        for altered in variants:
            with self.assertRaises(t.TemplateError):t.open_encrypted_template(self.manifest,self.scope,10000,self.custody,altered,require_protected=False)
        for key in ('malformed','invalidUtf8'):
            raw=decode(self.f[key])
            self.assertTrue(t.open_encrypted_template_bytes(self.manifest,self.scope,10000,self.custody,raw,require_protected=False))
            with self.assertRaises(t.TemplateError):t.open_encrypted_template(self.manifest,self.scope,10000,self.custody,raw,require_protected=False)
        duplicate=b'{"v":1,"v":1,"template":"x","values":{}}'
        raw=t.seal_encrypted_template_bytes(self.manifest,self.scope,10000,duplicate)
        self.assertEqual(t.open_encrypted_template_bytes(self.manifest,self.scope,10000,self.custody,raw,require_protected=False),duplicate)
        with self.assertRaises(t.TemplateError):t.open_encrypted_template(self.manifest,self.scope,10000,self.custody,raw,require_protected=False)

    def test_content_bounds_and_protected_default(self):
        for content in (b'x',bytes([171])*32768):
            envelope=t.seal_encrypted_template_bytes(self.manifest,self.scope,10000,content)
            self.assertEqual(t.open_encrypted_template_bytes(self.manifest,self.scope,10000,self.custody,envelope,require_protected=False),content)
        for content in (b'',bytes(32769),'x'):
            with self.assertRaises(t.TemplateError):t.seal_encrypted_template_bytes(self.manifest,self.scope,10000,content)
        with self.assertRaises(t.TemplateError):t.open_encrypted_template(self.manifest,self.scope,10000,self.custody,decode(self.f['envelope']))
        with self.assertRaises(t.TemplateError):t.open_encrypted_template(self.manifest,self.scope,10000,object(),decode(self.f['envelope']),require_protected=False)

    @unittest.skipUnless(os.name=='nt','Windows TPM only; not protected acceptance')
    def test_actual_tpm_template_opening_uses_exact_qualified_archive_key(self):
        from zrotext_native_candidate.cng_custody import HardwareRecipient,CngUnavailable,probe_platform
        try:probe_platform()
        except CngUnavailable as error:self.skipTest('No hardware provider: '+error.operation)
        fd,path=tempfile.mkstemp(prefix='zrotext-template-cng-',suffix='.json');os.close(fd)
        def receipt(value):
            with open(path,'w',encoding='utf-8') as file:json.dump(value,file);file.flush();os.fsync(file.fileno())
        key=HardwareRecipient.create(lambda name:receipt(dict(pending_alias=name)))
        try:
            f=fixture(key.public_point());manifest,scope,_=material(f);self.assertNotIn('archiveScalar',f)
            with HardwareRecipient.open(key.name,key.public_point()) as reopened:
                self.assertEqual(t.open_encrypted_template(manifest,scope,10000,reopened,decode(f['envelope'])),f['content'])
        finally:key.delete();receipt(dict(owned_test_key_deleted=True))


if __name__=='__main__':unittest.main()
