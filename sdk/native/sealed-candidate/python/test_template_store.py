"""Maintained TS differential plus genuine ciphertext request composition."""
import base64
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import subprocess
import unittest
from zrotext_native_candidate import template_store as p
from zrotext_native_candidate import encrypted_template as t
from test_encrypted_template import fixture,material,decode

REQUEST='00000000-0000-0000-0000-000000000041'
def encode(b):return base64.b64encode(b).decode('ascii')
def as_wire(value):return dict(path=value.path,headers=dict(value.headers),body=encode(value.body),revision=value.revision,encryptedDigest=value.encrypted_digest)


class TemplateStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=fixture()

    def test_real_native_ciphertext_request_is_independently_accepted_and_snapshotted(self):
        manifest,scope,custody=material(self.fixture)
        raw=bytearray(t.seal_encrypted_template(manifest,scope,10000,self.fixture['content']))
        request=p.template_save_request(scope,REQUEST,0,raw);before=request.body;raw[:]=bytes(len(raw));scope['templateId']=bytes(16)
        self.assertEqual(request.body,before);self.assertNotEqual(request.body,bytes(raw))
        with self.assertRaises(FrozenInstanceError):request.revision=2
        with self.assertRaises(TypeError):request.headers['authorization']='not accepted'
        result=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('template-store-interop.mjs'))],input=json.dumps([dict(scope=self.fixture['scope'],requestId=REQUEST,expectedRevision=0,envelope=encode(before))]),encoding='utf-8'))
        self.assertEqual(result,[dict(accepted=True,value=as_wire(request))])
        self.assertEqual(p.template_save_receipt(request,b'{"revision":1}'),dict(revision=1))
        scope=material(self.fixture)[1]
        self.assertEqual(t.open_encrypted_template(manifest,scope,10000,custody,request.body,require_protected=False),self.fixture['content'])

    def test_request_and_raw_receipt_differential(self):
        base=dict(scope=self.fixture['scope'],requestId=REQUEST,expectedRevision=0,envelope=self.fixture['envelope']);cases=[base]
        for revision in (0.0,1,-1,127,128,True,0.5):cases.append(dict(base,expectedRevision=revision))
        for identity in ('00000000-0000-0000-0000-000000000000','A0000000-0000-0000-0000-000000000001','../save',''):
            cases.append(dict(base,requestId=identity))
        raw=decode(base['envelope'])
        for altered in (raw[:-1],raw+b'x',raw[:287]+bytes(4)+raw[291:],bytes([raw[0]^1])+raw[1:]):cases.append(dict(base,envelope=encode(altered)))
        # Framing validation is deliberately not authentication or a curve check.
        cases.append(dict(base,envelope=encode(raw[:222]+bytes(65)+raw[287:])))
        for length in (16,17,32784,32785):
            cases.append(dict(base,envelope=encode(raw[:287]+length.to_bytes(4,'big')+bytes(length))))
        for revision in (1,128):
            scope=dict(base['scope'],revision=revision)
            native={k:v if type(v) is int else decode(v) for k,v in scope.items()}
            envelope=t.encrypted_template_aad(native)+raw[222:]
            cases.append(dict(base,scope=scope,expectedRevision=revision-1,envelope=encode(envelope)))
        receipts=[b'{"revision":1}',b'{"revision":1.0}',b'{"revision":1e0}',b'{"revision":2}',b'{"revision":true}',b'{"revision":"1"}',
            b'{"revision":1,"send":true}',b'null',b'[]',b'{}',b'',b'x'*257,b'\xff',b'\xef\xbb\xbf{"revision":1}',b'\xef\xbb\xbf'*2+b'{"revision":1}',
            b'{"revision":2,"revision":1}',b'{"revision":1,"revision":2}',b'{"revision":NaN}',b' '+b'{"revision":1}'+b' '*241]
        for receipt in receipts:cases.append(dict(base,receipt=encode(receipt)))
        expected=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('template-store-interop.mjs'))],input=json.dumps(cases),encoding='utf-8'))
        actual=[]
        for case in cases:
            scope={k:v if type(v) is int else decode(v) for k,v in case['scope'].items()}
            try:
                request=p.template_save_request(scope,case['requestId'],case['expectedRevision'],decode(case['envelope']))
                value=p.template_save_receipt(request,decode(case['receipt'])) if 'receipt' in case else as_wire(request)
                actual.append(dict(accepted=True,value=value))
            except p.TemplateStoreError:actual.append(dict(accepted=False))
        self.assertEqual(actual,expected);self.assertEqual(len(cases),42)

    def test_public_refusals_are_redacted_and_no_io_or_authority_is_created(self):
        _,scope,_=material(self.fixture)
        for expected in (10**1000,float('nan'),float('inf'),object()):
            with self.assertRaises(p.TemplateStoreError) as caught:p.template_save_request(scope,REQUEST,expected,decode(self.fixture['envelope']))
            self.assertEqual(str(caught.exception),'Invalid template persistence contract')
        request=p.template_save_request(scope,REQUEST,0,decode(self.fixture['envelope']))
        for receipt in ('{"revision":1}',memoryview(b'{"revision":1}'),None):
            with self.assertRaises(p.TemplateStoreError):p.template_save_receipt(request,receipt)
        with self.assertRaises(p.TemplateStoreError):p.template_save_receipt(object(),b'{"revision":1}')


if __name__=='__main__':unittest.main()
