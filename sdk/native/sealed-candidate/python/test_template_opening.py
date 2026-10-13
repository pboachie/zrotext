"""Real owner TLS + protected provider opening through the composed native API."""
import json
from pathlib import Path
import subprocess
import unittest
from installed_template_opening_consumer import TemplateOpeningTlsTests
ROOT=Path(__file__).parent
TemplateOpeningTlsTests.producer=ROOT/'owner-template-interop.mjs'
TemplateOpeningTlsTests.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'owner-template-interop.mjs')],encoding='utf-8'))

class OpeningDifferentialTests(unittest.TestCase):
    def test_actual_maintained_opening_acceptance_and_effects(self):
        import base64
        from unittest.mock import patch
        from cryptography.hazmat.primitives.asymmetric import ec
        from installed_owner_template_consumer import materials
        from zrotext_native_candidate import sealed_candidate as s
        from zrotext_native_candidate.owner_template_save import OwnerTemplateClient
        from zrotext_native_candidate.template_opening import OwnerTemplateOpening,TemplateOpeningError
        f=TemplateOpeningTlsTests.fixture;dec=base64.b64decode;manifest,binding=materials(f)
        cases=[{},dict(ownerLive=False),dict(ownerLostAfterRead=True),dict(csrfLostAfterRead=True),dict(tamper=True),dict(status=302)]
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'template-opening-interop.mjs')],input=json.dumps(dict(fixture=f,cases=cases)),encoding='utf-8'))
        for case,want in zip(cases,expected):
            with self.subTest(case=case):
                calls=[];raw=bytearray(dec(f['envelope']))
                if case.get('tamper'):raw[-1]^=1
                class Response:
                    status=case.get('status',200);length=0
                    def getheader(self,name):return 'application/vnd.zrotext.workflow-template.v1'
                    def read(self,n):return bytes(raw)
                class Connection:
                    sock=None
                    def __init__(self,*args,**kwargs):pass
                    def connect(self):pass
                    def request(self,*args,**kwargs):calls.append(args)
                    def getresponse(self):return Response()
                    def close(self):pass
                current=lambda:dict(binding=binding,manifest=manifest,nowMs=f['now'],ownerSessionLive=case.get('ownerLive',True) and not(case.get('ownerLostAfterRead') and calls),consentLive=True,phase='active',validForMs=10000)
                session=lambda:dict(origin='https://owner.example.invalid',cookie='synthetic=session',csrf='rotated' if case.get('csrfLostAfterRead') and calls else 'synthetic-csrf')
                client=OwnerTemplateClient('https://owner.example.invalid',binding,dec(f['scope']['templateId']),read_current=current,current_session=session,consume_ciphertext_review=lambda _:None,enabled=True)
                opening=OwnerTemplateOpening('https://owner.example.invalid',binding,dec(f['scope']['templateId']),client=client,read_current=current,current_session=session,enabled=True)
                key=s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(dec(f['archiveScalar']),'big'),ec.SECP256R1()))
                with patch('zrotext_native_candidate.owner_template.http.client.HTTPSConnection',Connection):
                    try:
                        value=opening.open_latest(key,require_protected=False);got=dict(accepted=True,calls=len(calls),preview=dict(value['preview']))
                    except TemplateOpeningError:got=dict(accepted=False,calls=len(calls))
                opening.close();self.assertEqual(got,want)
