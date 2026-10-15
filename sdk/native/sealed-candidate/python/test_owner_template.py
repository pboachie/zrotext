import base64
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from installed_owner_template_consumer import OwnerTemplateTests,materials
from zrotext_native_candidate.owner_template import OwnerTemplateReader,OwnerTemplateError

ROOT=Path(__file__).parent
OwnerTemplateTests.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'owner-template-interop.mjs')],encoding='utf-8'))

class OwnerTemplateDifferential(unittest.TestCase):
    def test_actual_maintained_cold_reads(self):
        f=OwnerTemplateTests.fixture
        cases=[{},dict(ownerLive=False),dict(status=401),dict(status=503),dict(contentType='application/json')]
        raw=bytearray(base64.b64decode(f['envelope']))
        for offset in (0,70,86,126,222,287):
            changed=bytearray(raw);changed[offset]^=1;cases.append(dict(envelope=base64.b64encode(changed).decode()))
        cases.append(dict(envelope=base64.b64encode(raw[:-1]).decode()))
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'owner-template-interop.mjs'),'--cases'],input=json.dumps(dict(fixture=f,cases=cases)),encoding='utf-8'))
        manifest,binding=materials(f)
        for case,want in zip(cases,expected):
            with self.subTest(case=case):
                calls=[]
                class Response:
                    status=case.get('status',200);length=0
                    def getheader(self,name):return case.get('contentType','application/vnd.zrotext.workflow-template.v1')
                    def read(self,limit):return base64.b64decode(case.get('envelope',f['envelope']))
                class Connection:
                    sock=None
                    def __init__(self,*args,**kwargs):pass
                    def connect(self):pass
                    def request(self,*args,**kwargs):calls.append(args)
                    def getresponse(self):return Response()
                    def close(self):pass
                current=lambda:dict(binding=binding,manifest=manifest,nowMs=f['now'],ownerSessionLive=case.get('ownerLive',True),consentLive=True,phase='active',validForMs=10000)
                client=OwnerTemplateReader('https://owner.example.invalid',binding,base64.b64decode(f['scope']['templateId']),enabled=True,read_current=current,current_session=lambda:dict(origin='https://owner.example.invalid',cookie='synthetic=session',csrf='synthetic-csrf'))
                with patch('zrotext_native_candidate.owner_template.http.client.HTTPSConnection',Connection):
                    try:
                        value=client.read_latest();got=dict(accepted=True,calls=len(calls),digest=value['encryptedDigest'],ack=value['requestAcknowledged'])
                    except OwnerTemplateError as error:got=dict(accepted=False,calls=len(calls),code=error.code,state=error.state)
                client.close();self.assertEqual(got,want)
