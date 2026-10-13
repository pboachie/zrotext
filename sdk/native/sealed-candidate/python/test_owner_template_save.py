"""Actual maintained state-machine comparison; trusted transport seam only."""
import base64
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from installed_owner_template_consumer import materials
from zrotext_native_candidate.owner_template_save import OwnerTemplateClient
from zrotext_native_candidate.owner_template import OwnerTemplateError

ROOT=Path(__file__).parent
REQUEST='00000000-0000-0000-0000-000000000041'
def dec(value):return base64.b64decode(value)
def cases():
    rows=[dict(ops=['prepare','commit','pending']),dict(ops=['prepare','wrong','commit']),dict(ops=['prepare','prepare','commit']),
          dict(ops=['prepare','retry','verify','commit']),dict(ops=['prepare','read','commit']),
          dict(ops=['prepare','commit','pending'],reviewReject=True),dict(ops=['prepare','close','commit','pending'])]
    for response in (dict(network=True),*(dict(status=status) for status in (400,401,403,404,409,413,429,503)),
                     dict(body='{"revision":1.0}'),dict(body=' {"revision":1}'),dict(body='{"revision":2}'),
                     dict(body='\ufeff{"revision":1}'),dict(body='\ufeff\ufeff{"revision":1}'),dict(body='{"revision":1,"revision":1}'),
                     dict(contentType='text/plain'),dict(ownerLost=True)):
        rows.append(dict(ops=['prepare','commit','pending','verify','pending','retry','pending'],responses=[response,{},{}]))
    rows.append(dict(ops=['prepare','commit','retry','retry','retry','pending'],responses=[dict(network=True)]*3))
    rows.append(dict(ops=['prepare','commit','verify','verify','verify','verify','pending'],responses=[dict(network=True),{},{},{}]))
    rows.append(dict(ops=['prepare','commit','read','pending'],responses=[dict(network=True),{}]))
    return rows

class OwnerTemplateSaveDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'owner-template-interop.mjs')],encoding='utf-8'))
    def test_maintained_exact_save_retry_and_snapshot_semantics(self):
        f=self.fixture;scenarios=cases()
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'owner-template-save-interop.mjs')],input=json.dumps(dict(fixture=f,cases=scenarios)),encoding='utf-8'))
        for index,(case,want) in enumerate(zip(scenarios,expected)):
            with self.subTest(case=index):
                manifest,binding=materials(f);scope={k:v if type(v) is int else dec(v) for k,v in f['scope'].items()}
                responses=list(case.get('responses',[]));trace=[];results=[];review=[];live=True
                class Response:
                    length=0
                    def close(self):pass
                    def __init__(self,r,method):self.r,self.method,self.status=r,method,r.get('status',200)
                    def getheader(self,key):return self.r.get('contentType','application/json' if self.method=='POST' else 'application/vnd.zrotext.workflow-template.v1')
                    def read(self,limit):return dec(self.r.get('envelope',f['envelope'])) if self.method=='GET' else self.r.get('body','{"revision":1}').encode()
                class Connection:
                    sock=None
                    def __init__(self,*args,**kwargs):pass
                    def connect(self):pass
                    def request(self,method,path,body=None,headers=None):
                        self.method=method;trace.append(dict(method=method,path=path,body=base64.b64encode(body).decode() if body else None,requestId=headers.get('idempotency-key'),revision=headers.get('x-zrotext-template-revision')))
                    def getresponse(self):
                        nonlocal live
                        r=responses.pop(0) if responses else {}
                        if r.get('network'):raise OSError('synthetic network')
                        if r.get('ownerLost'):live=False
                        return Response(r,self.method)
                    def close(self):pass
                def reviewed(value):
                    review.append(value)
                    if case.get('reviewReject'):raise ValueError('review refused')
                current=lambda:dict(binding=binding,manifest=manifest,nowMs=f['now'],ownerSessionLive=live,consentLive=True,phase='active',validForMs=10000)
                client=OwnerTemplateClient('https://owner.example.invalid',binding,scope['templateId'],enabled=True,read_current=current,current_session=lambda:dict(origin='https://owner.example.invalid',cookie='synthetic=session',csrf='synthetic-csrf'),consume_ciphertext_review=reviewed)
                ticket=None
                with patch('zrotext_native_candidate.owner_template_save.http.client.HTTPSConnection',Connection):
                    for op in case['ops']:
                        try:
                            if op=='prepare':ticket=client.prepare_save(REQUEST,0,scope,dec(f['envelope']));value=dict(ticket=True)
                            elif op=='close':client.close();value=None
                            elif op=='pending':value=client.pending()
                            elif op=='commit':value=client.commit(ticket)
                            elif op=='retry':value=client.retry_unknown(ticket)
                            elif op=='verify':value=client.verify_unknown(ticket)
                            elif op=='read':value=client.read_latest()
                            else:value=client.commit(object())
                            if type(value) is dict and value.get('state')=='verified_current_snapshot':value={k:value[k] for k in ('state','requestAcknowledged','encryptedDigest','matchesPending')}
                            results.append(dict(ok=True,value=value))
                        except OwnerTemplateError as error:results.append(dict(ok=False,code=error.code,state=error.state))
                client.close();self.assertEqual(dict(results=results,trace=trace,review=len(review)),want)

from installed_owner_template_save_consumer import OwnerTemplateSaveTests
OwnerTemplateSaveTests.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'owner-template-interop.mjs')],encoding='utf-8'))
