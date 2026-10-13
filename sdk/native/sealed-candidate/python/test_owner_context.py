"""Actual maintained state-machine comparison; trusted transport seam only."""
import base64
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from installed_owner_template_consumer import materials
from zrotext_native_candidate.owner_context import OwnerWorkflowContextClient
from zrotext_native_candidate.owner_context import OwnerContextError

ROOT=Path(__file__).parent
REQUEST='00000000-0000-0000-0000-000000000041'
def dec(value):return base64.b64decode(value)
def cases():
    rows=[dict(ops=['prepare','commit','pending']),dict(ops=['prepare','wrong','commit']),dict(ops=['prepare','prepare','commit']),
          dict(ops=['prepare','retry','verify','commit']),
          dict(ops=['prepare','commit','pending'],reviewReject=True),dict(ops=['prepare','close','commit','pending'])]
    for response in (dict(network=True),*(dict(status=status) for status in (400,401,403,404,409,413,429,503)),
                     dict(body='{"revision":1.0}'),dict(body=' {"revision":1}'),dict(body='{"revision":2}'),
                     dict(body='\ufeff{"revision":1}'),dict(body='\ufeff\ufeff{"revision":1}'),dict(body='{"revision":1,"revision":1}'),
                     dict(contentType='text/plain'),dict(ownerLost=True)):
        rows.append(dict(ops=['prepare','commit','pending','verify','pending','retry','pending'],responses=[response,{},{}]))
    rows.append(dict(ops=['prepare','commit','retry','retry','retry','pending'],responses=[dict(network=True)]*3))
    rows.append(dict(ops=['prepare','commit','verify','verify','verify','verify','pending'],responses=[dict(network=True),{},{},{}]))
    rows.append(dict(ops=['prepare','commit','pending'],responses=[{},dict(newer=True)]))
    return rows

class OwnerContextDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'owner-context-interop.mjs')],encoding='utf-8'))
    def test_maintained_exact_save_retry_and_snapshot_semantics(self):
        f=self.fixture;scenarios=cases()
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'owner-context-state-interop.mjs')],input=json.dumps(dict(fixture=f,cases=scenarios)),encoding='utf-8'))
        for index,(case,want) in enumerate(zip(scenarios,expected)):
            with self.subTest(case=index):
                manifest,binding=materials(f);scope={k:v if type(v) is int else dec(v) for k,v in f['scope'].items()}
                responses=list(case.get('responses',[]));trace=[];results=[];review=[];live=True
                class Response:
                    length=0
                    def close(self):pass
                    def __init__(self,r,method):self.r,self.method,self.status=r,method,r.get('status',200)
                    def getheader(self,key):return self.r.get('contentType','application/json' if self.method=='POST' else 'application/vnd.zrotext.workflow-context.v1')
                    def read(self,limit):return dec(f['newer'] if self.r.get('newer') else self.r.get('envelope',f['envelope'])) if self.method=='GET' else self.r.get('body','{"revision":1}').encode()
                class Connection:
                    sock=None
                    def __init__(self,*args,**kwargs):pass
                    def connect(self):pass
                    def request(self,method,path,body=None,headers=None):
                        self.method=method;trace.append(dict(method=method,path=path,body=base64.b64encode(body).decode() if body else None,requestId=headers.get('idempotency-key'),revision=headers.get('x-zrotext-context-revision')))
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
                client=OwnerWorkflowContextClient('https://owner.example.invalid',binding,scope['contextId'],scope['kind'],enabled=True,read_current=current,current_session=lambda:dict(origin='https://owner.example.invalid',cookie='synthetic=session',csrf='synthetic-csrf'),consume_write_review=reviewed)
                ticket=None
                with patch('zrotext_native_candidate.owner_context.http.client.HTTPSConnection',Connection):
                    for op in case['ops']:
                        try:
                            if op=='prepare':ticket=client.prepare(REQUEST,0,scope,dec(f['envelope']));value=dict(ticket=True)
                            elif op=='close':client.close();value=None
                            elif op=='pending':value=client.pending()
                            elif op=='commit':value=client.commit(ticket)
                            elif op=='retry':value=client.retry_unknown(ticket)
                            elif op=='verify':value=client.verify_unknown(ticket)
                            else:value=client.commit(object())
                            results.append(dict(ok=True,value=value))
                        except OwnerContextError as error:results.append(dict(ok=False,code=error.code,state=error.state))
                client.close();self.assertEqual(dict(results=results,trace=trace,review=len(review)),want)

from installed_owner_context_consumer import OwnerContextTests
OwnerContextTests.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'owner-context-interop.mjs')],encoding='utf-8'))
