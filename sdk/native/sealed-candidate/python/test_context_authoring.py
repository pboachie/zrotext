"""Source execution of the actual owner-session TLS authoring acceptance."""
import json
from pathlib import Path
import subprocess
import base64
import unittest
from installed_context_authoring_consumer import ContextAuthoringTests

ROOT=Path(__file__).parent
ContextAuthoringTests.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'context-authoring-interop.mjs')],encoding='utf-8'))


class ContextAuthoringInteropTests(unittest.TestCase):
    def test_actual_maintained_authoring_phases_and_explicit_reconciliation(self):
        cases=[dict(ops=['author','verify','retry','close']),dict(ops=['author'],reviewReject=True),dict(ops=['author'],rotate=True)]
        for status in (400,401,403,404,409,413,429,503,302):
            cases.append(dict(ops=['author','verify','retry'],responses=[dict(status=status),{},{}]))
        cases += [dict(ops=['author','verify','retry'],responses=[dict(network=True),{},{}]),
                  dict(ops=['author','retry','retry','retry'],responses=[dict(status=503)]*3),
                  dict(ops=['author','verify','verify','verify','verify'],responses=[dict(network=True),{},{},{}])]
        cases += [dict(ops=['author'],text=v) for v in ('','x'*32769,'☃'*12000,'\ud800','\ud83c\udf31','\ufefffacts','x\0y')]
        f=ContextAuthoringTests.fixture
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'context-authoring-interop.mjs'),'--cases'],input=json.dumps(dict(fixture=f,cases=cases)),encoding='utf-8'))
        self.assertEqual(len(expected),len(cases))
        for case,want in zip(cases,expected):
            with self.subTest(case=case):
                fixture=ContextAuthoringTests();fixture.setUp()
                try:
                    def review(value):
                        fixture.assertEqual(fixture.calls,[]);fixture.reviews.append(value)
                        if case.get('reviewReject'):raise ValueError('declined')
                        if case.get('rotate'):fixture.csrf='rotated'
                    fixture.client=fixture.make(consume_review=review)
                    for r in case.get('responses',[]):
                        fixture.respond(0 if r.get('network') else r.get('status',200),b'' if r.get('network') or r.get('status',200)!=200 else None)
                    # Dynamic server response has POST receipt / GET exact echo.
                    original=fixture.responses.pop
                    def response(index):
                        if fixture.responses:
                            status,body,headers,delay=original(index)
                            if status!=200:return status,body,headers,delay
                        else:status,body,headers,delay=200,None,{},0
                        if fixture.calls[-1][0]=='POST':return status,b'{"revision":1}',{'Content-Type':'application/json'},delay
                        return status,next(v[3] for v in reversed(fixture.calls) if v[0]=='POST'),{'Content-Type':'application/vnd.zrotext.workflow-context.v1'},delay
                    fixture.responses.pop=response
                    got=[]
                    for op in case['ops']:
                        if op=='author':fixture.author(case.get('text','Synthetic reviewed facts 🌱'))
                        elif op=='retry':fixture.client.retry_unknown()
                        elif op=='verify':fixture.client.verify_unknown()
                        else:fixture.client.close()
                        posts=[v for v in fixture.calls if v[0]=='POST'];state=fixture.client.state()
                        got.append(dict(phase=state['phase'],pending=state['pending'] is not None,source=fixture.client.saved_source() is not None,posts=len(posts),gets=len(fixture.calls)-len(posts),exactRetry=all(v[3]==posts[0][3] and v[2]['idempotency-key']==posts[0][2]['idempotency-key'] for v in posts),reviews=len(fixture.reviews)))
                    self.assertEqual(got,want)
                finally:fixture.doCleanups()

    def test_native_ciphertext_independently_opens_with_maintained_context_reader(self):
        fixture=ContextAuthoringTests();fixture.setUp()
        try:
            fixture.receipt();fixture.respond();self.assertEqual(fixture.author()['phase'],'saved')
            raw=fixture.calls[0][3]
            output=dict(envelope=base64.b64encode(raw).decode(),plaintext=base64.b64encode('Synthetic reviewed facts 🌱'.encode()).decode())
            value=json.loads(subprocess.check_output(['node',str(ROOT/'context-authoring-interop.mjs'),'--consume'],input=json.dumps(dict(fixture=fixture.fixture,outputs=[output])),encoding='utf-8'))
            self.assertEqual(value,dict(verified=True,opened=1))
        finally:fixture.doCleanups()
