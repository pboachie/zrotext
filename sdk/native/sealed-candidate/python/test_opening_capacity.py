"""Actual maintained opening transport comparison and installed TLS controls."""
import json
from pathlib import Path
import subprocess
import unittest
from installed_opening_capacity_consumer import OpeningCapacityTests,REQUEST,OPENING,OpeningCapacityError

ROOT=Path(__file__).parent
OpeningCapacityTests.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'opening-capacity-interop.mjs')],encoding='utf-8'))


def normalized(value,key=None):
    if hasattr(value,'items'):return {k:normalized(v,k) for k,v in value.items()}
    if type(value) is int and key in ('definition_version','state_version','pending','confirmed'):return str(value)
    return value


class OpeningCapacityInteropTests(unittest.TestCase):
    def test_maintained_state_machine_wire_and_validation_differential(self):
        cases=[dict(ops=['prepare','create','status','wrongTicket']),dict(ops=['status','prepare','create']),
               dict(ops=['prepare','dropSource','create']),dict(ops=['prepare','rotate','create']),dict(ops=['prepare','close','create']),
               dict(ops=['prepare'],rejectReview=True),dict(ops=['prepare'],changeOnReview=True)]
        cases += [dict(ops=['prepare'],sourceChange={key:value}) for key,value in [('requestAcknowledged',False),('revision',2),('envelopeDigest','0'*64)]]
        cases += [dict(ops=['prepare'],capacity=n) for n in (0,1,100,101,1.5)]
        cases += [dict(ops=['prepare','create','wrongStatus','status','retry'],responses=[dict(status=status)]) for status in (400,401,403,404,409,413,429,503,302)]
        cases += [dict(ops=['prepare','create','retry'],responses=[dict(network=True)]),dict(ops=['prepare','create','retry'],maxAttempts=1,responses=[dict(status=503)])]
        cases += [dict(ops=['prepare','create','rotateInvalid','retry'],responses=[dict(status=503)])]
        f=OpeningCapacityTests.fixture
        receipt=dict(opening=dict(opening_id=OPENING,definition_version='1',state_version='1'),offer=None,allocation_id=None,allocation_version=None,phase='open',pending='0',confirmed='0')
        ack=json.dumps(dict(account_id=f['source']['accountId'],request_id=REQUEST,outcome=dict(receipt=receipt,applied=True,recorded=True)),separators=(',',':'))
        raw_cases=[ack.replace('"state_version":"1"','"state_version":"9223372036854775807"'),
                   ack.replace('"state_version":"1"','"state_version":"9223372036854775808"'),ack.replace('"pending":"0"','"pending":0'),
                   ack.replace('"pending":"0"','"pending":"00"'),ack.replace('"confirmed":"0"','"confirmed":"101"'),
                   ack.replace('"phase":"open"','"phase":"open","phase":"closed"'),ack.replace('"recorded":true','"recorded":false'),
                   '\ufeff'+ack,'\ufeff\ufeff'+ack,'{"a":[1]}']
        cases += [dict(ops=['prepare','create'],responses=[dict(raw=raw)]) for raw in raw_cases]
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'opening-capacity-interop.mjs'),'--cases'],input=json.dumps(dict(fixture=f,cases=cases)),encoding='utf-8'))
        self.assertEqual(len(cases),len(expected))
        for case,want in zip(cases,expected):
            with self.subTest(case=case):
                fixture=OpeningCapacityTests();fixture.setUp()
                try:
                    if case.get('sourceChange'):fixture.source['receipt'].update(case['sourceChange'])
                    def review(value):
                        fixture.reviews.append(value)
                        if case.get('rejectReview'):raise ValueError('declined')
                        if case.get('changeOnReview'):fixture.source['receipt']['envelopeDigest']='a'*64
                    fixture.client=fixture.make(consume_create_review=review,max_attempts=case.get('maxAttempts',3))
                    for response in case.get('responses',[]):fixture.respond(status=0 if response.get('network') else response.get('status',200),raw=response.get('raw','').encode())
                    rows=[];ticket=None
                    for op in case['ops']:
                        try:
                            if op=='prepare':ticket=fixture.prepare(capacity=case.get('capacity',3));value=dict(prepared=True)
                            elif op=='create':value=fixture.client.create(ticket)
                            elif op=='retry':value=fixture.client.retry(ticket)
                            elif op=='status':value=fixture.client.status(OPENING)
                            elif op=='wrongStatus':value=fixture.client.status(REQUEST)
                            elif op=='wrongTicket':value=fixture.client.create(object())
                            elif op in ('rotate','rotateInvalid'):fixture.csrf='changed' if op=='rotate' else '';value=dict(rotated=True)
                            elif op=='dropSource':fixture.source=None;value=dict(dropped=True)
                            else:fixture.client.close();value=dict(closed=True)
                        except OpeningCapacityError as error:value=dict(error=error.code)
                        rows.append(dict(value=normalized(value),pending=normalized(fixture.client.state()['pending']),calls=[dict(path=v[1],body=v[3].decode()) for v in fixture.calls],reviews=len(fixture.reviews),currentReads=fixture.current_calls))
                    self.assertEqual(rows,want)
                finally:fixture.doCleanups()
