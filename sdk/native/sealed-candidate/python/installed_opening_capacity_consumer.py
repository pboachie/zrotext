"""Synthetic owner TLS through isolated installed opening transport APIs."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time
import unittest
import uuid
from zrotext_native_candidate.opening_capacity import OwnerOpeningCapacityClient,OpeningCapacityError
from zrotext_native_candidate.context_authoring import OwnerContextAuthoring

spec=importlib.util.spec_from_file_location('opening_owner_tls',Path(__file__).with_name('installed_owner_template_consumer.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
REQUEST='00000000-0000-0000-0000-000000000021'
OPENING='00000000-0000-0000-0000-000000000022'


class OpeningCapacityTests(unittest.TestCase):
    fixture=None
    session=helper.OwnerTemplateTests.session
    def setUp(self):
        self.reviews=[];self.source=json.loads(json.dumps(self.fixture['source']));self.head=None
        helper.OwnerTemplateTests.setUp(self);self.server.daemon_threads=False
        owner=self
        class Responses(list):
            def pop(self,index):
                method,path,_,body=owner.calls[-1]
                if self:
                    status,raw,headers,delay=super().pop(index)
                    return status,raw,headers,delay
                if path.startswith('/v1/owner/workflow/contexts'):
                    if method=='POST':owner.head=body;return 200,b'{"revision":1}',{'Content-Type':'application/json'},0
                    return 200,owner.head,{'Content-Type':'application/vnd.zrotext.workflow-context.v1'},0
                return 200,json.dumps(owner.status_value() if path.endswith('/status') else owner.ack(),separators=(',',':')).encode(),{'Content-Type':'application/json'},0
        self.responses=Responses()
    def current(self):
        self.current_calls+=1
        return dict(binding=self.binding,manifest=self.manifest,nowMs=self.fixture['now'],ownerSessionLive=self.live,consentLive=True)
    def make(self,**changes):
        options=dict(read_saved_source=lambda:self.source,read_current=self.current,current_session=self.session,consume_create_review=self.reviews.append,
                     enabled=True,total_timeout_ms=5000,attempt_timeout_ms=1000,observation_timeout_ms=5000,max_attempts=3)
        options.update(changes)
        if options['max_attempts']=='default':del options['max_attempts']
        client=OwnerOpeningCapacityClient(self.origin,self.binding,helper.dec(self.fixture['scope']['contextId']),self.fixture['scope']['expiresMs'],**options)
        self.addCleanup(client.close);return client
    def prepare(self,**changes):
        values=dict(request_id=REQUEST,opening_id=OPENING,capacity=3,decision_deadline_ms=self.fixture['now']+4000);values.update(changes)
        return self.client.prepare_create(**values)
    def receipt(self):return dict(opening=dict(opening_id=OPENING,definition_version='1',state_version='1'),offer=None,allocation_id=None,allocation_version=None,phase='open',pending='0',confirmed='0')
    def ack(self):return dict(account_id=str(uuid.UUID(bytes=self.binding['account'])),request_id=REQUEST,outcome=dict(receipt=self.receipt(),applied=True,recorded=True))
    def status_value(self):return dict(account_id=str(uuid.UUID(bytes=self.binding['account'])),receipt=self.receipt())
    def respond(self,status=200,raw=None,delay=0,media='application/json',**headers):
        self.responses.append((status,json.dumps(self.ack(),separators=(',',':')).encode() if raw is None else raw,dict(headers,**{'Content-Type':media}),delay))
    def test_actual_native_author_acknowledgment_is_reviewed_then_created(self):
        author=OwnerContextAuthoring(self.origin,self.binding,helper.dec(self.fixture['scope']['contextId']),self.fixture['scope']['expiresMs'],
            read_current=self.current,current_session=self.session,read_draft_state=lambda:dict(epoch=1,revision=1,custodyLive=True),consume_review=lambda _:None,enabled=True)
        self.addCleanup(author.close)
        self.assertEqual(author.author('Synthetic acknowledged opening facts',epoch=1,draft_revision=1)['phase'],'saved')
        source=author.saved_source();self.assertEqual(source['receipt']['envelopeDigest'],hashlib.sha256(self.head).hexdigest())
        self.client=self.make(read_saved_source=author.saved_source);before=len(self.calls);ticket=self.prepare()
        self.assertEqual(len(self.calls),before);self.assertEqual(self.reviews[0]['source'],source)
        with self.assertRaises(TypeError):self.reviews[0]['source']['receipt']['revision']=2
        result=self.client.create(ticket);self.assertEqual(result['state'],'acknowledged');self.assertTrue(result['applied'])
        method,path,headers,body=self.calls[-1];self.assertEqual(path,'/v1/owner/workflow/openings');self.assertEqual(method,'POST')
        self.assertEqual(json.loads(body)['description'],dict(context_id=source['receipt']['contextId'],revision=1,digest=source['receipt']['envelopeDigest']))
        self.assertEqual(headers['Cookie'],self.cookie);self.assertEqual(headers['x-zrotext-csrf'],self.csrf);self.assertEqual(headers['x-zrotext-opening-account'],source['accountId']);self.assertNotIn('Authorization',headers)
        self.assertIsNone(self.client.state()['pending'])
    def test_unknown_status_never_acknowledges_and_retry_is_identical(self):
        ticket=self.prepare();self.respond(503,b'');self.assertEqual(self.client.create(ticket)['state'],'unknown');first=self.calls[0]
        pending=self.client.state()['pending'];self.assertEqual(self.client.status(OPENING)['state'],'metadata_snapshot');self.assertEqual(self.client.state()['pending'],pending)
        self.assertEqual(self.client.retry(ticket)['state'],'acknowledged');self.assertEqual(first[3],self.calls[-1][3]);self.assertEqual(first[2],self.calls[-1][2])
        self.assertEqual(self.current_calls,2)
    def test_first_refusal_differs_from_prior_unknown_and_status_shares_attempt_budget(self):
        for status in (400,401,403,404,409,413,429):
            self.client=self.make();ticket=self.prepare();self.respond(status,b'');self.assertEqual(self.client.create(ticket),dict(state='refused',code='server'))
            self.client=self.make();ticket=self.prepare();self.respond(503,b'');self.client.create(ticket);self.respond(status,b'');self.assertEqual(self.client.retry(ticket)['state'],'unknown')
            self.client.close()
        self.client=self.make(max_attempts=2);ticket=self.prepare();self.respond(503,b'');self.client.create(ticket);self.client.status(OPENING)
        before=len(self.calls);self.assertEqual(self.client.retry(ticket)['code'],'attempts');self.assertEqual(len(self.calls),before)
    def test_default_one_attempt_and_no_redirect_or_network_retry(self):
        for status in (0,302,503,429):
            self.client=self.make(max_attempts='default');ticket=self.prepare();before=len(self.calls);self.respond(status,b'',Location=self.origin+'/other')
            result=self.client.create(ticket);self.assertEqual(len(self.calls),before+1)
            self.assertEqual(result['state'],'refused' if status==429 else 'unknown')
            self.client.retry(ticket);self.assertEqual(len(self.calls),before+1)
    def test_closed_decimal_dtos_and_bounded_framing(self):
        original=json.dumps(self.ack(),separators=(',',':')).encode()
        invalid=[original.replace(b'"pending":"0"',b'"pending":0'),original.replace(b'"pending":"0"',b'"pending":"00"'),
                 original.replace(b'"confirmed":"0"',b'"confirmed":"101"'),original.replace(b'"recorded":true',b'"recorded":false'),
                 original.replace(b'"applied":true',b'"applied":1'),original.replace(b'"phase":"open"',b'"phase":"open","phase":"closed"'),
                 original.replace(b'"state_version":"1"',b'"state_version":"9223372036854775808"'),b'\xef\xbb\xbf\xef\xbb\xbf'+original,b' '*8193,b'{"a":[1]}']
        for raw in invalid:
            self.client=self.make();ticket=self.prepare();self.respond(raw=raw);self.assertEqual(self.client.create(ticket)['state'],'unknown');self.client.close()
        self.client=self.make();ticket=self.prepare();self.respond(raw=b'\xef\xbb\xbf'+original);self.assertEqual(self.client.create(ticket)['state'],'acknowledged')
        self.client=self.make();ticket=self.prepare();self.respond(raw=original,**{'extra-length':4});self.assertEqual(self.client.create(ticket)['state'],'unknown')
    def test_current_source_session_and_expiry_refuse_before_effect(self):
        for change in ('source','current','session','expiry'):
            def review(_):
                if change=='source':self.source=None
                if change=='current':self.live=False
                if change=='session':self.csrf='changed'
            self.client=self.make(consume_create_review=review)
            with self.assertRaises(OpeningCapacityError):self.prepare(decision_deadline_ms=self.fixture['scope']['expiresMs']+1 if change=='expiry' else self.fixture['now']+4000)
            self.assertEqual(self.calls,[]);self.source=json.loads(json.dumps(self.fixture['source']));self.live=True;self.csrf='synthetic-csrf'
    def test_close_and_late_response_keep_unknown_without_publication(self):
        self.client=self.make(attempt_timeout_ms=100);ticket=self.prepare();self.respond(delay=.25)
        start=time.monotonic();result=self.client.create(ticket);self.assertLess(time.monotonic()-start,.5);self.assertEqual(result['state'],'unknown')
        self.client.close();self.server.shutdown();self.server.server_close()
        self.assertEqual(len(self.calls),1);self.assertIsNotNone(self.client.state()['pending']);self.assertEqual(self.client.retry(ticket)['state'],'unknown')
    def test_post_response_session_change_suppresses_acknowledgment(self):
        original=self.session
        def changed():
            value=original()
            if self.calls:value['cookie']='synthetic-owner=rotated'
            return value
        self.client=self.make(current_session=changed);ticket=self.prepare()
        result=self.client.create(ticket);self.assertEqual(result['state'],'unknown');self.assertEqual(result['code'],'closed')
        before=len(self.calls);self.assertEqual(self.client.retry(ticket)['state'],'unknown');self.assertEqual(len(self.calls),before)
    def test_blocked_current_retains_admission_and_uses_original_sample_time(self):
        release=threading.Event();clients=[]
        try:
            def slow():value=self.current();release.wait(3);return value
            for _ in range(8):
                client=self.make(read_current=slow,observation_timeout_ms=40);clients.append(client)
                with self.assertRaises(OpeningCapacityError):client.prepare_create(REQUEST,OPENING,3,self.fixture['now']+4000)
                self.assertTrue(client.state()['busy'])
            self.client=self.make()
            with self.assertRaises(OpeningCapacityError) as caught:self.prepare()
            self.assertEqual(caught.exception.code,'capacity');self.assertEqual(self.calls,[])
        finally:
            release.set();deadline=time.monotonic()+2
            while any(c.state()['busy'] for c in clients) and time.monotonic()<deadline:time.sleep(.01)
            self.assertFalse(any(c.state()['busy'] for c in clients))
        self.assertEqual(self.reviews,[]);self.client=self.make();self.assertIsNotNone(self.prepare())
    def test_overlapping_prepare_cannot_retire_reviewed_ticket(self):
        entered,release=threading.Event(),threading.Event();result=[]
        def review(_):entered.set();release.wait(2)
        self.client=self.make(consume_create_review=review)
        thread=threading.Thread(target=lambda:result.append(self.prepare()));thread.start();self.assertTrue(entered.wait(1))
        with self.assertRaises(OpeningCapacityError) as caught:self.prepare()
        self.assertEqual(caught.exception.code,'busy');release.set();thread.join(1);self.assertFalse(thread.is_alive())
        self.assertEqual(self.client.create(result[0])['state'],'acknowledged')


if __name__=='__main__':
    import zrotext_native_candidate as package
    assert Path(package.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    OpeningCapacityTests.fixture=json.load(sys.stdin)
    result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(OpeningCapacityTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print(json.dumps(dict(installed=True,opening_capacity_tls=result.testsRun)))
