"""Actual owner context HTTPS behavior in source and installed consumers."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from zrotext_native_candidate.owner_context import OwnerWorkflowContextClient,OwnerContextError
from zrotext_native_candidate.workflow_context import seal_workflow_context

spec=importlib.util.spec_from_file_location('owner_read_fixture',Path(__file__).with_name('installed_owner_template_consumer.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
dec=helper.dec
REQUEST='00000000-0000-0000-0000-000000000041'
_CONTENT='application/vnd.zrotext.workflow-context.v1'

class OwnerContextTests(unittest.TestCase):
    fixture=None
    native_envelope=None
    current=helper.OwnerTemplateTests.current
    session=helper.OwnerTemplateTests.session
    def setUp(self):
        self.reviews=[];helper.OwnerTemplateTests.setUp(self)
        self.scope={k:v if type(v) is int else dec(v) for k,v in self.fixture['scope'].items()}
    def make(self,**changes):
        options=dict(read_current=self.current,current_session=self.session,enabled=True,consume_write_review=self.reviews.append);options.update(changes)
        return OwnerWorkflowContextClient(self.origin,self.binding,dec(self.fixture['scope']['contextId']),self.fixture['scope']['kind'],**options)
    def respond(self,body=None,status=200,headers=None,delay=0):
        return helper.OwnerTemplateTests.respond(self,body,status,dict({'Content-Type':_CONTENT},**(headers or {})),delay)
    def prepare(self,body=None):return self.client.prepare(REQUEST,0,self.scope,dec(self.fixture['envelope']) if body is None else body)
    def receipt(self):self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'})
    def unknown(self,call):
        with self.assertRaises(OwnerContextError) as caught:call()
        self.assertEqual(caught.exception.state,'unknown');self.assertIsNotNone(self.client.pending())
    def test_native_crypto_post_requires_exact_get_before_acknowledgement(self):
        raw=seal_workflow_context(self.manifest,self.scope,self.fixture['now'],dec(self.fixture['plaintext']))
        type(self).native_envelope=base64.b64encode(raw).decode();ticket=self.prepare(raw);self.receipt();self.respond(raw)
        value=self.client.commit(ticket);self.assertTrue(value['requestAcknowledged']);self.assertEqual(value['state'],'verified_current_snapshot');self.assertIsNone(self.client.pending())
        self.assertEqual([c[0] for c in self.calls],['POST','GET']);self.assertEqual(self.calls[0][3],raw)
        for method,path,headers,body in self.calls:
            self.assertTrue(path.startswith('/v1/owner/workflow/contexts'));self.assertEqual(headers['Cookie'],self.cookie);self.assertEqual(headers['x-zrotext-csrf'],self.csrf);self.assertNotIn('Authorization',headers)
        self.assertEqual(self.calls[0][2]['x-zrotext-context-revision'],'0')
        with self.assertRaises(TypeError):self.reviews[0]['scope']['revision']=2
    def test_first_refusals_clear_intent_but_prior_unknown_refusals_do_not(self):
        for status,code in ((400,'invalid_request'),(401,'unauthorized'),(403,'forbidden'),(404,'not_found'),(409,'conflict'),(413,'too_large'),(429,'rate_limited')):
            self.client=self.make();ticket=self.prepare();before=len(self.calls);self.respond(b'',status)
            with self.assertRaises(OwnerContextError) as caught:self.client.commit(ticket)
            self.assertEqual((caught.exception.code,caught.exception.state),(code,'refused'));self.assertIsNone(self.client.pending());self.assertEqual(len(self.calls),before+1)
            self.client.close();self.client=self.make();ticket=self.prepare();self.respond(b'',0);self.unknown(lambda:self.client.commit(ticket))
            self.respond(b'',status);self.unknown(lambda:self.client.retry_unknown(ticket));self.client.close()
    def test_unknown_snapshot_never_acknowledges_and_retry_is_exact(self):
        ticket=self.prepare();self.respond(b'',0);self.unknown(lambda:self.client.commit(ticket));pending=self.client.pending()
        self.respond();value=self.client.verify_unknown(ticket);self.assertFalse(value['requestAcknowledged']);self.assertEqual(self.client.pending(),pending)
        self.receipt();self.respond();self.assertTrue(self.client.retry_unknown(ticket)['requestAcknowledged'])
        posts=[c for c in self.calls if c[0]=='POST'];self.assertEqual(posts[0],posts[1]);self.assertEqual(len(self.reviews),1)
    def test_acknowledged_newer_head_is_not_current_but_unknown_newer_head_stays_unknown(self):
        ticket=self.prepare();self.receipt();self.respond(dec(self.fixture['newer']))
        with self.assertRaises(OwnerContextError) as caught:self.client.commit(ticket)
        self.assertEqual((caught.exception.code,caught.exception.state),('head_changed','not_current'));self.assertIsNone(self.client.pending())
        self.client=self.make();ticket=self.prepare();self.respond(b'',0);self.unknown(lambda:self.client.commit(ticket))
        self.respond(dec(self.fixture['newer']));self.unknown(lambda:self.client.verify_unknown(ticket))
    def test_wrong_current_head_and_lost_get_never_acknowledge(self):
        for body in (b'bad',dec(self.fixture['envelope'])[:-1]):
            self.client=self.make();ticket=self.prepare();self.receipt();self.respond(body);self.unknown(lambda:self.client.commit(ticket));self.client.close()
        self.client=self.make();ticket=self.prepare();self.receipt();self.respond(b'',0);self.unknown(lambda:self.client.commit(ticket));self.assertIsNotNone(self.client.pending())
    def test_session_rotation_timeout_and_redirect_refuse_without_hidden_retries(self):
        ticket=self.prepare();self.csrf='rotated'
        with self.assertRaises(OwnerContextError):self.client.commit(ticket)
        self.assertEqual(self.calls,[])
        self.client=self.make();ticket=self.prepare();self.respond(b'',302,{'Location':'/other'});self.unknown(lambda:self.client.commit(ticket));self.assertEqual(len(self.calls),1)
        self.client.close();self.client=self.make(timeout_ms=80);ticket=self.prepare();self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'},delay=.25)
        start=time.monotonic();self.unknown(lambda:self.client.commit(ticket));self.assertLess(time.monotonic()-start,.5)
    def test_review_cancellation_wrong_ticket_and_wrong_kind_dispatch_zero(self):
        ticket=self.prepare()
        with self.assertRaises(OwnerContextError) as caught:self.client.commit(object())
        self.assertEqual(caught.exception.code,'invalid_ticket');self.client.close()
        entered=threading.Event();release=threading.Event();errors=[]
        def review(value):entered.set();release.wait(2)
        self.client=self.make(consume_write_review=review)
        def prepare():
            try:self.prepare()
            except OwnerContextError as error:errors.append(error.state)
        worker=threading.Thread(target=prepare);worker.start();self.assertTrue(entered.wait(1));self.client.close();worker.join(1);release.set()
        self.assertFalse(worker.is_alive());self.assertEqual(errors,['refused']);self.assertEqual(self.calls,[])
        self.client=OwnerWorkflowContextClient(self.origin,self.binding,self.scope['contextId'],1,enabled=True,read_current=self.current,current_session=self.session,consume_write_review=self.reviews.append)
        with self.assertRaises(OwnerContextError):self.prepare()
        self.assertEqual(self.calls,[])

    def test_all_supported_context_kinds_accept_real_maintained_ciphertext(self):
        for kind in (1,2):
            scope=dict(self.scope,kind=kind);raw=dec(self.fixture['kinds'][str(kind)])
            self.client=OwnerWorkflowContextClient(self.origin,self.binding,scope['contextId'],kind,enabled=True,read_current=self.current,current_session=self.session,consume_write_review=self.reviews.append)
            ticket=self.client.prepare(REQUEST,0,scope,raw);self.receipt();self.respond(raw)
            self.assertTrue(self.client.commit(ticket)['requestAcknowledged']);self.client.close()

    def test_prepare_rechecks_pending_after_admission_gap(self):
        for uncertain in (False,True):
            self.client=self.make();self.reviews.clear()
            engine=self.client._OwnerWorkflowContextClient__session;original=engine._operation
            entered=threading.Event();release=threading.Event();errors=[];paused=None
            def barrier(*args,**kwargs):
                if threading.current_thread() is paused:entered.set();release.wait(2)
                return original(*args,**kwargs)
            engine._operation=barrier
            def second():
                try:self.prepare()
                except OwnerContextError as error:errors.append(error.code)
            paused=threading.Thread(target=second);paused.start();self.assertTrue(entered.wait(1))
            ticket=self.prepare()
            if uncertain:self.respond(b'',0);self.unknown(lambda:self.client.commit(ticket))
            pending=self.client.pending();release.set();paused.join(2)
            self.assertFalse(paused.is_alive());self.assertEqual(errors,['pending_write']);self.assertEqual(len(self.reviews),1);self.assertEqual(self.client.pending(),pending)
            self.receipt();self.respond();method=self.client.retry_unknown if uncertain else self.client.commit
            self.assertTrue(method(ticket)['requestAcknowledged']);self.client.close()

if __name__=='__main__':
    import zrotext_native_candidate as n
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    OwnerContextTests.fixture=json.load(sys.stdin)
    result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(OwnerContextTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print(json.dumps(dict(installed=True,owner_context_tls=result.testsRun,envelope=OwnerContextTests.native_envelope)))
