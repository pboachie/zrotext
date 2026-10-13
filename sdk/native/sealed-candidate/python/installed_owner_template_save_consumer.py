"""Actual TLS save effects and reconciliation, also isolated installed imports."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from zrotext_native_candidate.owner_template_save import OwnerTemplateClient
from zrotext_native_candidate.owner_template import OwnerTemplateError

spec=importlib.util.spec_from_file_location('owner_read_fixture',Path(__file__).with_name('installed_owner_template_consumer.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
dec=helper.dec
REQUEST='00000000-0000-0000-0000-000000000041'

class OwnerTemplateSaveTests(unittest.TestCase):
    fixture=None
    current=helper.OwnerTemplateTests.current
    session=helper.OwnerTemplateTests.session
    respond=helper.OwnerTemplateTests.respond
    def setUp(self):
        self.reviews=[]
        helper.OwnerTemplateTests.setUp(self)
        self.scope={k:v if type(v) is int else dec(v) for k,v in self.fixture['scope'].items()}
    def make(self,**changes):
        options=dict(read_current=self.current,current_session=self.session,enabled=True,consume_ciphertext_review=self.reviews.append);options.update(changes)
        return OwnerTemplateClient(self.origin,self.binding,dec(self.fixture['scope']['templateId']),**options)
    def prepare(self):return self.client.prepare_save(REQUEST,0,self.scope,dec(self.fixture['envelope']))
    def assert_unknown(self,call):
        with self.assertRaises(OwnerTemplateError) as caught:call()
        self.assertEqual(caught.exception.state,'unknown');self.assertIsNotNone(self.client.pending())
    def test_real_save_exact_snapshot_immutable_review_and_receipt(self):
        body=bytearray(dec(self.fixture['envelope']));ticket=self.client.prepare_save(REQUEST,0,self.scope,body);body[:]=bytes(len(body))
        self.scope['revision']=2
        with self.assertRaises(TypeError):self.reviews[0]['requestId']='different'
        with self.assertRaises(TypeError):self.reviews[0]['scope']['revision']=2
        self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'})
        result=self.client.commit(ticket);self.assertEqual(result['state'],'acknowledged_saved_revision');self.assertIsNone(self.client.pending())
        method,path,headers,raw=self.calls[0]
        self.assertEqual((method,path),('POST','/v1/owner/workflow/templates'));self.assertEqual(raw,dec(self.fixture['envelope']))
        self.assertEqual(headers['idempotency-key'],REQUEST);self.assertEqual(headers['x-zrotext-template-revision'],'0')
        self.assertEqual(headers['Cookie'],self.cookie);self.assertEqual(headers['x-zrotext-csrf'],self.csrf)
        with self.assertRaises(OwnerTemplateError):self.client.commit(ticket)
        self.assertEqual(len(self.calls),1)
    def test_unknown_network_reconciliation_never_acknowledges_and_exact_retry(self):
        ticket=self.prepare();self.respond(b'',status=0);self.assert_unknown(lambda:self.client.commit(ticket))
        pending=self.client.pending();copy=self.client.pending();copy['revision']=99;self.assertEqual(self.client.pending(),pending)
        self.respond();snapshot=self.client.verify_unknown(ticket);self.assertTrue(snapshot['matchesPending']);self.assertFalse(snapshot['requestAcknowledged']);self.assertEqual(self.client.pending(),pending)
        self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'});self.client.retry_unknown(ticket)
        posts=[c for c in self.calls if c[0]=='POST'];self.assertEqual(len(posts),2);self.assertEqual(posts[0],posts[1]);self.assertEqual(len(self.reviews),1)
    def test_all_http_refusals_stay_unknown_without_automatic_retry(self):
        for status in (400,401,403,404,409,413,429,503,302):
            self.client=self.make();ticket=self.prepare();before=len(self.calls);self.respond(b'',status=status)
            self.assert_unknown(lambda:self.client.commit(ticket));self.assertEqual(len(self.calls),before+1)
            if status in (401,403):
                with self.assertRaises(OwnerTemplateError):self.client.retry_unknown(ticket)
                self.assertEqual(len(self.calls),before+1)
            self.client.close()
    def test_retry_and_verification_limits_keep_original_pending(self):
        ticket=self.prepare()
        for call in (self.client.commit,self.client.retry_unknown,self.client.retry_unknown):
            self.respond(b'',status=0);self.assert_unknown(lambda:call(ticket))
        before=len(self.calls);self.assert_unknown(lambda:self.client.retry_unknown(ticket));self.assertEqual(len(self.calls),before)
        changed=bytearray(dec(self.fixture['envelope']));changed[-1]^=1
        for _ in range(3):
            self.respond(bytes(changed));value=self.client.verify_unknown(ticket);self.assertFalse(value['matchesPending']);self.assertFalse(value['requestAcknowledged'])
        before=len(self.calls);self.assert_unknown(lambda:self.client.verify_unknown(ticket));self.assertEqual(len(self.calls),before)
    def test_current_loss_after_response_and_csrf_rotation_before_effect(self):
        ticket=self.prepare();original=self.current
        self.client._current=lambda:dict(original(),ownerSessionLive=self.current_calls<4)
        self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'});self.assert_unknown(lambda:self.client.commit(ticket));self.assertEqual(len(self.calls),1)
        self.client=self.make();ticket=self.prepare();self.csrf='rotated-csrf';before=len(self.calls)
        with self.assertRaises(OwnerTemplateError) as caught:self.client.commit(ticket)
        self.assertEqual(caught.exception.state,'refused');self.assertIsNone(self.client.pending());self.assertEqual(len(self.calls),before)
    def test_review_cancel_and_retained_busy_admission(self):
        entered=threading.Event();release=threading.Event();errors=[]
        def review(value):entered.set();release.wait(2)
        self.client=self.make(consume_ciphertext_review=review)
        def prepare():
            try:self.prepare()
            except OwnerTemplateError as error:errors.append(error.state)
        worker=threading.Thread(target=prepare);worker.start();self.assertTrue(entered.wait(1));self.client.close();worker.join(1)
        self.assertFalse(worker.is_alive());self.assertEqual(errors,['refused']);self.assertEqual(self.calls,[])
        with self.assertRaises(OwnerTemplateError) as caught:self.client.read_latest()
        self.assertEqual(caught.exception.code,'busy');release.set()
    def test_timeout_and_noncanonical_receipts_never_publish_acknowledgement(self):
        for body in (b'{"revision":1.0}',b' {"revision":1}',b'{"revision":1,"extra":true}'):
            self.client=self.make();ticket=self.prepare();self.respond(body,headers={'Content-Type':'application/json'})
            self.assert_unknown(lambda:self.client.commit(ticket));self.client.close()
        self.client=self.make(timeout_ms=80);ticket=self.prepare();self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'},delay=.25)
        start=time.monotonic();self.assert_unknown(lambda:self.client.commit(ticket));self.assertLess(time.monotonic()-start,.5)
    def test_foreign_ticket_and_failed_review_dispatch_zero(self):
        ticket=self.prepare()
        with self.assertRaises(OwnerTemplateError):self.client.commit(object())
        self.assertEqual(self.calls,[]);self.client.close()
        def reject(value):raise ValueError('private caller detail')
        self.client=self.make(consume_ciphertext_review=reject)
        with self.assertRaises(OwnerTemplateError) as caught:self.prepare()
        self.assertNotIn('private caller detail',str(caught.exception));self.assertEqual(self.calls,[]);self.assertIsNone(self.client.pending())

    def test_read_selects_pending_record_after_operation_admission(self):
        ticket=self.prepare();entered=threading.Event();release=threading.Event();results=[]
        original=self.client._operation;reader_thread=None
        def barrier(*args,**kwargs):
            if threading.current_thread() is reader_thread:
                entered.set();release.wait(2)
            return original(*args,**kwargs)
        self.client._operation=barrier
        reader_thread=threading.Thread(target=lambda:results.append(self.client.read_latest()))
        reader_thread.start();self.assertTrue(entered.wait(1))
        self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'});self.client.commit(ticket)
        self.respond();release.set();reader_thread.join(2)
        self.assertFalse(reader_thread.is_alive());self.assertEqual(len(results),1)
        self.assertFalse(results[0]['matchesPending']);self.assertFalse(results[0]['requestAcknowledged']);self.assertIsNone(self.client.pending())

    def test_rejected_prepare_cannot_clear_another_unknown_intent(self):
        entered=threading.Event();release=threading.Event();errors=[];paused=None
        original=self.client._operation
        def barrier(*args,**kwargs):
            if threading.current_thread() is paused:entered.set();release.wait(2)
            return original(*args,**kwargs)
        self.client._operation=barrier
        def second():
            try:self.prepare()
            except OwnerTemplateError as error:errors.append(error.code)
        paused=threading.Thread(target=second);paused.start();self.assertTrue(entered.wait(1))
        ticket=self.prepare();self.respond(b'',status=0);self.assert_unknown(lambda:self.client.commit(ticket))
        pending=self.client.pending();release.set();paused.join(2)
        self.assertFalse(paused.is_alive());self.assertEqual(errors,['pending_write']);self.assertEqual(self.client.pending(),pending)
        self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'});self.client.retry_unknown(ticket)
        self.assertIsNone(self.client.pending())

if __name__=='__main__':
    import zrotext_native_candidate as n
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    OwnerTemplateSaveTests.fixture=json.load(sys.stdin)
    result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(OwnerTemplateSaveTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print(json.dumps(dict(installed=True,owner_template_save_tls=result.testsRun)))
