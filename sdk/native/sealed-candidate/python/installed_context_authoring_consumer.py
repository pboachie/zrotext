"""Actual synthetic owner HTTPS authoring; usable from isolated distributions."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest

from zrotext_native_candidate.context_authoring import OwnerContextAuthoring

spec=importlib.util.spec_from_file_location('owner_authoring_tls',Path(__file__).with_name('installed_owner_template_consumer.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


class ContextAuthoringTests(unittest.TestCase):
    fixture=None
    outputs=[]
    session=helper.OwnerTemplateTests.session
    def setUp(self):
        self.epoch=self.revision=1;self.custody=True;self.reviews=[]
        helper.OwnerTemplateTests.setUp(self)
        self.server.daemon_threads=False
        owner=self
        class Responses(list):
            def pop(self,index):
                status,body,headers,delay=super().pop(index)
                if body is None:body=next(v[3] for v in reversed(owner.calls) if v[0]=='POST')
                return status,body,headers,delay
        self.responses=Responses()
    def current(self):
        self.current_calls+=1
        return dict(binding=self.binding,manifest=self.manifest,nowMs=self.fixture['now'],ownerSessionLive=self.live,consentLive=True)
    def make(self,**changes):
        options=dict(read_current=self.current,current_session=self.session,read_draft_state=lambda:dict(epoch=self.epoch,revision=self.revision,custodyLive=self.custody),consume_review=self.reviews.append,enabled=True)
        options.update(changes)
        author=OwnerContextAuthoring(self.origin,self.binding,helper.dec(self.fixture['scope']['contextId']),self.fixture['scope']['expiresMs'],**options)
        self.addCleanup(author.close)
        return author
    def respond(self,status=200,body=None,delay=0,content='application/vnd.zrotext.workflow-context.v1'):
        self.responses.append((status,body,{'Content-Type':content},delay))
    def receipt(self):self.respond(body=b'{"revision":1}',content='application/json')
    def author(self,text='Synthetic reviewed facts 🌱'):return self.client.author(text,epoch=self.epoch,draft_revision=self.revision)
    def test_exact_review_before_post_and_acknowledged_source(self):
        def review(value):
            self.assertEqual(self.calls,[]);self.assertEqual(self.client.state()['phase'],'review');self.assertIsNone(self.client.saved_source())
            self.reviews.append(value)
            with self.assertRaises(TypeError):value['review']['scope']['revision']=2
        self.client=self.make(consume_review=review);self.receipt();self.respond()
        self.assertEqual(dict(self.author()),dict(phase='saved',pending=None));source=self.client.saved_source()
        post=self.calls[0];self.assertEqual([v[0] for v in self.calls],['POST','GET']);self.assertEqual(post[2]['x-zrotext-context-revision'],'0')
        self.assertEqual(source['receipt']['envelopeDigest'],hashlib.sha256(post[3]).hexdigest());self.assertEqual(source['receipt']['requestId'],post[2]['idempotency-key']);self.assertIs(source['receipt']['requestAcknowledged'],True)
        self.assertEqual(self.reviews[0]['text'],'Synthetic reviewed facts 🌱');self.assertEqual(self.reviews[0]['review']['envelopeDigest'],source['receipt']['envelopeDigest'])
        before=(len(self.calls),self.current_calls);self.assertEqual(self.client.saved_source(),source);self.assertEqual(before,(len(self.calls),self.current_calls))
        for _,_,headers,_ in self.calls:self.assertEqual(headers['Cookie'],self.cookie);self.assertEqual(headers['x-zrotext-csrf'],self.csrf);self.assertNotIn('Authorization',headers)
        type(self).outputs.append(dict(envelope=base64.b64encode(post[3]).decode(),plaintext=base64.b64encode('Synthetic reviewed facts 🌱'.encode()).decode()))
        self.client.close();self.assertIsNone(self.client.saved_source())
    def test_unknown_get_cannot_acknowledge_and_retry_keeps_exact_identity(self):
        self.respond(503,b'');self.assertEqual(self.author()['phase'],'unknown');pending=self.client.state()['pending'];first=self.calls[0]
        self.respond();self.assertEqual(self.client.verify_unknown()['phase'],'unknown');self.assertIsNone(self.client.saved_source());self.assertEqual(self.client.state()['pending'],pending)
        self.receipt();self.respond();self.assertEqual(self.client.retry_unknown()['phase'],'saved')
        second=next(v for v in self.calls[1:] if v[0]=='POST');self.assertEqual(first[2]['idempotency-key'],second[2]['idempotency-key']);self.assertEqual(first[3],second[3])
    def test_three_post_and_three_check_limits_and_first_refusal(self):
        self.respond(403,b'');self.assertEqual(self.author()['phase'],'refused');self.assertIsNone(self.client.state()['pending'])
        self.client=self.make();self.respond(503,b'');self.assertEqual(self.author()['phase'],'unknown')
        for _ in range(3):self.respond();self.assertEqual(self.client.verify_unknown()['phase'],'unknown')
        before=len(self.calls);self.client.verify_unknown();self.assertEqual(len(self.calls),before)
        for _ in range(2):self.respond(403,b'');self.assertEqual(self.client.retry_unknown()['phase'],'unknown')
        before=len(self.calls);self.client.retry_unknown();self.assertEqual(len(self.calls),before)
    def test_review_refusal_draft_invalidation_and_cookie_rotation_dispatch_zero(self):
        for action in ('refuse','draft','session'):
            def review(value):
                if action=='refuse':raise ValueError('declined')
                if action=='draft':self.revision+=1
                if action=='session':self.csrf='rotated'
            self.client=self.make(consume_review=review)
            self.assertIn(self.author()['phase'],('refused','closed'));self.assertEqual(self.calls,[])
    def test_close_and_deadline_during_review_never_post(self):
        for expire in (False,True):
            entered,release=threading.Event(),threading.Event()
            def review(value):entered.set();release.wait(2)
            self.client=self.make(consume_review=review,timeout_ms=80 if expire else 1000);states=[]
            thread=threading.Thread(target=lambda:states.append(self.author()));thread.start();self.assertTrue(entered.wait(1))
            if not expire:self.client.close()
            thread.join(.5);self.assertFalse(thread.is_alive());self.assertEqual(states[0]['phase'],'closed');self.assertEqual(self.calls,[])
            release.set();time.sleep(.03);self.assertEqual(self.calls,[])
    def test_original_deadline_not_refreshed_by_reconciliation(self):
        # Leave TLS/crypto setup room, then reconcile inside the original window.
        # A refreshed deadline would still be live at the final assertion.
        self.client=self.make(timeout_ms=2000);self.respond(503,b'');started=time.monotonic()
        self.assertEqual(self.author()['phase'],'unknown');pending=self.client.state()['pending']
        time.sleep(max(0,started+1.1-time.monotonic()));self.respond()
        self.assertEqual(self.client.verify_unknown()['phase'],'unknown');self.assertEqual(self.client.state()['pending'],pending)
        time.sleep(max(0,started+2.1-time.monotonic()))
        self.assertEqual(self.client.state()['phase'],'closed')
        self.assertEqual(self.client.retry_unknown()['phase'],'closed');self.assertEqual([v[0] for v in self.calls],['POST','GET']);self.assertIsNone(self.client.saved_source())
    def test_real_post_timeout_keeps_uncertain_identity_and_does_not_retry(self):
        self.client=self.make(timeout_ms=100);self.respond(body=b'{"revision":1}',delay=.25,content='application/json')
        start=time.monotonic();state=self.author();self.assertLess(time.monotonic()-start,.5)
        self.assertIn(state['phase'],('unknown','closed'));self.assertIsNotNone(state['pending']);self.assertIsNone(self.client.saved_source())
        time.sleep(.03);self.assertEqual(self.client.state()['phase'],'closed')
        self.server.shutdown();self.server.server_close()
        self.assertEqual([v[0] for v in self.calls],['POST'])
    def test_slow_current_and_mutated_draft_refuse_before_review_or_post(self):
        def slow():
            sample=self.current();time.sleep(.15);return sample
        self.client=self.make(read_current=slow,timeout_ms=80)
        self.assertEqual(self.author()['phase'],'closed');time.sleep(.18)
        self.assertEqual(self.calls,[]);self.assertEqual(self.reviews,[])
        def changed():
            sample=self.current();self.revision+=1;return sample
        self.client=self.make(read_current=changed)
        self.assertEqual(self.author()['phase'],'closed');self.assertEqual(self.calls,[]);self.assertEqual(self.reviews,[])
    def test_missing_phone_authority_and_unawaited_review_fail_closed(self):
        original=self.binding
        self.binding=dict(original,phoneReader=bytes([9])*32)
        self.client=self.make();self.assertEqual(self.author()['phase'],'closed')
        self.assertEqual(self.calls,[]);self.assertEqual(self.reviews,[])
        self.binding=original
        async def review(value):raise AssertionError('must not run')
        self.client=self.make(consume_review=review)
        self.assertEqual(self.author()['phase'],'refused');self.assertEqual(self.calls,[])
    def test_unresolved_reviews_retain_four_worker_slots_after_close(self):
        release=threading.Event();authors=[];threads=[]
        try:
            for _ in range(4):
                entered=threading.Event()
                def review(value,event=entered):event.set();release.wait(3)
                author=self.make(consume_review=review,timeout_ms=2000);authors.append(author)
                thread=threading.Thread(target=lambda a=author:a.author('Facts',epoch=1,draft_revision=1));threads.append(thread);thread.start()
                self.assertTrue(entered.wait(1));author.close();thread.join(.5);self.assertFalse(thread.is_alive())
            extra=self.make();self.assertEqual(extra.author('Facts',epoch=1,draft_revision=1)['phase'],'refused')
            self.assertEqual(self.calls,[])
        finally:
            release.set()
            for thread in threads:thread.join(1)
            deadline=time.monotonic()+2
            while any(a._busy.locked() for a in authors) and time.monotonic()<deadline:time.sleep(.01)
            self.assertFalse(any(a._busy.locked() for a in authors))
        self.client=self.make();self.receipt();self.respond();self.assertEqual(self.author()['phase'],'saved')
    def test_utf16_textencoder_bytes_and_invalid_bound_without_authority(self):
        for text,encoded in (('\ud800','�'.encode()),('\ud83c\udf31','🌱'.encode()),('\ufefffacts','\ufefffacts'.encode()),('x\0y',b'x\0y')):
            self.client=self.make();self.receipt();self.respond();self.assertEqual(self.author(text)['phase'],'saved')
            type(self).outputs.append(dict(envelope=base64.b64encode(self.calls[-2][3]).decode(),plaintext=base64.b64encode(encoded).decode()));self.client.close()
        for text in ('','x'*32769,'☃'*12000):
            self.client=self.make();before=(len(self.calls),self.current_calls);self.assertEqual(self.author(text)['phase'],'refused');self.assertEqual(before,(len(self.calls),self.current_calls))


if __name__=='__main__':
    import zrotext_native_candidate as package
    assert Path(package.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    ContextAuthoringTests.fixture=json.load(sys.stdin)
    result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(ContextAuthoringTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print(json.dumps(dict(installed=True,context_authoring_tls=result.testsRun,outputs=ContextAuthoringTests.outputs)))
