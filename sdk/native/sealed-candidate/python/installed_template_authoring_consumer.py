"""Isolated installed authoring, explicit commit, and owner-session TLS effects."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import time
import unittest
from zrotext_native_candidate.template_authoring import OwnerTemplateAuthoring,TemplateAuthoringError
from zrotext_native_candidate.owner_template import OwnerTemplateError

spec=importlib.util.spec_from_file_location('authoring_owner_fixture',Path(__file__).with_name('installed_owner_template_consumer.py'))
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
dec=helper.dec
REQUEST='00000000-0000-0000-0000-000000000041'

class TemplateAuthoringTlsTests(unittest.TestCase):
    fixture=None
    native_envelope=None
    current=helper.OwnerTemplateTests.current
    session=helper.OwnerTemplateTests.session
    respond=helper.OwnerTemplateTests.respond
    def setUp(self):
        self.drafts=[];self.metadata=[]
        helper.OwnerTemplateTests.setUp(self)
        self.scope={k:v if type(v) is int else dec(v) for k,v in self.fixture['scope'].items()}
    def make(self,**changes):
        def review(value):self.drafts.append(value);return True
        options=dict(read_current=self.current,current_session=self.session,enabled=True,read_draft_state=lambda:dict(epoch=1,revision=1,custodyLive=True),consume_draft_review=review,consume_ciphertext_review=self.metadata.append);options.update(changes)
        return OwnerTemplateAuthoring(self.origin,self.binding,dec(self.fixture['scope']['templateId']),**options)
    def prepare(self):
        f=self.fixture
        return self.client.prepare(REQUEST,0,self.scope,f['content']['template'],f['content']['values'],epoch=1,draft_revision=1)
    def test_reviewed_capture_explicit_commit_and_exact_unknown_retry(self):
        ticket=self.prepare();self.assertEqual(self.calls,[]);self.assertEqual(len(self.drafts),1);self.assertEqual(len(self.metadata),1)
        with self.assertRaises(TypeError):self.drafts[0]['values']['name']='changed'
        with self.assertRaises(TypeError):self.drafts[0]['scope']['revision']=99
        self.respond(b'',0)
        with self.assertRaises(OwnerTemplateError) as caught:self.client.client.commit(ticket)
        self.assertEqual(caught.exception.state,'unknown');self.assertEqual(len(self.calls),1)
        self.respond(b'{"revision":1}',headers={'Content-Type':'application/json'})
        result=self.client.client.retry_unknown(ticket);self.assertEqual(result['state'],'acknowledged_saved_revision')
        self.assertEqual(self.calls[0],self.calls[1]);method,path,headers,raw=self.calls[0]
        self.assertEqual(method,'POST');self.assertEqual(headers['Cookie'],self.cookie);self.assertEqual(headers['x-zrotext-csrf'],self.csrf)
        type(self).native_envelope=base64.b64encode(raw).decode();self.assertEqual(len(self.drafts),1);self.assertEqual(len(self.metadata),1)
    def test_session_change_after_preparation_refuses_before_effect(self):
        ticket=self.prepare();self.csrf='rotated-synthetic'
        with self.assertRaises(OwnerTemplateError):self.client.client.commit(ticket)
        self.assertEqual(self.calls,[])
    def test_original_authoring_deadline_closes_returned_ticket(self):
        self.client.close();self.client=self.make(timeout_ms=400);self.addCleanup(self.client.close)
        ticket=self.prepare();time.sleep(.45)
        with self.assertRaises(OwnerTemplateError):self.client.client.commit(ticket)
        self.assertEqual(self.calls,[])

if __name__=='__main__':
    import zrotext_native_candidate as n
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    TemplateAuthoringTlsTests.fixture=json.load(sys.stdin)
    result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(TemplateAuthoringTlsTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print(json.dumps(dict(installed=True,template_authoring_tls=result.testsRun,envelope=TemplateAuthoringTlsTests.native_envelope)))
