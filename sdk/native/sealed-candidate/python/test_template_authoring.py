"""Maintained host review acceptance and independent native lifecycle checks."""
import base64
import json
from pathlib import Path
import subprocess
import threading
import unittest
from unittest.mock import patch
from installed_owner_template_consumer import materials
from zrotext_native_candidate.template_authoring import OwnerTemplateAuthoring,TemplateAuthoringError

ROOT=Path(__file__).parent
REQUEST='00000000-0000-0000-0000-000000000041'
def dec(v):return base64.b64decode(v)

class TemplateAuthoringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'owner-template-interop.mjs')],encoding='utf-8'))
    def make(self,**options):
        f=self.fixture;manifest,binding=materials(f)
        defaults=dict(enabled=True,read_current=lambda:dict(binding=binding,manifest=manifest,nowMs=f['now'],ownerSessionLive=True,consentLive=True,phase='active',validForMs=10000),current_session=lambda:dict(origin='https://owner.example.invalid',cookie='synthetic=session',csrf='synthetic-csrf'),read_draft_state=lambda:dict(epoch=1,revision=1,custodyLive=True),consume_draft_review=lambda _:True,consume_ciphertext_review=lambda _:None)
        defaults.update(options);return OwnerTemplateAuthoring('https://owner.example.invalid',binding,dec(f['scope']['templateId']),**defaults)
    def prepare(self,a,**changes):
        f=self.fixture;scope={k:v if type(v) is int else dec(v) for k,v in f['scope'].items()}
        args=dict(epoch=1,draft_revision=1);args.update(changes)
        return a.prepare(REQUEST,0,scope,f['content']['template'],f['content']['values'],**args)
    def test_actual_maintained_review_and_draft_fences(self):
        cases=[{},dict(decision=False),dict(decision=1),dict(decision=None),dict(custodyLive=False),dict(epochChanged=True),dict(revisionChanged=True),dict(custodyLost=True),dict(ownerLost=True),dict(csrfChanged=True),dict(template='{{missing}}'),dict(values={'name':5})]
        f=self.fixture;want=json.loads(subprocess.check_output(['node',str(ROOT/'template-authoring-interop.mjs')],input=json.dumps(dict(fixture=f,cases=cases)),encoding='utf-8'))
        manifest,binding=materials(f)
        for case,expected in zip(cases,want):
            with self.subTest(case=case):
                counts=dict(reviewed=0,metadata=0,posts=0)
                def review(value):counts['reviewed']+=1;return case.get('decision',True)
                def metadata(value):counts['metadata']+=1
                current=lambda:dict(binding=binding,manifest=manifest,nowMs=f['now'],ownerSessionLive=not(case.get('ownerLost') and counts['reviewed']),consentLive=True,phase='active',validForMs=10000)
                draft=lambda:dict(epoch=2 if case.get('epochChanged') and counts['reviewed'] else 1,revision=2 if case.get('revisionChanged') and counts['reviewed'] else 1,custodyLive=case.get('custodyLive',True) and not(case.get('custodyLost') and counts['reviewed']))
                session=lambda:dict(origin='https://owner.example.invalid',cookie='synthetic=session',csrf='rotated' if case.get('csrfChanged') and counts['reviewed'] else 'synthetic-csrf')
                a=self.make(read_current=current,read_draft_state=draft,current_session=session,consume_draft_review=review,consume_ciphertext_review=metadata)
                scope={k:v if type(v) is int else dec(v) for k,v in f['scope'].items()}
                with patch('zrotext_native_candidate.template_authoring.t.seal_encrypted_template',wraps=__import__('zrotext_native_candidate.encrypted_template',fromlist=['seal_encrypted_template']).seal_encrypted_template) as seal:
                    try:a.prepare(REQUEST,0,scope,case.get('template',f['content']['template']),case.get('values',f['content']['values']),epoch=1,draft_revision=1);accepted=True
                    except TemplateAuthoringError:accepted=False
                    if not accepted:self.assertEqual(seal.call_count,0)
                a.close();self.assertEqual(dict(accepted=accepted,**counts),expected)
    def test_invalidation_retains_admission_and_prevents_late_sealing(self):
        entered=threading.Event();release=threading.Event();errors=[]
        def review(value):entered.set();release.wait(2);return True
        a=self.make(consume_draft_review=review)
        def prepare():
            try:self.prepare(a)
            except TemplateAuthoringError as error:errors.append(error.code)
        with patch('zrotext_native_candidate.template_authoring.t.seal_encrypted_template') as seal:
            worker=threading.Thread(target=prepare);worker.start();self.assertTrue(entered.wait(1));a.invalidate();worker.join(1)
            self.assertFalse(worker.is_alive());self.assertEqual(errors,['closed'])
            with self.assertRaises(TemplateAuthoringError) as caught:self.prepare(a)
            self.assertEqual(caught.exception.code,'busy');release.set();self.assertEqual(seal.call_count,0)
    def test_owned_client_cannot_be_replaced_or_shadowed(self):
        a=self.make()
        with self.assertRaises(AttributeError):a.client=object()
        a.client.prepare_save=lambda *args:object();a.client.close=lambda:None
        ticket=self.prepare(a);self.assertIsNotNone(ticket)
        with self.assertRaises(TemplateAuthoringError) as caught:self.prepare(a)
        self.assertEqual(caught.exception.code,'pending_draft');a.close()
        with self.assertRaises(Exception):a.client.commit(ticket)

    def test_current_sample_is_captured_before_host_mutation(self):
        f=self.fixture;manifest,binding=materials(f);sample={}
        def current():
            sample.clear();sample.update(binding=binding,manifest=manifest,nowMs=f['now'],ownerSessionLive=True,consentLive=True,phase='active',validForMs=10000);return sample
        def draft():
            sample['manifest']=object();sample['nowMs']=0
            return dict(epoch=1,revision=1,custodyLive=True)
        a=self.make(read_current=current,read_draft_state=draft)
        from zrotext_native_candidate.encrypted_template import seal_encrypted_template
        with patch('zrotext_native_candidate.template_authoring.t.seal_encrypted_template',wraps=seal_encrypted_template) as seal:
            self.prepare(a);self.assertIs(seal.call_args.args[0],manifest);self.assertEqual(seal.call_args.args[2],f['now'])
        a.close()

from installed_template_authoring_consumer import TemplateAuthoringTlsTests
TemplateAuthoringTlsTests.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'owner-template-interop.mjs')],encoding='utf-8'))
