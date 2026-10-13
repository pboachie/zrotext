"""Maintained one-shot enrollment and explicit host/CAS boundaries."""
import json
from pathlib import Path
import subprocess
import threading
import time
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from installed_enrollment_consumer import material,check
from zrotext_native_candidate import enrollment_ceremony as e

ROOT=Path(__file__).parent
class EnrollmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'enrollment-interop.mjs')],encoding='utf-8'))
    def setup_flow(self,case=None,**options):
        case=case or {};binding,manifest,point=material(self.fixture);events=[];current=dict(binding=binding,manifest=manifest,nowMs=self.fixture['now'],ownerSessionLive=True,consentLive=True)
        def change():
            field=case['field']
            if field.endswith('Live'):current[field]=False
            elif field=='nowMs':current[field]=self.fixture['review']['untilMs']
            else:current['binding']={**binding,field:2 if field=='generation' else '+13' if field=='peer' else bytes([9])*(32 if field.endswith('Reader') else 16)}
        def read():events.append('current');return current
        def decide(review):
            events.append('decision')
            if case.get('decline'):raise ValueError('declined')
            if case.get('stage')=='decision':change()
            return case.get('decisionValue')
        def install(*args):
            events.append('install')
            if case.get('installThrows'):raise ValueError('uncertain')
        original=e.SoftwareEnrollmentRootSigner._sign_enrollment
        def sign(self,*args):
            events.append('sign');value=bytes(64) if case.get('badSignature') else original(self,*args)
            if case.get('stage')=='sign':change()
            return value
        args=dict(signer=e.SoftwareEnrollmentRootSigner(ec.derive_private_key(7,ec.SECP256R1())),read_current=read,consume_owner_decision=decide,install_verified=install,require_protected=False);args.update(options)
        return e.ConversationEnrollment(binding,point,**args),current,events,sign
    def test_actual_maintained_lifecycle(self):
        rows=[{},dict(decisionValue=False),dict(decline=True),dict(badSignature=True),dict(installThrows=True)]
        for stage in ('decision','sign'):
            for field in ('ownerSessionLive','consentLive','nowMs','account','device','line','session','interval','generation','peer','phoneReader','archiveReader'):rows.append(dict(stage=stage,field=field))
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'enrollment-interop.mjs'),'--cases'],input=json.dumps(dict(fixture=self.fixture,cases=rows)),encoding='utf-8'))
        self.assertEqual(len(rows),len(expected))
        for case,want in zip(rows,expected):
            with self.subTest(case=case):
                flow,current,events,sign=self.setup_flow(case)
                with patch.object(e.SoftwareEnrollmentRootSigner,'_sign_enrollment',sign):
                    try:flow.enroll();accepted=True
                    except e.EnrollmentError:accepted=False
                self.assertEqual(dict(accepted=accepted,events=events),want)
    def test_actual_protected_signer_and_installed_consumer_contract(self):
        result=check(self.fixture,ROOT/'enrollment-interop.mjs');self.assertTrue(result['enrollment_verified'])
        if result['skipped']:self.skipTest('Windows protected provider unavailable')
        self.assertTrue(result['protected_enrollment'])
    def test_protected_default_and_consumed_refusal(self):
        flow,_,events,_=self.setup_flow(require_protected=True)
        with self.assertRaises(e.EnrollmentError):flow.enroll()
        self.assertEqual(events,[])
        with self.assertRaises(e.EnrollmentError) as error:flow.enroll()
        self.assertEqual(error.exception.code,'consumed')
    def test_declined_and_wrong_predecessor_cannot_sign(self):
        flow,current,events,sign=self.setup_flow(dict(decline=True))
        with patch.object(e.SoftwareEnrollmentRootSigner,'_sign_enrollment',sign):
            with self.assertRaises(e.EnrollmentError):flow.enroll()
        self.assertEqual(events,['current','decision'])
        binding,manifest,point=material(self.fixture);review,_=e._review(manifest,binding,point,self.fixture['now']);review['predecessorDigest']=bytes(32)
        with self.assertRaises(e.s.SealedError):flow._signer._sign_enrollment(review,manifest,self.fixture['now'])
    def test_immutable_review_and_captured_binding(self):
        flow,current,events,sign=self.setup_flow()
        def decide(review):
            with self.assertRaises(TypeError):review['binding']['account']=bytes(16)
            current['binding']=dict(current['binding'])
        flow._decision=decide;accepted=flow.enroll();self.assertIsNot(accepted,current['manifest'])
        with self.assertRaises(e.EnrollmentError):flow.enroll()
    def test_late_sample_refuses_before_review(self):
        flow,current,events,_=self.setup_flow();current['nowMs']=self.fixture['review']['untilMs']-25
        original=flow._read
        def slow():time.sleep(.06);return original()
        flow._read=slow
        with self.assertRaises(e.EnrollmentError) as error:flow.enroll()
        self.assertEqual(error.exception.code,'deadline');self.assertEqual(events,['current'])
    def test_timeout_retains_worker_and_suppresses_late_signature(self):
        entered=threading.Event();release=threading.Event()
        def decision(review):entered.set();release.wait(2)
        flow,_,events,sign=self.setup_flow(consume_owner_decision=decision,timeout_ms=40)
        with patch.object(e.SoftwareEnrollmentRootSigner,'_sign_enrollment',sign):
            with self.assertRaises(e.EnrollmentError):flow.enroll()
            self.assertTrue(entered.is_set())
            with self.assertRaises(e.EnrollmentError) as error:flow.enroll()
            self.assertEqual(error.exception.code,'busy');release.set();time.sleep(.04);self.assertNotIn('sign',events)
    def test_install_cancellation_is_unknown(self):
        entered=threading.Event();release=threading.Event();errors=[]
        def install(*args):entered.set();release.wait(2)
        flow,_,_,_=self.setup_flow(install_verified=install)
        def run():
            try:flow.enroll()
            except e.EnrollmentError as error:errors.append(error)
        thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(2));flow.close();thread.join(2);release.set()
        self.assertFalse(thread.is_alive());self.assertEqual(errors[0].state,'unknown');time.sleep(.04)
    def test_forged_current_and_wrong_root_refuse_before_review(self):
        flow,current,events,_=self.setup_flow();current['manifest']=object()
        with self.assertRaises(e.EnrollmentError):flow.enroll()
        self.assertEqual(events,['current'])
        wrong=e.SoftwareEnrollmentRootSigner(ec.derive_private_key(9,ec.SECP256R1()))
        flow,current,events,_=self.setup_flow(signer=wrong)
        with self.assertRaises(e.EnrollmentError):flow.enroll()
        self.assertEqual(events,['current'])
    def test_successor_replacement_during_review_is_not_same_predecessor(self):
        flow,current,events,_=self.setup_flow();binding,manifest,point=material(self.fixture);review,base=e._review(manifest,binding,point,self.fixture['now'])
        raw=review['unsigned']+flow._signer._sign_enrollment(review,manifest,self.fixture['now']);trust=e.s._accept(e.s._trusts,base.trust);successor=e.s.verify_manifest02(raw,trust,self.fixture['now'])
        flow._decision=lambda review:current.update(manifest=successor)
        with self.assertRaises(e.EnrollmentError):flow.enroll()
        self.assertNotIn('install',events)

if __name__=='__main__':unittest.main()
