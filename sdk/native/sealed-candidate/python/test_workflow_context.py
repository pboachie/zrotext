"""Genuine maintained context crypto, current authority and native lifecycle."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate import workflow_context as w


def dec(value):return base64.b64decode(value,validate=True)
def fixture(role=2,public=None):
    args=['node',str(Path(__file__).with_name('workflow-context-interop.mjs')),str(role)]
    if public is not None:args.append(public.hex())
    return json.loads(subprocess.check_output(args,encoding='utf-8'))
def material(f):
    root=s.enroll_root02(dec(f['rootPin']),dec(f['fingerprint']))
    manifest=s.verify_manifest02(dec(f['manifest']),root,f['now'])
    scope={k:v if type(v) is int else dec(v) for k,v in f['scope'].items()}
    custody=s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(dec(f['selectedScalar']),'big'),ec.SECP256R1())) if 'selectedScalar' in f else None
    return manifest,scope,custody
def functions(role):return (w.seal_workflow_context,w.open_workflow_context) if role==2 else (w.seal_integration_workflow_context,w.open_integration_workflow_context)


class ContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixtures=[fixture(2),fixture(3)]

    def test_real_ts_envelopes_and_native_fresh_encapsulations_bidirectionally(self):
        for f in self.fixtures:
            manifest,scope,custody=material(f);seal,opened=functions(f['role'])
            self.assertEqual(w.workflow_context_aad(scope),dec(f['aad']))
            self.assertEqual(opened(manifest,scope,10000,custody,dec(f['envelope']),require_protected=False),dec(f['plaintext']))
            first=seal(manifest,scope,10000,dec(f['plaintext']));second=seal(manifest,scope,10000,dec(f['plaintext']))
            self.assertNotEqual(first[222:287],second[222:287])
            for raw in (first,second):
                result=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('workflow-context-interop.mjs')),'--consume'],input=json.dumps(dict(fixture=f,envelope=base64.b64encode(raw).decode(),plaintext=f['plaintext'])),encoding='utf-8'))
                self.assertTrue(result['verified'])

    def test_exact_scope_and_current_authority_refuse_before_custody_or_randomness(self):
        for f in self.fixtures:
            manifest,scope,custody=material(f);seal,opened=functions(f['role'])
            for field in scope:
                value=scope[field];bad=dict(scope);bad[field]=value+1 if type(value) is int else bytes([value[0]^1])+value[1:]
                with patch.object(s.SoftwareRecipient,'exchange',side_effect=AssertionError('early custody')) as exchange:
                    with self.assertRaises(w.WorkflowContextError):opened(manifest,bad,10000,custody,dec(f['envelope']),require_protected=False)
                    exchange.assert_not_called()
            for change in ({'accountId':bytes(16)},{'revision':129},{'revision':True},{'kind':True},{'kind':4},{'expiresMs':10000},
                           {'expiresMs':10000+30*86400000+1},{'readerId':bytes([99])*32},{'deviceId':bytes([99])*16},{'trustGeneration':2}):
                with patch.object(w,'_wrap',side_effect=AssertionError('early randomness')) as draw:
                    with self.assertRaises(w.WorkflowContextError):seal(manifest,dict(scope,**change),10000,b'x')
                    draw.assert_not_called()
            other_seal,other_open=functions(3 if f['role']==2 else 2)
            with self.assertRaises(w.WorkflowContextError):other_seal(manifest,scope,10000,b'x')
            with self.assertRaises(w.WorkflowContextError):other_open(manifest,scope,10000,custody,dec(f['envelope']),require_protected=False)
            for now in (0,8999,100000):
                with self.assertRaises(w.WorkflowContextError):seal(manifest,scope,now,b'x')
            with self.assertRaises(w.WorkflowContextError):seal(object(),scope,10000,b'x')

    def test_framing_authentication_bounds_and_protected_default(self):
        for f in self.fixtures:
            manifest,scope,custody=material(f);seal,opened=functions(f['role']);raw=dec(f['envelope'])
            variants=[raw[:-1],raw+b'x',raw[:287]+bytes(4)+raw[291:]]
            for at in (0,100,222,250,len(raw)-1):
                bad=bytearray(raw);bad[at]^=1;variants.append(bad)
            for bad in variants:
                with self.assertRaises(w.WorkflowContextError):opened(manifest,scope,10000,custody,bad,require_protected=False)
            for body in (b'\xff',bytes([171])*32768):
                self.assertEqual(opened(manifest,scope,10000,custody,seal(manifest,scope,10000,body),require_protected=False),body)
            for body in (b'',bytes(32769),'x'):
                with self.assertRaises(w.WorkflowContextError):seal(manifest,scope,10000,body)
            with self.assertRaises(w.WorkflowContextError):opened(manifest,scope,10000,custody,raw)
            with self.assertRaises(w.WorkflowContextError):opened(manifest,scope,10000,object(),raw,require_protected=False)
            wrong=s.SoftwareRecipient(ec.derive_private_key(81,ec.SECP256R1()))
            with patch.object(s.SoftwareRecipient,'exchange') as exchange:
                with self.assertRaises(w.WorkflowContextError):opened(manifest,scope,10000,wrong,raw,require_protected=False)
                exchange.assert_not_called()

    def test_cancelled_open_has_no_effect_and_late_cancel_suppresses_plaintext(self):
        f=self.fixtures[0];manifest,scope,custody=material(f);token=w.WorkflowContextCancellation();token.cancel()
        with patch.object(s.SoftwareRecipient,'exchange') as exchange:
            with self.assertRaises(w.WorkflowContextError):w.open_workflow_context(manifest,scope,10000,custody,dec(f['envelope']),require_protected=False,cancel=token)
            exchange.assert_not_called()
        original=s.SoftwareRecipient.exchange;entered=threading.Event();release=threading.Event();settled=threading.Event();results=[]
        def delayed(key,point):
            entered.set();release.wait(3)
            try:return original(key,point)
            finally:settled.set()
        token=w.WorkflowContextCancellation()
        def invoke():
            try:results.append(w.open_workflow_context(manifest,scope,10000,custody,dec(f['envelope']),require_protected=False,cancel=token))
            except w.WorkflowContextError:results.append('refused')
        with patch.object(s.SoftwareRecipient,'exchange',delayed):
            thread=threading.Thread(target=invoke);thread.start();self.assertTrue(entered.wait(2));token.cancel();thread.join(1)
            self.assertEqual(results,['refused']);self.assertFalse(settled.is_set());release.set();self.assertTrue(settled.wait(2))

    def test_snapshot_and_deadline_suppress_late_sealing(self):
        f=self.fixtures[0];manifest,scope,_=material(f);original=w._wrap;entered=threading.Event();release=threading.Event();settled=threading.Event();result=[]
        body=bytearray(b'original');times=[0]
        def delayed(public,content,info,aad):
            entered.set();release.wait(3)
            try:self.assertEqual(bytes(content),b'original');return original(public,content,info,aad)
            finally:settled.set()
        def invoke():
            try:result.append(w.seal_workflow_context(manifest,scope,10000,body))
            except w.WorkflowContextError:result.append('refused')
        with patch.object(w,'_wrap',delayed),patch.object(w.time,'monotonic',side_effect=lambda:times[0]):
            thread=threading.Thread(target=invoke);thread.start();self.assertTrue(entered.wait(2));body[:]=b'changed!';scope['contextId']=bytes(16);times[0]=11
            thread.join(1);self.assertEqual(result,['refused']);release.set();self.assertTrue(settled.wait(2))

    def test_cancelled_unresolved_custody_retains_all_four_admissions(self):
        f=self.fixtures[0];manifest,scope,custody=material(f);release=threading.Event();entered=threading.Event();original=s.SoftwareRecipient.exchange
        def delayed(key,point):entered.set();release.wait(5);return original(key,point)
        try:
            with patch.object(s.SoftwareRecipient,'exchange',delayed):
                for _ in range(4):
                    entered.clear();token=w.WorkflowContextCancellation()
                    threading.Thread(target=lambda current=token:(entered.wait(2),current.cancel()),daemon=True).start()
                    with self.assertRaises(w.WorkflowContextError):w.open_workflow_context(manifest,scope,10000,custody,dec(f['envelope']),require_protected=False,cancel=token)
                entered.clear()
                with self.assertRaises(w.WorkflowContextError):w.open_workflow_context(manifest,scope,10000,custody,dec(f['envelope']),require_protected=False)
                self.assertFalse(entered.is_set())
        finally:release.set()
        deadline=time.monotonic()+2
        while w._admission._value!=4 and time.monotonic()<deadline:time.sleep(0.001)
        self.assertEqual(w.open_workflow_context(manifest,scope,10000,custody,dec(f['envelope']),require_protected=False),dec(f['plaintext']))

    @unittest.skipUnless(os.name=='nt','Windows TPM only; not protected acceptance')
    def test_actual_tpm_archive_and_integration_context_opening(self):
        from zrotext_native_candidate.cng_custody import HardwareRecipient,CngUnavailable,probe_platform
        try:probe_platform()
        except CngUnavailable as error:self.skipTest('No hardware provider: '+error.operation)
        fd,path=tempfile.mkstemp(prefix='zrotext-context-cng-',suffix='.json');os.close(fd)
        def receipt(value):
            with open(path,'w',encoding='utf-8') as file:json.dump(value,file);file.flush();os.fsync(file.fileno())
        key=HardwareRecipient.create(lambda name:receipt(dict(pending_alias=name)))
        try:
            for role in (2,3):
                f=fixture(role,key.public_point());manifest,scope,_=material(f);self.assertNotIn('selectedScalar',f)
                with HardwareRecipient.open(key.name,key.public_point()) as reopened:
                    seal,opened=functions(role)
                    self.assertEqual(opened(manifest,scope,10000,reopened,dec(f['envelope'])),dec(f['plaintext']))
                    self.assertEqual(opened(manifest,scope,10000,reopened,seal(manifest,scope,10000,b'native')),b'native')
        finally:key.delete();receipt(dict(owned_test_key_deleted=True))


if __name__=='__main__':unittest.main()
