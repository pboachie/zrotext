"""Maintained genesis lifecycle differential and native cancellation boundaries."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import threading
import time
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import genesis_ceremony as g

ROOT=Path(__file__).parent
def decode(f):
    value=copy.deepcopy(f['input'])
    for key in ('rootPin','comparedRootFingerprint','phoneReaderPoint','archiveReaderPoint','phoneSignerPoint'):value[key]=base64.b64decode(value[key])
    for key in ('account','session','device','line','phoneSigningFingerprint'):value['selection'][key]=base64.b64decode(value['selection'][key])
    return value

class GenesisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=json.loads(subprocess.check_output(['node',str(ROOT/'genesis-ceremony-interop.mjs')],encoding='utf-8'))
    def setup_flow(self,case=None,**options):
        case=case or {};value=decode(self.fixture);events=[]
        current=dict(selection=copy.deepcopy(value['selection']),rootPin=value['rootPin'],nowMs=value['nowMs'],version=0,manifest=None,ownerSessionLive=True,authorityLive=True,deviceKeyLive=True,lineBindingLive=True)
        def change():
            field=case['field']
            if field.endswith('Live'):current[field]=False
            elif field=='nowMs':current[field]=value['expiresMs']
            elif field=='version':current[field]=1
            else:current['selection'][field]=2 if field=='generation' else bytes([9])*(32 if field=='phoneSigningFingerprint' else 16)
        def read():events.append('current');return current
        def decision(review):
            events.append('decision')
            if case.get('decline'):raise ValueError('declined')
            if case.get('stage')=='decision':change()
            return case.get('decisionValue')
        def install(raw,snapshot):
            events.append('install')
            if case.get('installThrows'):raise ValueError('uncertain')
            if not case.get('missing'):current.update(version=1,manifest=raw if not case.get('fork') else raw[:-64]+bytes(64))
            if case.get('stage')=='install':change()
        signer=g.SoftwareGenesisRootSigner(ec.derive_private_key(int.from_bytes(base64.b64decode(self.fixture['scalar']),'big'),ec.SECP256R1()))
        original=g.SoftwareGenesisRootSigner._sign_genesis
        def sign(self,unsigned):
            events.append('sign');signature=bytes(64) if case.get('badSignature') else original(self,unsigned)
            if case.get('stage')=='sign':change()
            return signature
        args=dict(signer=signer,read_current=read,consume_owner_decision=decision,install=install,require_protected=False);args.update(options)
        return g.ConversationGenesis(value,**args),current,events,sign,value
    def test_maintained_lifecycle_differential(self):
        rows=[{},dict(decisionValue=False),dict(decline=True),dict(badSignature=True),dict(installThrows=True),dict(missing=True),dict(fork=True)]
        for stage in ('decision','sign','install'):
            for field in ('ownerSessionLive','authorityLive','deviceKeyLive','lineBindingLive','nowMs','account','session','device','line','phoneSigningFingerprint','generation'):rows.append(dict(stage=stage,field=field))
        expected=json.loads(subprocess.check_output(['node',str(ROOT/'genesis-ceremony-interop.mjs'),'--cases'],input=json.dumps(rows),encoding='utf-8'))
        self.assertEqual(len(rows),len(expected))
        for case,want in zip(rows,expected):
            with self.subTest(case=case):
                flow,current,events,sign,_=self.setup_flow(case)
                with patch.object(g.SoftwareGenesisRootSigner,'_sign_genesis',sign):
                    try:flow.provision();accepted=True
                    except g.GenesisCeremonyError:accepted=False
                self.assertEqual(dict(accepted=accepted,events=events),want)
    def test_independent_maintained_signature_and_one_shot(self):
        flow,current,events,sign,_=self.setup_flow()
        with patch.object(g.SoftwareGenesisRootSigner,'_sign_genesis',sign):flow.provision()
        receipt=json.loads(subprocess.check_output(['node',str(ROOT/'genesis-ceremony-interop.mjs'),'--consume'],input=json.dumps(dict(input=self.fixture['input'],signed=base64.b64encode(current['manifest']).decode())),encoding='utf-8'))
        self.assertTrue(receipt['verified'])
        with self.assertRaises(g.GenesisCeremonyError) as error:flow.provision()
        self.assertEqual(error.exception.code,'consumed');self.assertEqual(events.count('install'),1)
    def test_default_protected_refuses_software_before_review(self):
        flow,_,events,_,_=self.setup_flow(require_protected=True)
        with self.assertRaises(g.GenesisCeremonyError):flow.provision()
        self.assertEqual(events,[])
    def test_snapshot_and_immutable_review(self):
        flow,current,events,sign,value=self.setup_flow()
        def decide(review):
            with self.assertRaises(TypeError):review['unsigned']=b'changed'
            value['selection']['account']=bytes(16);value['rootPin']=bytes(94)
        flow._decision=decide
        with patch.object(g.SoftwareGenesisRootSigner,'_sign_genesis',sign):flow.provision()
        self.assertEqual(current['manifest'][5:21],base64.b64decode(self.fixture['input']['selection']['account']))
    def test_timed_out_review_retains_admission_until_settled(self):
        entered=threading.Event();release=threading.Event();finished=threading.Event()
        def decision(review):entered.set();release.wait(3);finished.set()
        flow,_,events,sign,_=self.setup_flow(consume_owner_decision=decision,timeout_ms=50)
        with patch.object(g.SoftwareGenesisRootSigner,'_sign_genesis',sign):
            with self.assertRaises(g.GenesisCeremonyError) as error:flow.provision()
            self.assertTrue(entered.is_set());self.assertEqual(error.exception.state,'refused')
            with self.assertRaises(g.GenesisCeremonyError) as busy:flow.provision()
            self.assertEqual(busy.exception.code,'busy');release.set();self.assertTrue(finished.wait(2))
            time.sleep(.03);self.assertNotIn('sign',events);self.assertNotIn('install',events)
    def test_cancel_during_install_is_unknown_and_not_repeated(self):
        entered=threading.Event();release=threading.Event();errors=[]
        def install(raw,current):entered.set();release.wait(3)
        flow,_,events,sign,_=self.setup_flow(install=install)
        def run():
            try:flow.provision()
            except g.GenesisCeremonyError as error:errors.append(error)
        with patch.object(g.SoftwareGenesisRootSigner,'_sign_genesis',sign):
            thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(2));flow.close();thread.join(2)
            self.assertFalse(thread.is_alive());self.assertEqual(errors[0].state,'unknown');release.set()
            time.sleep(.03)
            with self.assertRaises(g.GenesisCeremonyError):flow.provision()
    def test_actual_protected_signing_and_maintained_readback(self):
        from installed_genesis_ceremony_consumer import check
        result=check(self.fixture,ROOT/'genesis-ceremony-interop.mjs')
        self.assertTrue(result['genesis_verified'])
        if result['skipped']:self.skipTest('Windows hardware provider unavailable')
        self.assertTrue(result['protected_genesis'])
    def test_sampled_expiry_bounds_slow_signing_with_constant_clock(self):
        flow,current,events,sign,_=self.setup_flow();current['nowMs']=flow._input['expiresMs']-30
        def slow(signer,unsigned):time.sleep(.08);return sign(signer,unsigned)
        with patch.object(g.SoftwareGenesisRootSigner,'_sign_genesis',slow):
            with self.assertRaises(g.GenesisCeremonyError) as error:flow.provision()
            self.assertEqual(error.exception.code,'deadline');self.assertEqual(error.exception.state,'refused')
            time.sleep(.1);self.assertNotIn('install',events)
    def test_readback_crypto_overrun_is_unknown(self):
        flow,current,events,sign,_=self.setup_flow();original=g.s.verify_manifest02;calls=0
        def verify(*args,**kwargs):
            nonlocal calls
            calls+=1
            if calls==2:time.sleep(.08)
            return original(*args,**kwargs)
        current['nowMs']=flow._input['expiresMs']-40
        with patch.object(g.s,'verify_manifest02',verify):
            with self.assertRaises(g.GenesisCeremonyError) as error:flow.provision()
            self.assertEqual(error.exception.state,'unknown');time.sleep(.1)
    def test_delayed_initial_sample_does_not_extend_expiry(self):
        flow,current,events,sign,_=self.setup_flow();current['nowMs']=flow._input['expiresMs']-25
        original=flow._read
        def delayed():time.sleep(.06);return original()
        flow._read=delayed
        with self.assertRaises(g.GenesisCeremonyError) as error:flow.provision()
        self.assertEqual(error.exception.code,'deadline');self.assertEqual(events,['current'])

if __name__=='__main__':unittest.main()
