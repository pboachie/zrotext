"""Maintained decision/refusal parity and bounded native lifecycle tests."""
import base64
from pathlib import Path
import os
import threading
import time
import tempfile
import json
import unittest
from unittest.mock import patch
from installed_conversation_signer_consumer import oracle,inputs,enroll,check,protected_available
from zrotext_native_candidate import conversation_signer as c
from zrotext_native_candidate import sealed_candidate as s

SOURCE=Path(__file__).with_name('conversation-signer-interop.mjs')


class ConversationSignerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=oracle(SOURCE)
    def client(self,decision=lambda b:None,read=None):
        pin,current=inputs(self.f)
        client=c.ConversationSignerSetup02(current['binding'],decision,read or (lambda:current),record_pending_alias=lambda a:None,record_deleted_alias=lambda a:None,require_hardware=False)
        self.addCleanup(client.close)
        return client,pin,current
    def ready(self):
        client,pin,current=self.client();client.setup();enroll(SOURCE,self.f,client,pin,current)
        return client,current
    def test_actual_maintained_decisions_content_and_byte_refusals(self):
        rows=[{},dict(setupThrow=True),dict(setupField='ownerSessionLive'),dict(setupField='consentLive'),dict(reviewField='consentLive'),dict(confirmThrow=True),dict(replay=True),dict(confirmNow=40000),dict(confirmNow=9999),dict(confirmText='different')]
        rows += [dict(text=v) for v in ('','\ufeffbad','bad\0body','\ud800','\udc00','\ud83c\udf31','🌱','x'*32769)]
        rows += [dict(proofOffset=n) for n in (0,5,21,37,53,69,85,101,109,117,125,133,134,137,169,201,233,265,296)]
        rows += [dict(envelopeOffset=n) for n in (0,100,300)]
        expected=oracle(SOURCE,'--cases',dict(fixture=self.f,cases=rows));self.assertEqual(len(expected),len(rows))
        for row,want in zip(rows,expected):
            with self.subTest(row=row):
                counts=dict(calls=0,confirmation=0)
                def decide(b):
                    counts['calls']+=1
                    if row.get('setupThrow'):raise ValueError()
                    return False
                client,pin,current=self.client(decide)
                try:
                    if 'setupField' in row:current[row['setupField']]=False
                    client.setup();enroll(SOURCE,self.f,client,pin,current)
                    if 'reviewField' in row:current[row['reviewField']]=False
                    text=row.get('text','Session review 🌱');review=client.prepare_review(text)
                    proof,envelope=bytearray(review['proof']),bytearray(review['envelope'])
                    if 'proofOffset' in row:proof[row['proofOffset']]^=1
                    if 'envelopeOffset' in row:envelope[row['envelopeOffset']]^=1
                    if 'confirmNow' in row:current['nowMs']=row['confirmNow']
                    def confirm(p,b):
                        counts['confirmation']+=1
                        self.assertIn(s.sha(proof),client._used)
                        if row.get('confirmThrow'):raise ValueError()
                        return False
                    client.sign_reviewed(proof,envelope,row.get('confirmText',text),confirm)
                    if row.get('replay'):client.sign_reviewed(proof,envelope,text,confirm)
                    got=dict(accepted=True,**counts)
                except Exception:got=dict(accepted=False,**counts)
                finally:client.close()
                self.assertEqual(got,want)
    def test_independent_complete_envelope_and_confirmation_consumption(self):
        self.assertEqual(check(SOURCE),dict(installed=True,protected=False,openedRecipients=2,confirmation=True))
    def test_setup_does_not_automatically_enroll_or_authorize_its_new_key(self):
        client,_,_=self.client();client.setup()
        with self.assertRaises(c.ConversationSignerError):client.prepare_review('not enrolled')
        with self.assertRaises(c.ConversationSignerError):_ = client.public_point
        self.assertEqual(client.cleanup_state,'complete')
    @unittest.skipUnless(os.name=='nt','Windows PCP qualification requires Windows')
    def test_actual_protected_owned_key_creation_and_deletion(self):
        if not protected_available(): self.skipTest('Windows hardware provider unavailable')
        self.assertEqual(check(SOURCE,True),dict(installed=True,protected=True,openedRecipients=2,confirmation=True))
    def test_caller_binding_and_current_dictionary_are_snapshots(self):
        client,pin,current=self.client();current['binding']=dict(current['binding']);client.setup();enroll(SOURCE,self.f,client,pin,current)
        original=client._read
        def read():
            value=original();result=dict(value);result['binding']={k:bytearray(v) if type(v) is bytes else v for k,v in value['binding'].items()};return result
        client._read=read
        review=client.prepare_review('snapshot')
        with self.assertRaises(TypeError):review['body']='mutation'
        self.assertEqual(review['body'],'snapshot')
        current['binding']['generation']+=1
        with self.assertRaises(c.ConversationSignerError):client.sign_reviewed(review['proof'],review['envelope'],'snapshot',lambda p,b:None)
    def test_delayed_callback_cancellation_retains_admission_until_settlement(self):
        entered,release,cancel=threading.Event(),threading.Event(),threading.Event()
        def decide(b):entered.set();release.wait(2)
        client,_,_=self.client(decide);out=[]
        def run():
            try:out.append(client.setup(timeout=.05,cancel=cancel))
            except c.ConversationSignerError:out.append('refused')
        thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(1));thread.join(1)
        self.assertEqual(out,['refused']);self.assertTrue(client._busy);self.assertFalse(client.close())
        with self.assertRaises(c.ConversationSignerError):client.setup()
        release.set()
        for _ in range(100):
            if not client._busy:break
            time.sleep(.005)
        self.assertFalse(client._busy);self.assertFalse(client.cleanup_pending)
    def test_explicit_cancellation_and_close_during_signature_suppress_output(self):
        for action in ('cancel','close'):
            client,_=self.ready();review=client.prepare_review('close fence');entered,release,cancel=threading.Event(),threading.Event(),threading.Event();out=[]
            original=client._signature
            def blocked(*args):entered.set();release.wait(2);return original(*args)
            client._signature=blocked
            def run():
                try:out.append(client.sign_reviewed(review['proof'],review['envelope'],'close fence',lambda p,b:None,cancel=cancel))
                except c.ConversationSignerError:out.append('refused')
            thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(1))
            if action=='cancel':cancel.set()
            else:client.close()
            release.set();thread.join(1);self.assertEqual(out,['refused']);self.assertFalse(client.cleanup_pending)
    def test_setup_normal_return_is_approval_but_async_callback_is_not(self):
        client,_,_=self.client(lambda b:False);client.setup();client.close()
        async def decision(b):return None
        client,_,_=self.client(decision)
        with self.assertRaises(c.ConversationSignerError):client.setup()
    def test_default_requires_actual_protected_provider_no_software_fallback(self):
        _,current=inputs(self.f);calls=[]
        client=c.ConversationSignerSetup02(current['binding'],lambda b:calls.append('review'),lambda:current,record_pending_alias=lambda a:None,record_deleted_alias=lambda a:None)
        with patch.object(c.ConversationRole5Signer,'create',side_effect=RuntimeError('unsupported')):
            with self.assertRaises(c.ConversationSignerError):client.setup()
        self.assertEqual(calls,['review']);self.assertIsNone(client._key)

    def test_creation_failure_does_not_falsely_certify_owned_alias_deletion(self):
        _,current=inputs(self.f);events=[]
        client=c.ConversationSignerSetup02(current['binding'],lambda b:None,lambda:current,
            record_pending_alias=lambda a:events.append(('pending',a)),record_deleted_alias=lambda a:events.append(('deleted',a)))
        def failed(receipt):receipt('synthetic-exact-owned-alias');raise OSError('ambiguous creation outcome')
        with patch.object(c.ConversationRole5Signer,'create',side_effect=failed):
            with self.assertRaises(c.ConversationSignerError):client.setup()
        self.assertEqual(client.cleanup_state,'creation_outcome_unknown');self.assertFalse(client.cleanup())
        self.assertEqual(events,[('pending','synthetic-exact-owned-alias')])

    def test_all_four_worker_slots_remain_owned_through_unresolved_cleanup(self):
        release=threading.Event();clients=[];entered=[]
        try:
            for _ in range(4):
                client,_,_=self.client();client.setup();clients.append(client);event=threading.Event();entered.append(event);original=client._cleanup
                def blocked(original=original,event=event):event.set();release.wait(3);return original()
                client._cleanup=blocked
                with self.assertRaises(c.ConversationSignerError):client.close(timeout=.02)
                self.assertTrue(event.is_set());self.assertTrue(client._busy)
            fifth,_,_=self.client()
            with self.assertRaises(c.ConversationSignerError) as refused:fifth.setup()
            self.assertEqual(refused.exception.code,'capacity')
        finally:
            release.set()
            for client in clients:
                for _ in range(200):
                    if not client._busy:break
                    time.sleep(.005)
                self.assertFalse(client._busy);self.assertEqual(client.cleanup_state,'complete')
    def test_slow_current_sample_cannot_refresh_near_expiry_lifetime(self):
        _,current=inputs(self.f);current['nowMs']=99999
        def read():time.sleep(.01);return current
        client,_,_=self.client(read=read)
        with patch.object(c.ec,'generate_private_key',side_effect=AssertionError('must not generate')):
            with self.assertRaises(c.ConversationSignerError):client.setup()

    def test_confirmation_uses_captured_bytes_and_exact_manifest_highwater(self):
        client,current=self.ready();review=client.prepare_review('snapshot confirm');proof,envelope=bytearray(review['proof']),bytearray(review['envelope'])
        def confirm(p,b):proof[:]=bytes(len(proof));envelope[:]=bytes(len(envelope))
        signature=client.sign_reviewed(proof,envelope,review['body'],confirm)
        s.verify_signature(client.public_point,signature,c._CONFIRM,review['proof'])
        _,base=inputs(self.f);current['manifest']=base['manifest']
        with self.assertRaises(c.ConversationSignerError):client.prepare_review('rollback')

    @unittest.skipUnless(os.name=='nt','Windows PCP qualification requires Windows')
    def test_protected_key_deletion_waits_for_worker_and_failed_receipt_is_retryable(self):
        if not protected_available(): self.skipTest('Windows hardware provider unavailable')
        pin,current=inputs(self.f);events=[];entered,release,cancel=threading.Event(),threading.Event(),threading.Event()
        fd,name=tempfile.mkstemp(prefix='zrotext-conversation-deferred-',suffix='.jsonl');os.close(fd);receipt=Path(name)
        fail=[True]
        def record(kind,alias):
            if kind=='deleted' and fail[0]:fail[0]=False;raise OSError('synthetic receipt unavailable')
            with receipt.open('a',encoding='utf-8') as stream:
                stream.write(json.dumps(dict(kind=kind,alias=alias))+'\n');stream.flush();os.fsync(stream.fileno())
            events.append((kind,alias))
        client=c.ConversationSignerSetup02(current['binding'],lambda b:None,lambda:current,record_pending_alias=lambda a:record('pending',a),record_deleted_alias=lambda a:record('deleted',a))
        try:
            client.setup();enroll(SOURCE,self.f,client,pin,current);review=client.prepare_review('protected deferred');key=client._key
            original=key._sign_digest;deletions=[];delete=key.delete
            def blocked(digest):entered.set();release.wait(2);return original(digest)
            def deleting():deletions.append(True);return delete()
            key._sign_digest=blocked;key.delete=deleting;out=[]
            def run():
                try:out.append(client.sign_reviewed(review['proof'],review['envelope'],review['body'],lambda p,b:None,cancel=cancel))
                except c.ConversationSignerError:out.append('refused')
            thread=threading.Thread(target=run);thread.start();self.assertTrue(entered.wait(1));cancel.set();thread.join(1)
            self.assertEqual(out,['refused']);self.assertEqual(deletions,[]);self.assertTrue(client.cleanup_pending);self.assertFalse(client.close())
            release.set()
            for _ in range(200):
                if not client._busy:break
                time.sleep(.005)
            self.assertFalse(client._busy);self.assertEqual(deletions,[True]);self.assertTrue(client.cleanup_pending)
            self.assertTrue(client.cleanup());self.assertEqual(deletions,[True]);self.assertEqual(events,[('pending',key.name),('deleted',key.name)])
            receipt.unlink()
        finally:
            release.set();client.close()


if __name__=='__main__':unittest.main()
