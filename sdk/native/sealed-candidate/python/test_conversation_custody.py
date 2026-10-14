"""Maintained custody parity plus native admission and installed provenance."""
import base64
import gc
import json
import os
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch
from installed_conversation_custody_consumer import Session,oracle,check,exercise
from zrotext_native_candidate import conversation_custody as c
from zrotext_native_candidate import sealed_candidate as s

SOURCE=Path(__file__).with_name('conversation-custody-interop.mjs')


class ConversationCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=oracle(SOURCE)
    def session(self,**options):
        session=Session(self.f,**options);self.addCleanup(session.close);return session
    def test_actual_maintained_lifecycle_and_refusal_differential(self):
        rows=[{},dict(open=True),dict(setupThrow=True),dict(ownerThrow=True),dict(installThrow=True),dict(staleReadback=True),dict(confirmThrow=True),dict(replay=True),dict(close=True),dict(changedBody=True)]
        rows += [dict(scopeField=k) for k in c._SCOPE]
        rows += [dict(currentField=k) for k in ('ownerSessionLive','consentLive')]
        rows += [dict(text=t) for t in ('','\ufeffbad','bad\0text','\ud800','\ud83c\udf31','🌱','x'*32769)]
        expected=oracle(SOURCE,'--cases',dict(fixture=self.f,cases=rows));self.assertEqual(len(expected),len(rows))
        for row,want in zip(rows,expected):
            with self.subTest(row=row):
                session=self.session();client=session.client
                def decision(name,field):
                    session.events[name]+=1
                    if row.get(field):raise ValueError('declined')
                client._setup_decision=lambda b:decision('setup','setupThrow')
                client._owner_decision=lambda r:decision('owner','ownerThrow')
                client._confirm=lambda p,b:decision('confirmation','confirmThrow')
                actual_install=client._install
                def install(*args):
                    if row.get('installThrow') or row.get('staleReadback'):
                        session.events['install']+=1
                        if row.get('installThrow'):raise ValueError('uncertain')
                    else:actual_install(*args)
                client._install=install
                try:
                    client.setup();scope=dict(client.authority()['scope'])
                    if 'scopeField' in row:scope[row['scopeField']]='different'
                    if 'currentField' in row:session.current[row['currentField']]=False
                    text=row.get('text','Scope-bound native 🌱')
                    if row.get('open'):self.assertEqual(client.open_sealed(base64.b64decode(self.f['inbound']),scope),self.f['text'])
                    else:
                        ticket=client.prepare(scope,text)
                        if row.get('close'):client.close()
                        client.sign_reviewed(ticket,scope,'different' if row.get('changedBody') else text)
                        if row.get('replay'):client.sign_reviewed(ticket,scope,text)
                    got=dict(accepted=True,**session.events)
                except Exception:got=dict(accepted=False,**session.events)
                finally:session.close()
                self.assertEqual(got,want)
    def test_independent_signatures_and_both_hpke_recipients(self):
        self.assertEqual(exercise(self.f,SOURCE),dict(verified=True,openedRecipients=2,confirmation=True))
    @unittest.skipUnless(os.name=='nt','Windows protected qualification')
    def test_actual_protected_composed_root_archive_and_owned_signer(self):
        result=check(SOURCE)
        if result['skipped']:self.skipTest('qualified PCP unavailable')
        self.assertEqual(result['protected'],dict(verified=True,openedRecipients=1,confirmation=True))
    def test_discarded_reviews_release_storage_live_review_remains_one_use(self):
        session=self.session();client=session.client;client.setup();scope=client.authority()['scope']
        live=client.prepare(scope,'kept');discarded=client.prepare(scope,'discarded');self.assertEqual(len(client._reviews),2)
        del discarded;gc.collect();self.assertEqual(len(client._reviews),1)
        client.sign_reviewed(live,scope,'kept');self.assertEqual(len(client._reviews),0)
        with self.assertRaises(c.ConversationCustodyError):client.sign_reviewed(live,scope,'kept')
        self.assertEqual(session.events['confirmation'],1)
    def test_scope_values_do_not_coerce_equality(self):
        session=self.session();client=session.client;client.setup();scope=dict(client.authority()['scope'])
        class AnyValue:
            def __eq__(self,other):return True
        scope['manifest']=AnyValue()
        with self.assertRaises(s.SealedError):client.prepare(scope,'refused')
        self.assertEqual(session.events['confirmation'],0)
    def test_stale_installation_and_post_install_timeout_are_unknown(self):
        for late in (False,True):
            session=self.session();client=session.client;original=client._install
            def install(*args):
                if late:original(*args);time.sleep(.08)
            client._install=install
            with self.assertRaises(c.ConversationCustodyError) as caught:client.setup(timeout=.05 if late else 10)
            self.assertEqual(caught.exception.state,'unknown');self.assertFalse(client._ready)
    def test_parent_admission_retained_until_child_callback_settles(self):
        release=threading.Event();sessions=[]
        def block(_):release.wait(3)
        try:
            for _ in range(4):
                session=self.session(overrides=dict(consume_setup_decision=block));sessions.append(session)
                with self.assertRaises(c.ConversationCustodyError):session.client.setup(timeout=.03)
                self.assertTrue(session.client._busy)
            extra=self.session()
            with self.assertRaises(c.ConversationCustodyError) as caught:extra.client.setup()
            self.assertEqual(caught.exception.code,'capacity')
        finally:release.set()
        for session in sessions:session.close()
    def test_close_during_real_archive_exchange_suppresses_plaintext(self):
        session=self.session();client=session.client;client.setup();scope=client.authority()['scope'];archive=client._archive
        original=archive.exchange
        def exchange(point):
            value=original(point);client.close();return value
        with patch.object(archive,'exchange',exchange):
            with self.assertRaises(c.ConversationCustodyError):client.open_sealed(base64.b64decode(self.f['inbound']),scope)
    def test_signed_history_replay_and_current_snapshot_mismatch(self):
        session=self.session();client=session.client;client.setup();scope=client.authority()['scope']
        old_digest=s.sha(base64.b64decode(self.f['manifest'])[:-64]);old=session.store.history(old_digest,self.f['now'])
        self.assertEqual(s.manifest_identity(old)['digest'],old_digest)
        client._history.clear();self.assertEqual(client.open_sealed(base64.b64decode(self.f['inbound']),scope),self.f['text'])
        with self.assertRaises(s.SealedError):session.store.history(bytes(32),self.f['now'])
        session.current['manifest']=old
        with self.assertRaises(c.ConversationCustodyError):client.authority()
    def test_default_protected_policy_refuses_software_custody(self):
        session=self.session(overrides=dict(require_protected=True))
        with self.assertRaises(c.ConversationCustodyError):session.client.setup()
        self.assertEqual(session.events['install'],0)


if __name__=='__main__':unittest.main()
