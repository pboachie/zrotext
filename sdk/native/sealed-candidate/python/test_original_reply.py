"""Maintained TS role3 ciphertext with real TLS current/final grant proofs."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate.original_reply_client import OriginalReplyClient,OriginalReplyError
from zrotext_native_candidate.original_reply_reader import open_original_reply02
import test_sealed_http as http_tests


def decode(value):return base64.b64decode(value,validate=True)
def text(value):return str(uuid.UUID(bytes=value))


def fixture(public=None):
    args=['node',str(Path(__file__).with_name('produce-selected-reply02.mjs'))]
    if public is not None:args+=['--reader-point',public.hex()]
    return json.loads(subprocess.check_output(args,encoding='utf-8'))


def material(f,custody=None):
    root=s.enroll_root02(decode(f['rootPin']),decode(f['fingerprint']))
    before=s.verify_manifest02(decode(f['predecessor']),root,10000)
    active=s.verify_manifest02(decode(f['activation']),s.advance_trust02(root,before),10000)
    scope={k:decode(f[k]) for k in ('account','device','line','interval','connector')}
    scope.update(read_grant=decode(f['readGrant']),reader=decode(f['originalReader']),peer='+12')
    if custody is None:custody=s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(f['originalScalar']),'big'),ec.SECP256R1()))
    return scope,custody,[before,active]


def proof(f,baseline=2,version=2,revoked=False):
    scope={k:decode(f[k]) for k in ('account','device','line','interval','connector')}
    scope.update(read_grant=decode(f['readGrant']),reader=decode(f['originalReader']))
    fields={field:text(scope[name]) for field,name in (('account_id','account'),('device_id','device'),('line_id','line'),
            ('interval_id','interval'),('connector_id','connector'),('read_grant_id','read_grant'))}
    chain=[]
    for item_version,name in ((1,'predecessor'),(2,'activation'),(3,'revoked' if revoked else 'successor')):
        if baseline<=item_version<=version:chain.append(dict(version=item_version,accepted_at_ms=10000,manifest_b64=f[name]))
    return dict(fields,reader_id=scope['reader'].hex(),root_generation=1,authority_revision=1,expires_at_ms=20000,
                observed_at_ms=10000,current_manifest_version=version,current_manifest_digest=s.sha(decode(f['activation' if version==2 else 'revoked' if revoked else 'successor'])[:-64]).hex(),manifest_chain=chain)


def read_result(f):
    return dict(event_id=text(decode(f['event'])),accepted_at_ms=10000,envelope_b64=f['inbound'],historical_manifest_version=2,
                statement_b64=f['selection'],approval_signature_b64=f['approval'],installation_signature_b64=f['installation'],
                activation_manifest_version=2,proof=proof(f,1))


def proposal(scope):
    return dict(account_id=text(scope['account']),action_id=str(uuid.UUID(int=201)),revision=1,line_id=text(scope['line']),
                recipient_id=str(uuid.UUID(int=202)),purpose_id=str(uuid.UUID(int=203)),content_ref=str(uuid.UUID(int=204)),content_digest='ab'*32,content_version=1,
                not_before=10,expires_at=100,timezone='UTC',window_id='window-a',routine_id=str(uuid.UUID(int=205)),authority_generation=1,commitment='informational')


class OriginalReplyTests(unittest.TestCase):
    client_with=http_tests.SealedHttpTests.client_with
    permit=http_tests.SealedHttpTests.permit

    @classmethod
    def setUpClass(cls):
        http_tests.SealedHttpTests.setUpClass.__func__(cls);cls.original=fixture()

    def setUp(self):
        http_tests.SealedHttpTests.setUp(self)
        self.scope,self.custody,self.history=material(self.original)
        self.reply=self.reply_with()

    def reply_with(self,**changes):
        args=dict(scope=self.scope,custody=self.custody,accepted_history=self.history,clock=lambda:self.now,require_protected=False)
        args.update(changes)
        return OriginalReplyClient(self.origin,'ztr_'+base64.urlsafe_b64encode(bytes([77])*32).decode().rstrip('='),**args)

    def respond(self,method,value,status=200,delay=0):self.responses.append((status,dict(kind=method,result=value),{},delay))

    def test_actual_role3_plaintext_released_after_final_current_proof(self):
        self.respond('read',read_result(self.original));self.respond('current',proof(self.original))
        result=self.reply.read_verified(decode(self.original['event']))
        self.assertEqual(result['plaintext'],self.original['text'])
        self.assertEqual(result['event_envelope_digest'],s.sha(decode(self.original['inbound'])).hex())
        self.assertEqual([json.loads(c[3])['method'] for c in self.calls],['read','current'])
        self.assertTrue(all(c[2]['Authorization'].startswith('Bearer ztr_') for c in self.calls))

    def test_final_grant_refusal_and_changed_identity_release_no_plaintext(self):
        for mutate in (lambda p:p.update(authority_revision=2),lambda p:p.update(read_grant_id=str(uuid.UUID(int=99))),
                       lambda p:p.update(expires_at_ms=10000),lambda p:p.update(current_manifest_digest='00'*32)):
            p=proof(self.original);mutate(p)
            self.respond('read',read_result(self.original));self.respond('current',p)
            with self.assertRaises(OriginalReplyError):self.reply.read(decode(self.original['event']))

    def test_scope_selection_signature_wraps_and_wrong_custody_fail_before_final_call(self):
        for field,value in (('event_id',str(uuid.UUID(int=99))),('envelope_b64',self.original['archiveOnly']),
                            ('approval_signature_b64',base64.b64encode(bytes(64)).decode())):
            row=read_result(self.original);row[field]=value;before=len(self.calls);self.respond('read',row)
            with self.assertRaises(OriginalReplyError):self.reply.read(decode(self.original['event']))
            self.assertEqual(len(self.calls),before+1)
        wrong=s.SoftwareRecipient(ec.derive_private_key(11,ec.SECP256R1()))
        self.respond('read',read_result(self.original))
        with self.assertRaises(OriginalReplyError):self.reply_with(custody=wrong).read(decode(self.original['event']))

    def test_current_chain_fork_gap_clock_and_highwater_refuse(self):
        for mutate in (lambda p:p['manifest_chain'][0].update(version=3),lambda p:p.update(root_generation=2),
                       lambda p:p.update(observed_at_ms=50000),lambda p:p.update(reader_id='00'*32),
                       lambda p:p.update(manifest_chain=[])):
            p=proof(self.original);mutate(p);self.respond('current',p)
            with self.assertRaises(OriginalReplyError):self.reply.current()
        self.now=9999
        with self.assertRaises(OriginalReplyError):self.reply.current()

    def test_page_cursor_events_and_duplicate_refusal(self):
        event=dict(event_id=text(decode(self.original['event'])),accepted_at_ms=10000,observed_at_ms=10000,
                   historical_manifest_version=2,activation_manifest_version=2,disposition='request_available',active_request_ids=[str(uuid.UUID(int=99))])
        cursor=dict(accepted_at_ms=10000,event_id=event['event_id'])
        self.respond('page',dict(events=[event],next=cursor,proof=proof(self.original)))
        self.assertEqual(self.reply.page(limit=1),dict(events=[event],next=cursor))
        self.respond('page',dict(events=[],next=None,proof=proof(self.original)))
        self.assertEqual(self.reply.page(cursor)['events'],[])
        self.assertEqual(json.loads(self.calls[-1][3])['cursor'],cursor)
        self.respond('page',dict(events=[event,event],next=None,proof=proof(self.original)))
        with self.assertRaises(OriginalReplyError):self.reply.page()

    def test_signed_successor_advances_request_highwater_and_revoked_reader_refuses(self):
        self.respond('current',proof(self.original,version=3));self.reply.current()
        self.respond('current',proof(self.original,baseline=3,version=3));self.reply.current()
        self.assertEqual(json.loads(self.calls[-1][3])['accepted_manifest_version'],3)
        row=read_result(self.original);row['proof']=proof(self.original,baseline=1,version=3)
        self.respond('read',row);self.respond('current',proof(self.original,baseline=3,version=3))
        self.assertEqual(self.reply.read(decode(self.original['event'])),self.original['text'])
        revoked=read_result(self.original);revoked['proof']=proof(self.original,baseline=1,version=3,revoked=True)
        self.respond('read',revoked)
        with self.assertRaises(OriginalReplyError):self.reply_with().read(decode(self.original['event']))

    def test_final_signed_successor_change_refuses_plaintext(self):
        self.respond('read',read_result(self.original));self.respond('current',proof(self.original,version=3))
        with self.assertRaises(OriginalReplyError):self.reply.read(decode(self.original['event']))

    def test_owner_review_consumption_status_and_unknown_no_retry(self):
        request=dict(request_id=str(uuid.UUID(int=101)),event_id=text(decode(self.original['event'])),active_request_id=None,descriptor=None)
        result=dict(event_id=request['event_id'],consumption_id=request['request_id'],disposition='owner_review',active_request_id=None,action=None)
        self.respond('consume',result);self.assertEqual(self.reply.consume(request),result)
        self.respond('status',result);self.assertEqual(self.reply.status(request['request_id']),result)
        wrong=dict(result,consumption_id=str(uuid.UUID(int=102)));self.respond('consume',wrong)
        with self.assertRaises(OriginalReplyError) as caught:self.reply.consume(request)
        self.assertEqual(caught.exception.state,'unknown')
        self.assertEqual(len(self.calls),3)
        self.assertFalse(any('x-zrotext-output-authorization' in c[2] for c in self.calls))

    def test_protected_default_and_credential_realms_refuse(self):
        with self.assertRaises(OriginalReplyError):self.reply_with(require_protected=True)
        with self.assertRaises(OriginalReplyError):OriginalReplyClient(self.origin,'ztw_'+'A'*43,scope=self.scope,custody=self.custody,
                                                                      accepted_history=self.history,clock=lambda:self.now,require_protected=False)
        self.assertEqual(self.calls,[])

    def test_proposal_consume_uses_optional_workflow_digest_and_separate_credential(self):
        from zrotext_workflow import action_digest
        output='ztw_'+base64.urlsafe_b64encode(bytes([78])*32).decode().rstrip('=')
        reply=self.reply_with(output_credential=lambda:output)
        descriptor=proposal(self.scope);request=dict(request_id=str(uuid.UUID(int=104)),event_id=text(decode(self.original['event'])),
                                                  active_request_id=str(uuid.UUID(int=105)),descriptor=descriptor)
        action={k:descriptor[k] for k in ('account_id','action_id','revision')};action['binding_digest']=action_digest(descriptor)
        result=dict(event_id=request['event_id'],consumption_id=request['request_id'],disposition='proposal',active_request_id=request['active_request_id'],action=action)
        self.respond('consume',result);self.assertEqual(reply.consume(request),result)
        headers={k.lower():v for k,v in self.calls[-1][2].items()}
        self.assertTrue(headers['authorization'].startswith('Bearer ztr_'));self.assertEqual(headers['x-zrotext-output-authorization'],'Bearer '+output)
        wrong=copy.deepcopy(result);wrong['action']['binding_digest']='00'*32;self.respond('consume',wrong)
        with self.assertRaises(OriginalReplyError) as caught:reply.consume(request)
        self.assertEqual(caught.exception.state,'unknown')
        before=len(self.calls)
        for change in ({'account_id':str(uuid.UUID(int=200))},{'line_id':str(uuid.UUID(int=200))},{'revision':10**1000},{'content_digest':'bad'}):
            invalid=copy.deepcopy(request);invalid['descriptor'].update(change)
            with self.assertRaises(OriginalReplyError):reply.consume(invalid)
        with patch.dict('sys.modules',{'zrotext_workflow':None}):
            with self.assertRaises(OriginalReplyError):reply.consume(request)
        self.assertEqual(len(self.calls),before)

    def test_timeout_after_consumption_receipt_is_unknown_and_status_recovers(self):
        reply=self.reply_with(timeout_ms=5000)
        request=dict(request_id=str(uuid.UUID(int=103)),event_id=text(decode(self.original['event'])),active_request_id=None,descriptor=None)
        result=dict(event_id=request['event_id'],consumption_id=request['request_id'],disposition='owner_review',active_request_id=None,action=None)
        self.respond('consume',result,delay=6)
        with self.assertRaises(OriginalReplyError) as caught:reply.consume(request)
        self.assertEqual(caught.exception.state,'unknown');self.assertEqual(len(self.calls),1)
        self.respond('status',result);self.assertEqual(reply.status(request['request_id']),result)
        self.assertEqual([json.loads(c[3])['method'] for c in self.calls],['consume','status'])

    @unittest.skipUnless(os.name=='nt','Windows TPM only; not protected acceptance')
    def test_actual_tpm_original_reader_with_current_and_final_https_proofs(self):
        from zrotext_native_candidate.cng_custody import HardwareRecipient,CngUnavailable,probe_platform
        try:probe_platform()
        except CngUnavailable as error:self.skipTest('No hardware provider: '+error.operation)
        fd,path=tempfile.mkstemp(prefix='zrotext-original-cng-',suffix='.json');os.close(fd)
        def receipt(value):
            with open(path,'w',encoding='utf-8') as file:json.dump(value,file);file.flush();os.fsync(file.fileno())
        key=HardwareRecipient.create(lambda name:receipt(dict(pending_alias=name)))
        try:
            f=fixture(key.public_point());scope,_,history=material(f,key)
            self.assertNotIn('originalScalar',f)
            with HardwareRecipient.open(key.name,key.public_point()) as reopened:
                reply=self.reply_with(scope=scope,custody=reopened,accepted_history=history,require_protected=True)
                self.respond('read',read_result(f));self.respond('current',proof(f))
                self.assertEqual(reply.read(decode(f['event'])),f['text'])
        finally:key.delete();receipt(dict(owned_test_key_deleted=True))


if __name__=='__main__':unittest.main()
