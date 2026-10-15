"""Actual local TLS exercises exact durable ciphertext and unknown outcomes."""
from dataclasses import replace
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from zrotext_native_candidate import SoftwareSigner
from zrotext_native_candidate.outbound02_journal import OutboundJournal02
from zrotext_native_candidate.outbound_journal import OutboundJournal
from zrotext_native_candidate import compose02
from zrotext_native_candidate.sealed_http import SealedHttpClient,SealedHttpError
from test_compose02 import produce,inputs,decode,consume
from test_compose03 import inputs as inputs03
from test_election03 import produce as produce03


class SealedHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=produce();cls.fixture03=produce03()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.calls=[];self.stages=[];self.now=10000
        self.args=dict(inputs(self.fixture,SoftwareSigner(ec.derive_private_key(5,ec.SECP256R1()))),require_hardware=False)
        self.journal=OutboundJournal02(self.root/'outbound.db',decode(self.fixture['rootPin']),decode(self.fixture['fingerprint']))
        self.responses=[]
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):self.handle_request()
            def do_GET(self):self.handle_request()
            def handle_request(self):
                body=self.rfile.read(int(self.headers.get('Content-Length','0')))
                owner.calls.append((self.command,self.path,dict(self.headers),body))
                status,value,headers,delay=owner.responses.pop(0)
                time.sleep(delay)
                raw=value if type(value) is bytes else json.dumps(value).encode()
                try:
                    self.send_response(status)
                    self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(raw)+int(headers.pop('extra-length',0))))
                    for k,v in headers.items():self.send_header(k,v)
                    self.end_headers();self.wfile.write(raw)
                except (OSError,ssl.SSLError):pass
        key=ec.generate_private_key(ec.SECP256R1())
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1))
              .not_valid_after(datetime.now(timezone.utc)+timedelta(hours=1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False)
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
        ca=self.root/'ca.pem';private=self.root/'key.pem'
        ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.server=ThreadingHTTPServer(('localhost',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(ca,private)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        thread=threading.Thread(target=self.server.serve_forever,daemon=True);thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        trusted=patch.dict(os.environ,{'SSL_CERT_FILE':str(ca)});trusted.start();self.addCleanup(trusted.stop)
        self.origin='https://localhost:'+str(self.server.server_port)
        self.client=self.client_with()

    def permit(self,request):
        self.stages.append(dict(request));return dict(request,expires_ms=self.now+5000)

    def client_with(self,**options):
        return SealedHttpClient(self.origin,'synthetic-fixture-credential',options.pop('authorizer',self.permit),
                                clock=lambda:self.now,max_delay_ms=0,**options)

    def prepare(self):
        return self.client.prepare02(self.journal,**self.args,intent_id=bytes([61])*16,
                                     expected_revision=self.journal.revision(),current_manifest=self.args['manifest'])

    def respond(self,status=202,value=None,headers=None,delay=0):
        self.responses.append((status,value if value is not None else {'message_id':self.prepared.message_id,'created':True},headers or {},delay))

    def metadata(self,state='queued'):
        return dict(message_id=self.prepared.message_id,device_id=self.prepared.device_id,state=state,
                    state_version=1,created_at_ms=10000,updated_at_ms=10000,expires_at_ms=20000)

    def test_persisted_submission_retry_exact_bytes_and_reconcile_then_cancel(self):
        self.client=self.client_with(max_attempts=3)
        self.prepared=self.prepare()
        self.respond(429,{'code':'rate_limited'});self.respond()
        self.assertTrue(self.client.submit(self.prepared)['created'])
        self.assertEqual([x[3] for x in self.calls],[self.prepared.envelope]*2)
        self.assertEqual(self.calls[0][2]['Content-Type'],'application/vnd.zrotext.sealed.v1')
        self.assertFalse(any(k.lower()=='idempotency-key' for k in self.calls[0][2]))
        self.assertEqual(consume(self.fixture,self.prepared),{'verified':True,'openedRecipients':2})
        for method,state in ((self.client.reconcile,'queued'),(self.client.cancel,'cancelled')):
            self.respond(200,self.metadata(state));self.assertEqual(method(self.prepared)['state'],state)
        self.assertEqual([x[:2] for x in self.calls[2:]],[
            ('GET','/v1/sealed/messages/'+self.prepared.message_id),
            ('POST','/v1/sealed/messages/'+self.prepared.message_id+'/cancel')])
        with patch.object(compose02,'_compose') as fresh:
            self.assertEqual(self.prepare().envelope,self.prepared.envelope);fresh.assert_not_called()

    def test_timeout_is_unknown_once_and_reconcile_only_reads(self):
        self.prepared=self.prepare();self.respond(delay=6)
        with self.assertRaises(SealedHttpError) as caught:self.client_with(timeout_ms=5000).submit(self.prepared)
        self.assertEqual((caught.exception.code,caught.exception.state,caught.exception.attempts),('timeout','unknown',1))
        self.assertEqual(len(self.calls),1)
        self.respond(200,self.metadata());self.client.reconcile(self.prepared)
        self.assertEqual([x[0] for x in self.calls],['POST','GET'])

    def test_redirect_truncation_foreign_identity_and_terminal_errors_never_retry(self):
        self.prepared=self.prepare()
        cases=[(302,b'',{'Location':'/other'}),(202,{'message_id':'0'*36,'created':True},{}),
               (202,{'message_id':self.prepared.message_id,'created':True},{'extra-length':'100'}),
               (429,{'code':'queue_full'},{}),(409,{'code':'idempotency_conflict'},{}),
               (503,{'code':'not_found'},{}),(202,b'[]',{})]
        for status,value,headers in cases:
            with self.subTest(status=status,value=value):
                before=len(self.calls);self.respond(status,value,headers)
                with self.assertRaises(SealedHttpError):self.client.submit(self.prepared)
                self.assertEqual(len(self.calls),before+1)

    def test_authority_wrong_binding_expiry_throw_and_post_effect_unknown(self):
        self.prepared=self.prepare()
        for adapter in (lambda r:dict(r,message_id='foreign',expires_ms=15000),lambda r:dict(r,expires_ms=10000),
                        lambda r:None):
            with self.assertRaises(SealedHttpError) as caught:self.client_with(authorizer=adapter).submit(self.prepared)
            self.assertEqual(caught.exception.attempts,0)
        self.assertEqual(self.calls,[])
        decisions=iter([True,False])
        def post(request):return dict(request,expires_ms=15000) if next(decisions) else None
        self.respond()
        with self.assertRaises(SealedHttpError) as caught:self.client_with(authorizer=post).submit(self.prepared)
        self.assertEqual((caught.exception.code,caught.exception.state),('authority_unavailable','unknown'))

    def test_profile03_journal_integration_uses_real_elected_fixture(self):
        self.now=30000
        journal=OutboundJournal(self.root/'elected.db',decode(self.fixture03['rootPin']),decode(self.fixture03['fingerprint']))
        args=dict(inputs03(self.fixture03,SoftwareSigner(ec.derive_private_key(5,ec.SECP256R1()))),require_hardware=False)
        self.prepared=self.client.prepare03(journal,**args)
        self.respond();self.assertTrue(self.client.submit(self.prepared)['created'])
        self.assertEqual(self.client.prepare03(journal,**args).envelope,self.prepared.envelope)

    def test_expired_intent_cannot_resubmit_but_can_reconcile(self):
        self.prepared=self.prepare();self.now=20000
        with self.assertRaises(SealedHttpError):self.client.submit(self.prepared)
        self.assertEqual(self.calls,[])
        self.respond(200,self.metadata('expired'));self.assertEqual(self.client.reconcile(self.prepared)['state'],'expired')

    def test_invalid_digest_never_leaves_client(self):
        self.prepared=self.prepare()
        with self.assertRaises(Exception):self.client.submit(replace(self.prepared,unsigned_digest=bytes(32)))
        self.assertEqual(self.calls,[])

    def test_post_retry_authority_refusal_retains_prior_unknown(self):
        self.prepared=self.prepare();decisions=iter([True,False])
        def authorize(request):return dict(request,expires_ms=15000) if next(decisions) else None
        self.respond(503,{'code':'unavailable'})
        with self.assertRaises(SealedHttpError) as caught:self.client_with(authorizer=authorize,max_attempts=3).submit(self.prepared)
        self.assertEqual((caught.exception.state,caught.exception.attempts),('unknown',1))
        self.assertEqual(len(self.calls),1)

    def test_untrusted_tls_refuses_before_http(self):
        self.prepared=self.prepare()
        with patch.dict(os.environ,{'SSL_CERT_FILE':str(self.root/'missing-ca.pem')}):
            with self.assertRaises(SealedHttpError):self.client_with(max_attempts=1).submit(self.prepared)
        self.assertEqual(self.calls,[])

    def test_default_network_loss_rate_limit_and_unavailable_never_retry(self):
        self.prepared=self.prepare()
        with patch.object(self.client,'_exchange',return_value='network') as exchange:
            with self.assertRaises(SealedHttpError) as caught:self.client.submit(self.prepared)
            self.assertEqual(caught.exception.attempts,1);self.assertEqual(exchange.call_count,1)
        for code,status in (('rate_limited',429),('unavailable',503)):
            before=len(self.calls);self.respond(status,{'code':code})
            with self.assertRaises(SealedHttpError) as caught:self.client.submit(self.prepared)
            self.assertEqual(caught.exception.attempts,1);self.assertEqual(len(self.calls),before+1)

    def test_mutable_caller_buffer_cannot_change_captured_retry_bytes(self):
        self.prepared=self.prepare();mutable=bytearray(self.prepared.envelope)
        def authorize(request):mutable[0]^=1;return dict(request,expires_ms=15000)
        self.respond(429,{'code':'rate_limited'});self.respond()
        self.client_with(authorizer=authorize,max_attempts=3).submit(replace(self.prepared,envelope=mutable))
        self.assertEqual([x[3] for x in self.calls],[self.prepared.envelope]*2)

    def test_preparation_refusal_precedes_crypto_and_post_commit_retry_is_exact(self):
        self.client=self.client_with(authorizer=lambda request:None)
        with patch.object(compose02,'_compose') as draw:
            with self.assertRaises(SealedHttpError):self.prepare()
            draw.assert_not_called()
        self.assertEqual(self.journal.revision(),0)
        def authorize(request):return dict(request,expires_ms=15000) if request['unsigned_digest']=='' else None
        self.client=self.client_with(authorizer=authorize)
        with self.assertRaises(SealedHttpError):self.prepare()
        self.assertEqual(self.journal.revision(),1)
        self.client=self.client_with()
        with patch.object(compose02,'_compose') as draw:self.prepared=self.prepare();draw.assert_not_called()
        self.assertEqual(self.calls,[])

    def test_authority_expiry_during_tls_prevents_body_send(self):
        import http.client
        self.prepared=self.prepare();connect=http.client.HTTPSConnection.connect
        def delayed(connection):connect(connection);self.now=16000
        with patch.object(http.client.HTTPSConnection,'connect',delayed):
            with self.assertRaises(SealedHttpError) as caught:self.client.submit(self.prepared)
        self.assertEqual(caught.exception.code,'authority_unavailable')
        self.assertEqual(self.calls,[])

    def test_late_connection_completion_after_deadline_never_sends(self):
        import http.client
        self.prepared=self.prepare();completed=threading.Event()
        def delayed(connection):time.sleep(.2);completed.set()
        with patch.object(http.client.HTTPSConnection,'connect',delayed):
            with self.assertRaises(SealedHttpError) as caught:self.client_with(timeout_ms=40).submit(self.prepared)
            self.assertEqual(caught.exception.code,'timeout')
            # Context creation can also outlast the deadline. No delayed path is
            # allowed to submit after cancellation, whether connect was reached.
            completed.wait(3)
        self.assertEqual(self.calls,[])


if __name__=='__main__':unittest.main()
