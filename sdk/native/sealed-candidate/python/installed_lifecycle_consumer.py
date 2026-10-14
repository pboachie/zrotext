"""Real synthetic TLS acceptance, also run with isolated installed imports."""
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import zrotext_native_candidate as n
from zrotext_native_candidate.sealed_lifecycle import SealedLifecycleClient,SealedLifecycleError

ID='00000000-0000-0000-0000-000000000001'
def metadata(**changes):return dict(message_id=ID,device_id=ID,state='queued',state_version=1,created_at_ms=1,updated_at_ms=1,expires_at_ms=2,**changes)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);folder=Path(self.temp.name)
        self.calls=[];self.responses=[];owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):self.handle_request()
            def do_POST(self):self.handle_request()
            def handle_request(self):
                owner.calls.append((self.command,self.path,dict(self.headers),self.rfile.read(int(self.headers.get('Content-Length','0')))))
                status,body,headers,delay=owner.responses.pop(0);time.sleep(delay)
                if status==0:
                    self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                raw=body if type(body) is bytes else json.dumps(body).encode()
                try:
                    self.send_response(status);self.send_header('Content-Type','application/json')
                    self.send_header('Content-Length',str(len(raw)+headers.get('extra-length',0)))
                    for key,value in headers.items():
                        if key!='extra-length':self.send_header(key,value)
                    self.end_headers();self.wfile.write(raw)
                except (OSError,ssl.SSLError):pass
        key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address(socket.gethostbyname('localhost')))]),False).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
        ca=folder/'ca.pem';private=folder/'key.pem';ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.server=ThreadingHTTPServer(('localhost',0),Handler);self.server.daemon_threads=False
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(ca,private)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        trust=patch.dict(os.environ,{'SSL_CERT_FILE':str(ca)});trust.start();self.addCleanup(trust.stop)
        self.origin='https://'+socket.gethostbyname('localhost')+':'+str(self.server.server_port);self.client=SealedLifecycleClient(self.origin,'synthetic-fixture-credential')

    def respond(self,body,status=200,headers=None,delay=0):self.responses.append((status,body,headers or {},delay))
    def invoke(self,operation,argument=None):return getattr(self.client,operation)(argument) if argument is not None else self.client.list()

    def test_cold_metadata_and_exact_pagination_without_content_or_ambient_authority(self):
        self.respond(metadata(),headers={'Set-Cookie':'synthetic=unused'})
        with patch.dict(os.environ,{'HTTPS_PROXY':'http://synthetic-proxy.example.invalid','HTTP_PROXY':'http://synthetic-proxy.example.invalid'}):
            self.assertEqual(self.client.status(ID),metadata())
        row=metadata();row['state']='cancelled';self.respond(row);self.assertEqual(self.client.cancel(ID),row)
        rows=[dict(metadata(),message_id=f'00000000-0000-0000-0000-{index:012x}') for index in range(1,21)]
        self.respond(dict(messages=rows,next_cursor=rows[-1]['message_id']))
        page=self.client.list();self.assertEqual(page['messages'],rows)
        self.respond(dict(messages=[],next_cursor=None));self.assertEqual(self.client.list(page['next_cursor']),dict(messages=[],next_cursor=None))
        self.assertEqual([c[:2] for c in self.calls],[('GET','/v1/sealed/messages/'+ID),('POST','/v1/sealed/messages/'+ID+'/cancel'),('GET','/v1/sealed/messages'),('GET','/v1/sealed/messages?cursor='+rows[-1]['message_id'])])
        for _,_,headers,body in self.calls:
            self.assertEqual(body,b'');self.assertEqual(headers['Authorization'],'Bearer synthetic-fixture-credential')
            self.assertFalse(any(k.lower() in ('cookie','content-type','idempotency-key') for k in headers))
        self.assertNotIn('synthetic-fixture-credential',repr(self.client))

    def test_request_refusals_dispatch_zero_and_preserve_safe_integer_semantics(self):
        for value in ('../messages','A0000000-0000-0000-0000-000000000001','',1,None):
            for call in (self.client.status,self.client.cancel):
                with self.assertRaises(SealedLifecycleError) as caught:call(value)
                self.assertEqual((caught.exception.state,caught.exception.attempts),('refused',0))
            if value is not None:
                with self.assertRaises(SealedLifecycleError):self.client.list(value)
        self.assertEqual(self.calls,[])
        for origin in ('http://localhost','https://localhost/path','https://localhost/?x=1'):
            with self.assertRaises(SealedLifecycleError):SealedLifecycleClient(origin,'synthetic')
        for timeout in (0,True,10**1000,float('nan'),120001):
            with self.assertRaises(SealedLifecycleError):SealedLifecycleClient(self.origin,'synthetic',timeout_ms=timeout)
        row=metadata();row['state_version']=1.0;row['created_at_ms']=(1<<53)-1;self.respond(row)
        self.assertEqual(self.client.status(ID)['state_version'],1)
        self.respond(b'\xef\xbb\xbf'+json.dumps(metadata()).encode())
        self.assertEqual(self.client.status(ID),metadata())

    def test_known_rejections_unknown_unavailable_and_never_retry(self):
        codes={'invalid_request':400,'unauthorized':401,'forbidden':403,'not_found':404,'cancellation_conflict':409,'rate_limited':429,'unavailable':503}
        for code,status in codes.items():
            before=len(self.calls);self.respond(dict(code=code),status,{'Retry-After':'0'})
            with self.assertRaises(SealedLifecycleError) as caught:self.client.cancel(ID)
            error=caught.exception;self.assertEqual((error.code,error.status,error.attempts),(code,status,1))
            self.assertEqual(error.state,'unknown' if code=='unavailable' else 'refused');self.assertEqual(len(self.calls),before+1)

    def test_response_identity_state_bounds_and_page_fail_closed(self):
        invalid=[dict(metadata(),message_id='00000000-0000-0000-0000-000000000002'),dict(metadata(),plaintext='synthetic'),dict(metadata(),state='invented'),
            dict(metadata(),state_version=0),dict(metadata(),state_version=True),dict(metadata(),state_version=1.5),dict(metadata(),updated_at_ms=1<<53),
            dict(metadata(),created_at_ms=-1),dict(metadata(),expires_at_ms=10**1000),dict(metadata(),device_id='bad'),b'\xff',b'null',b'['*4000+b']'*4000,b'{"code":NaN}',b'\xef\xbb\xbf'*2+json.dumps(metadata()).encode()]
        for body in invalid:
            self.respond(body)
            with self.assertRaises(SealedLifecycleError) as caught:self.client.status(ID)
            self.assertEqual((caught.exception.code,caught.exception.state,caught.exception.attempts),('unexpected_response','unknown',1))
        self.respond(metadata())
        with self.assertRaises(SealedLifecycleError):self.client.cancel(ID)
        invalid_pages=[{},dict(messages=[metadata()]*21,next_cursor=None),dict(messages=[metadata()],next_cursor=ID),dict(messages=[metadata()]*20,next_cursor='bad'),
            dict(messages=[metadata()]*20,next_cursor='00000000-0000-0000-0000-000000000002'),dict(messages=[],next_cursor=None,extra=1),dict(messages={},next_cursor=None)]
        for page in invalid_pages:
            self.respond(page)
            with self.assertRaises(SealedLifecycleError):self.client.list()
        # Maintained wire contract does not require unique IDs or timestamp ordering.
        self.respond(dict(messages=[metadata()]*20,next_cursor=ID));self.assertEqual(len(self.client.list()['messages']),20)

    def test_redirect_framing_disconnect_deadline_refuse_without_resubmission(self):
        for status,body,headers in ((302,b'',{'Location':'/redirected'}),(307,b'',{'Location':'https://other.example.invalid/'}),
            (200,metadata(),{'extra-length':100}),(200,b'x'*16385,{}),(0,b'',{}),(503,{'code':'not_found'},{})):
            before=len(self.calls);self.respond(body,status,headers)
            with self.assertRaises(SealedLifecycleError) as caught:self.client.cancel(ID)
            self.assertEqual((caught.exception.state,caught.exception.attempts),('unknown',1));self.assertEqual(len(self.calls),before+1)
        before=len(self.calls);self.respond(metadata(),delay=0.3);started=time.monotonic()
        with self.assertRaises(SealedLifecycleError) as caught:SealedLifecycleClient(self.origin,'synthetic',timeout_ms=50).cancel(ID)
        self.assertEqual(caught.exception.code,'timeout');self.assertLess(time.monotonic()-started,0.25)
        # Observe all admitted handlers before counting: cancellation can race a
        # POST already dispatched, but must never resubmit or publish its result.
        self.server.shutdown();self.server.server_close()
        self.assertLessEqual(len(self.calls)-before,1)
        self.assertTrue(all(row[0]=='POST' for row in self.calls[before:]))

    def test_invalid_ca_refuses_on_fresh_server_and_oracle_detects_bypass(self):
        trusted=ssl.create_default_context()
        def refusal():
            with patch.dict(os.environ,{'SSL_CERT_FILE':str(Path(self.temp.name)/'missing.pem')}):
                with self.assertRaises(SealedLifecycleError):self.client.status(ID)
            self.assertEqual(self.calls,[])
        refusal()
        # Real TLS positive mutation: an explicitly supplied trusted context
        # bypasses the missing configuration, which the refusal oracle must catch.
        self.respond(metadata())
        with patch('ssl._create_default_https_context',return_value=trusted):
            with self.assertRaises(AssertionError):refusal()
        self.assertEqual([row[:2] for row in self.calls],[('GET','/v1/sealed/messages/'+ID)])


if __name__=='__main__':
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    output=io.StringIO();result=unittest.TextTestRunner(stream=output).run(unittest.defaultTestLoader.loadTestsFromTestCase(LifecycleTests))
    if not result.wasSuccessful():raise AssertionError(output.getvalue())
    print(json.dumps(dict(installed=True,real_tls_groups=result.testsRun)))
