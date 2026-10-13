"""Source and isolated installed owner-session HTTPS controls."""
import base64
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate.owner_template import OwnerTemplateReader,OwnerTemplateError

def dec(value):return base64.b64decode(value,validate=True)

def materials(f):
    manifest=s.verify_manifest02(dec(f['manifest']),s.enroll_root02(dec(f['rootPin']),dec(f['fingerprint'])),f['now'])
    binding={k:v if k in ('generation','peer') else dec(v) for k,v in f['binding'].items()}
    return manifest,binding

class OwnerTemplateTests(unittest.TestCase):
    fixture=None
    def setUp(self):
        # Reuse only synthetic TLS certificate setup; no metadata tests are inherited.
        import importlib.util
        spec=importlib.util.spec_from_file_location('owner_tls_fixture',Path(__file__).with_name('installed_lifecycle_consumer.py'))
        fixture_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture_module)
        LifecycleTests=fixture_module.LifecycleTests
        LifecycleTests.setUp(self)
        self.server.shutdown();self.server.server_close()
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):self.handle_request()
            def do_POST(self):self.handle_request()
            def handle_request(self):
                owner.calls.append((self.command,self.path,dict(self.headers),self.rfile.read(int(self.headers.get('Content-Length','0')))))
                status,body,headers,delay=owner.responses.pop(0);time.sleep(delay)
                if status==0:self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                try:
                    self.send_response(status);self.send_header('Content-Type',headers.get('Content-Type','application/vnd.zrotext.workflow-template.v1'))
                    self.send_header('Content-Length',str(len(body)+headers.get('extra-length',0)))
                    for key,value in headers.items():
                        if key not in ('Content-Type','extra-length'):self.send_header(key,value)
                    self.end_headers();self.wfile.write(body)
                except (OSError,ssl.SSLError):pass
        self.server=ThreadingHTTPServer(('localhost',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        folder=Path(self.temp.name);context.load_cert_chain(folder/'ca.pem',folder/'key.pem');self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        threading.Thread(target=self.server.serve_forever,daemon=True).start();self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        self.origin='https://'+socket.gethostbyname('localhost')+':'+str(self.server.server_port)
        self.manifest,self.binding=materials(self.fixture);self.cookie='synthetic-owner=session';self.csrf='synthetic-csrf';self.live=True;self.current_calls=0
        self.client=self.make();self.addCleanup(self.client.close)
    def current(self):
        self.current_calls+=1
        return dict(binding=self.binding,manifest=self.manifest,nowMs=self.fixture['now'],ownerSessionLive=self.live,consentLive=True,phase='active',validForMs=10000)
    def session(self):return dict(origin=self.origin,cookie=self.cookie,csrf=self.csrf)
    def make(self,**changes):
        options=dict(read_current=self.current,current_session=self.session,enabled=True);options.update(changes)
        return OwnerTemplateReader(self.origin,self.binding,dec(self.fixture['scope']['templateId']),**options)
    def respond(self,body=None,status=200,headers=None,delay=0):self.responses.append((status,dec(self.fixture['envelope']) if body is None else body,headers or {},delay))
    def test_real_tls_exact_origin_session_and_no_ambient_credentials(self):
        self.respond(headers={'Set-Cookie':'synthetic-owner=ignored'})
        with patch.dict(os.environ,{'HTTPS_PROXY':'http://synthetic-proxy.example.invalid'}):value=self.client.read_latest()
        self.assertFalse(value['requestAcknowledged']);self.assertFalse(value['matchesPending']);self.assertEqual(value['envelope'],dec(self.fixture['envelope']))
        self.assertEqual(self.current_calls,3);self.respond();self.client.read_latest()
        for method,path,headers,body in self.calls:
            self.assertEqual(method,'GET');self.assertTrue(path.startswith('/v1/owner/workflow/templates/'));self.assertEqual(body,b'')
            self.assertEqual(headers['Cookie'],self.cookie);self.assertEqual(headers['x-zrotext-csrf'],self.csrf);self.assertNotIn('Authorization',headers)
        self.assertNotIn(self.cookie,repr(self.client))
    def test_changed_authority_and_session_refuse_before_dispatch_and_after_response(self):
        self.live=False
        with self.assertRaises(OwnerTemplateError) as caught:self.client.read_latest()
        self.assertEqual(caught.exception.code,'owner_changed');self.assertEqual(self.calls,[])
        self.live=True;self.client=self.make(current_session=lambda:dict(self.session(),origin='https://other.example.invalid'))
        with self.assertRaises(OwnerTemplateError):self.client.read_latest()
        self.assertEqual(self.calls,[])
        self.client=self.make();original=self.current
        def changed():
            if self.current_calls>=2:self.live=False
            return original()
        self.client=self.make(read_current=changed);self.respond()
        with self.assertRaises(OwnerTemplateError):self.client.read_latest()
        self.assertEqual(len(self.calls),1)
    def test_redirect_network_truncation_and_bounded_deadline_no_retry(self):
        for status,headers,body in ((302,{'Location':'/elsewhere'},b''),(0,{},b''),(200,{'extra-length':1},dec(self.fixture['envelope']))):
            self.client=self.make();before=len(self.calls);self.respond(body,status,headers)
            with self.assertRaises(OwnerTemplateError):self.client.read_latest()
            self.assertEqual(len(self.calls),before+1)
        self.client=self.make(timeout_ms=80);self.respond(delay=.25);start=time.monotonic()
        with self.assertRaises(OwnerTemplateError):self.client.read_latest()
        self.assertLess(time.monotonic()-start,.5)
    def test_cancellation_and_busy_callback_admission_never_publish_late(self):
        entered=threading.Event();release=threading.Event()
        def current():entered.set();release.wait(2);return self.current()
        self.client=self.make(read_current=current);errors=[]
        def call():
            try:self.client.read_latest()
            except OwnerTemplateError as error:errors.append(error.code)
        worker=threading.Thread(target=call);worker.start();self.assertTrue(entered.wait(1))
        with self.assertRaises(OwnerTemplateError) as caught:self.client.read_latest()
        self.assertEqual(caught.exception.code,'busy');self.client.close();worker.join(1);release.set()
        self.assertFalse(worker.is_alive());self.assertEqual(errors,['closed']);self.assertEqual(self.calls,[])


    def test_head_equivocation_clock_rollback_and_callback_deadline(self):
        self.respond();self.client.read_latest()
        changed=bytearray(dec(self.fixture['envelope']));changed[-1]^=1;self.respond(bytes(changed))
        with self.assertRaises(OwnerTemplateError) as caught:self.client.read_latest()
        self.assertEqual(caught.exception.code,'head_changed')
        original=self.current
        def earlier():return dict(original(),nowMs=self.fixture['now']-1)
        self.client._current=earlier
        before=len(self.calls)
        with self.assertRaises(OwnerTemplateError) as caught:self.client.read_latest()
        self.assertEqual(caught.exception.code,'owner_changed');self.assertEqual(len(self.calls),before)
        release=threading.Event();count=0
        def session():
            nonlocal count
            count+=1
            if count==2:release.wait(1)
            return self.session()
        self.client=self.make(read_current=lambda:dict(original(),validForMs=60),current_session=session)
        start=time.monotonic()
        try:
            with self.assertRaises(OwnerTemplateError):self.client.read_latest()
            self.assertLess(time.monotonic()-start,.3);self.assertEqual(len(self.calls),before)
        finally:release.set()

if __name__=='__main__':
    import sys
    import zrotext_native_candidate as n
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    OwnerTemplateTests.fixture=json.load(sys.stdin)
    result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.loadTestsFromTestCase(OwnerTemplateTests))
    if not result.wasSuccessful():raise SystemExit(1)
    print(json.dumps(dict(installed=True,owner_template_tls=result.testsRun)))
