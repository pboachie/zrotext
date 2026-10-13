"""Run outside the checkout with -I against an installed candidate archive."""
import base64
from datetime import datetime,timedelta,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import zrotext_native_candidate as native
from zrotext_native_candidate.sealed_http import _prepared


def main():
    assert Path(native.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    request=json.load(sys.stdin);raw=base64.b64decode(request['envelope'],validate=True)
    digest=native.sealed_candidate.sha(raw[:-64])
    prepared=_prepared(native.Composition(raw,digest,native.sealed_candidate.sha(raw)))
    calls=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):self.exchange()
        def do_GET(self):self.exchange()
        def exchange(self):
            body=self.rfile.read(int(self.headers.get('Content-Length','0')))
            calls.append((self.command,self.path,body))
            if len(calls)==1:status,row=429,{'code':'rate_limited'}
            elif len(calls)==2:status,row=202,{'message_id':prepared.message_id,'created':True}
            else:status,row=200,dict(message_id=prepared.message_id,device_id=prepared.device_id,state='cancelled' if self.command=='POST' else 'queued',
                                    state_version=1,created_at_ms=10000,updated_at_ms=10000,expires_at_ms=20000)
            payload=json.dumps(row).encode();self.send_response(status)
            self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
    with tempfile.TemporaryDirectory() as directory:
        directory=Path(directory);key=ec.generate_private_key(ec.SECP256R1())
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(hours=1))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False)
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
        ca=directory/'ca.pem';private=directory/'key.pem';ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        os.environ['SSL_CERT_FILE']=str(ca)
        server=ThreadingHTTPServer(('localhost',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(ca,private)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            client=native.SealedHttpClient('https://localhost:'+str(server.server_port),'synthetic-fixture-credential',
                lambda binding:dict(binding,expires_ms=15000),clock=lambda:10000,max_delay_ms=0,max_attempts=3)
            assert client.submit(prepared)['created']
            assert client.reconcile(prepared)['state']=='queued'
            assert client.cancel(prepared)['state']=='cancelled'
            assert [entry[2] for entry in calls[:2]]==[raw,raw]
            assert [entry[0] for entry in calls]==['POST','POST','GET','POST']
        finally:server.shutdown();server.server_close()
    print(json.dumps(dict(installed=True,https_requests=len(calls),exact_ciphertext_replay=True)))


if __name__=='__main__':main()
