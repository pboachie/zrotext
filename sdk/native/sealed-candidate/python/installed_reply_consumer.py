"""Isolated installed native/workflow packages against synthetic original TLS."""
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
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import zrotext_native_candidate as native
from zrotext_native_candidate import sealed_candidate as s
try:import zrotext_workflow
except ModuleNotFoundError:zrotext_workflow=None


def main():
    missing='--without-workflow' in sys.argv
    assert (zrotext_workflow is None)==missing
    for module in (native,zrotext_workflow):
        if module is not None:assert Path(module.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    f=json.load(sys.stdin);decode=lambda x:base64.b64decode(x,validate=True);uid=lambda b:str(uuid.UUID(bytes=b))
    scope={k:decode(f[k]) for k in ('account','device','line','interval','connector')}
    scope.update(read_grant=decode(f['readGrant']),reader=decode(f['originalReader']),peer='+12')
    root=s.enroll_root02(decode(f['rootPin']),decode(f['fingerprint']))
    old=s.verify_manifest02(decode(f['predecessor']),root,10000)
    active=s.verify_manifest02(decode(f['activation']),s.advance_trust02(root,old),10000)
    custody=native.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(f['originalScalar']),'big'),ec.SECP256R1()))
    event=uid(decode(f['event']));consumptions={};calls=[]
    def proof(baseline):
        identities={name:uid(scope[key]) for name,key in (('account_id','account'),('device_id','device'),('line_id','line'),('interval_id','interval'),('connector_id','connector'),('read_grant_id','read_grant'))}
        chain=[dict(version=v,accepted_at_ms=10000,manifest_b64=f[key]) for v,key in ((1,'predecessor'),(2,'activation')) if v>=baseline]
        return dict(identities,reader_id=scope['reader'].hex(),root_generation=1,authority_revision=1,expires_at_ms=20000,observed_at_ms=10000,
                    current_manifest_version=2,current_manifest_digest=s.sha(decode(f['activation'])[:-64]).hex(),manifest_chain=chain)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            request=json.loads(self.rfile.read(int(self.headers['Content-Length'])));method=request['method'];calls.append(method)
            assert self.path=='/v1/reply-events' and self.headers['Authorization'].startswith('Bearer ztr_')
            if method=='current':row=proof(request['accepted_manifest_version'])
            elif method=='read':row=dict(event_id=event,accepted_at_ms=10000,envelope_b64=f['inbound'],historical_manifest_version=2,
                statement_b64=f['selection'],approval_signature_b64=f['approval'],installation_signature_b64=f['installation'],activation_manifest_version=2,proof=proof(request['accepted_manifest_version']))
            elif method=='page':row=dict(events=[dict(event_id=event,accepted_at_ms=10000,observed_at_ms=10000,historical_manifest_version=2,
                activation_manifest_version=2,disposition='owner_review',active_request_ids=[])],next=None,proof=proof(request['accepted_manifest_version']))
            elif method=='consume':
                p=request['params'];descriptor=p['descriptor'];action=None
                if descriptor:
                    assert zrotext_workflow is not None
                    assert self.headers['x-zrotext-output-authorization'].startswith('Bearer ztw_')
                    action={k:descriptor[k] for k in ('account_id','action_id','revision')};action['binding_digest']=zrotext_workflow.action_digest(descriptor)
                else:assert self.headers.get('x-zrotext-output-authorization') is None
                row=dict(event_id=p['event_id'],consumption_id=p['request_id'],disposition='proposal' if descriptor else 'owner_review',active_request_id=p['active_request_id'],action=action)
                consumptions[p['request_id']]=row
            else:assert method=='status';row=consumptions[request['consumption_id']]
            body=json.dumps(dict(kind=method,result=row)).encode();self.send_response(200)
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    with tempfile.TemporaryDirectory() as directory:
        directory=Path(directory);key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False)
            .add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
        ca=directory/'ca.pem';private=directory/'key.pem';ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        os.environ['SSL_CERT_FILE']=str(ca);server=ThreadingHTTPServer(('localhost',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(ca,private);server.socket=context.wrap_socket(server.socket,server_side=True)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            credential=lambda prefix:prefix+base64.urlsafe_b64encode(bytes([88])*32).decode().rstrip('=')
            client=native.OriginalReplyClient('https://localhost:'+str(server.server_port),credential('ztr_'),scope=scope,custody=custody,
                accepted_history=[old,active],clock=lambda:10000,output_credential=lambda:credential('ztw_'),require_protected=False)
            assert client.read(decode(f['event']))==f['text'];assert client.page()['events'][0]['event_id']==event
            request=dict(request_id=str(uuid.UUID(int=100)),event_id=event,active_request_id=None,descriptor=None)
            assert client.consume(request)['disposition']=='owner_review'
            descriptor=dict(account_id=uid(scope['account']),action_id=str(uuid.UUID(int=101)),revision=1,line_id=uid(scope['line']),
                recipient_id=str(uuid.UUID(int=102)),purpose_id=str(uuid.UUID(int=103)),content_ref=str(uuid.UUID(int=104)),content_digest='ab'*32,content_version=1,
                not_before=10,expires_at=100,timezone='UTC',window_id='window-a',routine_id=str(uuid.UUID(int=105)),authority_generation=1,commitment='informational')
            request.update(request_id=str(uuid.UUID(int=106)),active_request_id=str(uuid.UUID(int=107)),descriptor=descriptor)
            if missing:
                try:client.consume(request)
                except native.OriginalReplyError as error:assert error.state=='unavailable'
                else:raise AssertionError('proposal without workflow extra')
                assert calls==['read','current','page','consume']
            else:
                result=client.consume(request);assert result['disposition']=='proposal' and client.status(request['request_id'])==result
                assert calls==['read','current','page','consume','consume','status']
        finally:server.shutdown();server.server_close()
    print(json.dumps(dict(installed=True,workflow_coinstalled=not missing,original_reply_https=True)))


if __name__=='__main__':main()
