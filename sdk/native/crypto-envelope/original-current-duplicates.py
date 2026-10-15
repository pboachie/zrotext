"""Reject duplicate proof names even when both copies contain valid signed data."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import uuid


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',type=Path,required=True)
    parser.add_argument('--producer',type=Path,required=True)
    parser.add_argument('--command-file',type=Path,required=True)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('tls_fixture',args.fixture/'sdk/native/hpke-candidate/test-original-http.py')
    tls=importlib.util.module_from_spec(spec);spec.loader.exec_module(tls)
    command=json.loads(args.command_file.read_text(encoding='utf-8'))
    if not isinstance(command,list) or not command or any(not isinstance(v,str) or not v or '\0' in v for v in command):
        raise ValueError('Invalid trusted command')
    fixture=json.loads(subprocess.check_output(['node',str(args.producer/'sdk/native/sealed-candidate/python/produce-selected-reply02.mjs')],text=True,encoding='utf-8'))
    b=lambda name:base64.b64decode(fixture[name],validate=True)
    proof={field:str(uuid.UUID(bytes=b(name))) for field,name in {'account_id':'account','interval_id':'interval',
        'device_id':'device','line_id':'line','connector_id':'connector','read_grant_id':'readGrant'}.items()}
    proof.update(reader_id=b('originalReader').hex(),root_generation=1,authority_revision=1,expires_at_ms=20000,observed_at_ms=10000,
        current_manifest_version=3,current_manifest_digest=hashlib.sha256(b('successor')[:-64]).hexdigest(),
        manifest_chain=[dict(version=2,accepted_at_ms=10000,manifest_b64=fixture['activation']),
                        dict(version=3,accepted_at_ms=10000,manifest_b64=fixture['successor'])])
    class Handler(tls.http.server.BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert self.path=='/v1/reply-events' and request==dict(v=1,method='current',accepted_manifest_version=2)
            self.server.calls+=1;self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(self.server.raw)));self.end_headers();self.wfile.write(self.server.raw)
    with tempfile.TemporaryDirectory(prefix='zrotext-current-duplicates-') as directory:
        folder=Path(directory);roots=tls.certificates(folder)
        with tls.Server(('localhost',0),Handler) as server:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(folder/'cert.pem',folder/'key.pem')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            try:
                for needle in ['"reader_id":', '"accepted_at_ms":']:
                    text=json.dumps(dict(kind='current',result=proof),separators=(',',':'))
                    duplicate=('"reader_id":'+json.dumps(proof['reader_id'])+',') if needle.startswith('"reader') else '"accepted_at_ms":10000,'
                    server.raw=text.replace(needle,duplicate+needle,1).encode();server.calls=0
                    grant='ztr_'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
                    payload=dict(Fixture=fixture,Origin=f'https://{server.server_address[0]}:{server.server_port}',Roots=roots,
                                 Grant=grant,Clock=[10000],Retry=False,Conflict=False)
                    result=subprocess.run(command,input=json.dumps(payload),text=True,encoding='utf-8',capture_output=True,check=True,timeout=10)
                    value=json.loads(result.stdout)
                    assert value==dict(ok=False,revision=1,floor=10000,history=2,rollback_refused=True) and server.calls==1
                    assert grant not in result.stdout and grant not in result.stderr
            finally:server.shutdown()
    print('2 valid-data duplicate proof/chain controls passed')


if __name__=='__main__':main()
