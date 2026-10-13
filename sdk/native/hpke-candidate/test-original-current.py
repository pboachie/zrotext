"""Pinned signed manifests over synthetic TLS, with durable current-proof fences."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import uuid

PIN = '72124e1a3ff28e782f870eeddbdc33cacf8ca3b4'
spec = importlib.util.spec_from_file_location('reply_tls', Path(__file__).with_name('test-original-http.py'))
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)


class Handler(tls.http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        s = self.server
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert self.path == '/v1/reply-events'
        assert request == {'v':1, 'method':'current', 'accepted_manifest_version':2}
        assert self.headers['Authorization'] == 'Bearer '+s.grant
        s.calls += 1
        body = json.dumps({'kind':'current','result':s.proof}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)


def main():
    p = argparse.ArgumentParser(); p.add_argument('--binary',required=True); p.add_argument('--producer',required=True)
    args = p.parse_args(); producer = Path(args.producer).resolve(strict=True)
    def git(*words): return subprocess.check_output(['git','-C',str(producer),*words],text=True).strip()
    assert git('rev-parse','HEAD') == PIN and not git('status','--porcelain'), 'exact clean reviewed producer required'
    f = json.loads(subprocess.check_output(['node',str(producer/'sdk/native/sealed-candidate/python/produce-selected-reply02.mjs')],text=True,encoding='utf-8'))
    binary = str(Path(args.binary).resolve(strict=True))
    decode = lambda name: base64.b64decode(f[name],validate=True)
    proof = {field:str(uuid.UUID(bytes=decode(name))) for field,name in {
        'account_id':'account','interval_id':'interval','device_id':'device','line_id':'line',
        'connector_id':'connector','read_grant_id':'readGrant'}.items()}
    proof.update(reader_id=decode('originalReader').hex(),root_generation=1,authority_revision=1,
        expires_at_ms=20000,observed_at_ms=10000,current_manifest_version=3,
        current_manifest_digest=hashlib.sha256(decode('successor')[:-64]).hexdigest(),
        manifest_chain=[{'version':2,'accepted_at_ms':10000,'manifest_b64':f['activation']},
                        {'version':3,'accepted_at_ms':10000,'manifest_b64':f['successor']}])
    count = 0
    with tempfile.TemporaryDirectory(prefix='zrotext-current-tls-') as directory:
        folder=Path(directory); roots=tls.certificates(folder)
        with tls.Server(('localhost',0),Handler) as server:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(folder/'cert.pem',folder/'key.pem')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            server.grant='ztr_'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            def run(name,mutate=lambda _:None,ok=False,clock=(10000,),revision=1,floor=10000,history=2,retry=False,conflict=False):
                nonlocal count
                server.proof=copy.deepcopy(proof);mutate(server.proof);server.calls=0
                payload=dict(Fixture=f,Origin=f'https://{server.server_address[0]}:{server.server_port}',
                    Roots=roots,Grant=server.grant,Clock=clock,Retry=retry,Conflict=conflict)
                result=subprocess.run([binary],input=json.dumps(payload),text=True,encoding='utf-8',capture_output=True,check=True,timeout=10)
                actual=json.loads(result.stdout)
                assert actual['ok']==ok and actual['revision']==revision and actual['floor']==floor and actual['history']==history and actual['rollback_refused'],(name,actual)
                assert server.calls==1,(name,server.calls)
                if ok: assert actual['now']==floor and actual['version']==3,(name,actual)
                if retry: assert actual['stale_refused'],(name,actual)
                count+=1
            run('signed current advances',ok=True,revision=2,history=3)
            run('postcommit newer local clock persists',ok=True,clock=(10000,10000,11000,11000,12000,12000),revision=3,floor=12000,history=3)
            run('server future acceptance at allowed boundary',lambda p:p['manifest_chain'][1].update(accepted_at_ms=40000),ok=True,revision=2,history=3)
            run('server acceptance is not local comparison',lambda p:p['manifest_chain'][0].update(accepted_at_ms=9999),ok=True,revision=2,history=3)
            run('server acceptance beyond boundary',lambda p:p['manifest_chain'][1].update(accepted_at_ms=40001))
            run('local clock rollback',clock=(10000,9999))
            run('locked deadline',clock=(10000,10000,10000,20000),retry=True)
            run('postcommit deadline',clock=(10000,10000,10000,10000,20000),revision=2,history=3,retry=True)
            run('concurrent writer wins CAS',clock=(10000,10000,10000),conflict=True,revision=2,retry=True)
            for field in ('account_id','interval_id','device_id','line_id','connector_id','read_grant_id'):
                run('wrong '+field,lambda p,key=field:p.update({key:str(uuid.UUID(int=1))}))
            for field,value in [('reader_id','00'*32),('root_generation',2),('authority_revision',2),
                                ('expires_at_ms',10000),('observed_at_ms',40001),('current_manifest_version',2),
                                ('current_manifest_digest','00'*32),('extra',0)]:
                run('wrong '+field,lambda p,key=field,v=value:p.update({key:v}))
            for field in tuple(proof):
                run('missing '+field,lambda p,key=field:p.pop(key))
            run('chain empty',lambda p:p.update(manifest_chain=[]))
            run('chain oversized',lambda p:p.update(manifest_chain=p['manifest_chain']*17))
            run('chain reversed',lambda p:p['manifest_chain'].reverse())
            run('chain gap',lambda p:p['manifest_chain'][1].update(version=4))
            run('chain zero acceptance',lambda p:p['manifest_chain'][1].update(accepted_at_ms=0))
            run('chain extra field',lambda p:p['manifest_chain'][1].update(extra=True))
            run('same version fork',lambda p:p['manifest_chain'][0].update(manifest_b64=f['successor']))
            for at in (5,151,-1):
                def corrupt(p,at=at):
                    raw=bytearray(decode('successor'));raw[at]^=1
                    p['manifest_chain'][1]['manifest_b64']=base64.b64encode(raw).decode()
                    p['current_manifest_digest']=hashlib.sha256(raw[:-64]).hexdigest()
                run('signed bytes tampered '+str(at),corrupt)
            server.shutdown()
    print(f'{count} authenticated TLS current/checkpoint controls passed')


if __name__=='__main__':main()
