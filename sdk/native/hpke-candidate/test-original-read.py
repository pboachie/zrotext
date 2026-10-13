"""Genuine signed ciphertext over synthetic TLS, including final proof refusal."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
import queue
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
        assert self.headers['Authorization'] == 'Bearer '+s.grant
        expected = s.requests[s.calls]
        assert request == expected,(request,expected)
        s.calls += 1
        if s.fail_final and s.calls==2:
            self.send_response(403);self.send_header('Content-Length','0');self.end_headers();return
        result=s.read if request['method']=='read' else s.final
        body=json.dumps({'kind':request['method'],'result':result}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)



def read_public(child):
    lines=queue.Queue()
    threading.Thread(target=lambda:lines.put(child.stdout.readline()),daemon=True).start()
    return json.loads(lines.get(timeout=30))['public']


def finish_owned(child):
    if child is None or child.poll() is not None:return
    if child.stdin is not None:
        if not child.stdin.closed:child.stdin.close()
        child.stdin=None
    try:
        stdout,_=child.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        child.terminate()
        child.wait(timeout=5)
        raise RuntimeError('Owned child unresponsive; private receipt retained') from None
    rows=[json.loads(line) for line in stdout.splitlines()]
    assert rows and rows[-1]=={'owned_key_deleted':True},'Owned child did not confirm cleanup'


def make_read(f):
    decode = lambda name: base64.b64decode(f[name],validate=True)
    proof = {field:str(uuid.UUID(bytes=decode(name))) for field,name in {
        'account_id':'account','interval_id':'interval','device_id':'device','line_id':'line',
        'connector_id':'connector','read_grant_id':'readGrant'}.items()}
    proof.update(reader_id=decode('originalReader').hex(),root_generation=1,authority_revision=1,
        expires_at_ms=20000,observed_at_ms=10000,current_manifest_version=3,
        current_manifest_digest=hashlib.sha256(decode('successor')[:-64]).hexdigest(),
        manifest_chain=[{'version':2,'accepted_at_ms':10000,'manifest_b64':f['activation']},
                        {'version':3,'accepted_at_ms':10000,'manifest_b64':f['successor']}])
    proof['manifest_chain'].insert(0,{'version':1,'accepted_at_ms':10000,'manifest_b64':f['predecessor']})
    final=copy.deepcopy(proof);final['manifest_chain']=final['manifest_chain'][-1:]
    event=str(uuid.UUID(bytes=decode('event')))
    read=dict(event_id=event,accepted_at_ms=10000,envelope_b64=f['inbound'],historical_manifest_version=2,
        statement_b64=f['selection'],approval_signature_b64=f['approval'],installation_signature_b64=f['installation'],activation_manifest_version=2,proof=proof)
    return read,final,event


def main():
    p = argparse.ArgumentParser(); p.add_argument('--producer',required=True);p.add_argument('--hardware',action='store_true')
    command = p.add_mutually_exclusive_group(required=True)
    command.add_argument('--binary')
    command.add_argument('--command-file',help='Trusted local JSON argv, never server data')
    args = p.parse_args(); producer = Path(args.producer).resolve(strict=True)
    def git(*words): return subprocess.check_output(['git','-C',str(producer),*words],text=True).strip()
    assert git('rev-parse','HEAD') == PIN and not git('status','--porcelain'), 'exact clean reviewed producer required'
    f = json.loads(subprocess.check_output(['node',str(producer/'sdk/native/sealed-candidate/python/produce-selected-reply02.mjs')],text=True,encoding='utf-8'))
    if args.binary:
        argv = [str(Path(args.binary).resolve(strict=True))]
    else:
        argv = json.loads(Path(args.command_file).read_text(encoding='utf-8'))
        if not isinstance(argv,list) or not argv or any(not isinstance(v,str) or not v or '\0' in v for v in argv):
            p.error('command file must contain nonempty string arguments without NUL')
    read,final,event=make_read(f)
    decode=lambda name:base64.b64decode(f[name],validate=True)
    count=0
    with tempfile.TemporaryDirectory(prefix='zrotext-read-tls-') as directory:
        folder=Path(directory);roots=tls.certificates(folder)
        with tls.Server(('localhost',0),Handler) as server:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(folder/'cert.pem',folder/'key.pem')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            server.grant='ztr_'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            def run(name,mutate=lambda r,p:None,ok=False,calls=1,baseline=0,fail_final=False):
                nonlocal count,f,read,final,event
                hardware=None
                if args.hardware and name not in ("signed ciphertext and final fresh proof","final revoked service authority","authenticated envelope_b64 corruption"):return
                try:
                    if args.hardware:
                        hardware=subprocess.Popen([*argv,"--hardware"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8")
                        point=read_public(hardware)
                        f=json.loads(subprocess.check_output(["node",str(producer/"sdk/native/sealed-candidate/python/produce-selected-reply02.mjs"),"--reader-point",point],text=True,encoding="utf-8",timeout=20))
                        assert "originalScalar" not in f
                        read,final,event=make_read(f)
                    server.read=copy.deepcopy(read);server.final=copy.deepcopy(final);server.calls=0;server.fail_final=fail_final
                    if baseline==2:server.read['proof']['manifest_chain']=server.read['proof']['manifest_chain'][1:]
                    mutate(server.read,server.final)
                    server.requests=[{'v':1,'method':'read','event_id':event,'accepted_manifest_version':baseline or 1},
                        {'v':1,'method':'current','accepted_manifest_version':3}]
                    payload=dict(Fixture=f,Origin=f'https://{server.server_address[0]}:{server.server_port}',Roots=roots,Grant=server.grant,Clock=[10000],Baseline=baseline)
                    if hardware:
                        stdout,stderr=hardware.communicate(json.dumps(payload),timeout=30)
                        assert hardware.returncode==0,(name,stderr)
                        rows=[json.loads(line) for line in stdout.splitlines()]
                        assert rows[-1]=={'owned_key_deleted':True},(name,rows)
                        actual=rows[0]
                    else:
                        result=subprocess.run(argv,input=json.dumps(payload),text=True,encoding='utf-8',capture_output=True,check=True,timeout=10)
                        actual=json.loads(result.stdout)
                    assert actual['ok']==ok and server.calls==calls,(name,actual,server.calls)
                    assert actual['rollback_refused'],(name,actual)
                    if ok:
                        assert actual['plaintext']==f['text'] and actual['digest']==hashlib.sha256(decode('inbound')).hexdigest(),(name,actual)
                        assert actual['baseline']==(baseline or 1) and actual['version']==3 and actual['revision']==3,(name,actual)
                    else:assert 'plaintext' not in actual,(name,actual)
                    count+=1
                finally:
                    finish_owned(hardware)
            run('signed ciphertext and final fresh proof',ok=True,calls=2)
            run('explicit retained baseline',ok=True,calls=2,baseline=2)
            run('unknown baseline no network',baseline=4,calls=0)
            run('activation acceptance precedes local comparison',lambda r,p:r.update(accepted_at_ms=9999),ok=True,calls=2)
            run('final revoked service authority',calls=2,fail_final=True)
            run('final wrong scope',lambda r,p:p.update(reader_id='00'*32),calls=2)
            run('final expires',lambda r,p:p.update(expires_at_ms=10000),calls=2)
            run('final manifest rollback',lambda r,p:p.update(current_manifest_version=2),calls=2)
            run('wrong event',lambda r,p:r.update(event_id=str(uuid.UUID(int=1))))
            for key in tuple(read):run('missing '+key,lambda r,p,key=key:r.pop(key))
            run('unknown field',lambda r,p:r.update(extra=True))
            for key,value in [('historical_manifest_version',4),('activation_manifest_version',4),('accepted_at_ms',0),('accepted_at_ms',40001)]:
                run('invalid '+key,lambda r,p,key=key,value=value:r.update({key:value}))
            for key in ('envelope_b64','statement_b64','approval_signature_b64','installation_signature_b64'):
                def corrupt(r,p,key=key):
                    raw=bytearray(base64.b64decode(r[key]));raw[-1]^=1;r[key]=base64.b64encode(raw).decode()
                run('authenticated '+key+' corruption',corrupt)
                run('noncanonical '+key,lambda r,p,key=key:r.update({key:r[key]+'='}))
            run('cached baseline fork',lambda r,p:r['proof']['manifest_chain'][0].update(manifest_b64=f['activation']))
            run('cached middle fork',lambda r,p:r['proof']['manifest_chain'][1].update(manifest_b64=f['successor']))
            if args.hardware:
                child=subprocess.Popen([*argv,'--hardware'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
                try:
                    read_public(child)
                    try:raise RuntimeError('synthetic fixture producer failure')
                    except RuntimeError:pass
                finally:finish_owned(child)
                count+=1
            server.shutdown()
    print(f'{count} authenticated TLS read/final-proof controls passed')

if __name__=='__main__':main()
