"""Pinned maintained cold owner-template differential plus actual synthetic TLS."""
import argparse
import base64
import copy
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

PIN = '26e876da9f34372d9cf26511993cf633971e0037'
CONTENT = 'application/vnd.zrotext.workflow-template.v1'
spec = importlib.util.spec_from_file_location('tls_fixture', Path(__file__).with_name('test-original-http.py'))
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *_):
        pass

    def do_GET(self):
        s = self.server
        index = len(s.calls)
        s.calls.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
        if s.mode == 'drop':
            self.close_connection = True
            return
        body = s.bodies[min(index, len(s.bodies)-1)]
        self.send_response(s.status)
        self.send_header('Content-Type', s.content)
        self.send_header('Set-Cookie', 'untrusted-response=ignored')
        if s.mode == 'redirect':
            self.send_header('Location', '/unexpected')
        self.send_header('Content-Length', str(len(body) + (10 if s.mode == 'truncated' else 0)))
        self.end_headers()
        if s.mode == 'trickle':
            for byte in body:
                self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(.03)
        else:
            self.wfile.write(body); self.wfile.flush()
        self.close_connection = True


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--producer', type=Path, required=True)
    p.add_argument('--deadline-case-ms', type=int, default=100,
                   help='Explicit caller budget for post-dispatch deadline cases; pre-dispatch remains 100ms')
    command = p.add_mutually_exclusive_group(required=True)
    command.add_argument('--binary')
    command.add_argument('--command-file', type=Path)
    args = p.parse_args()
    if not 100 <= args.deadline_case_ms <= 2000:
        p.error('--deadline-case-ms must be 100..2000')
    producer = args.producer.resolve(strict=True)
    assert subprocess.check_output(['git', '-C', str(producer), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(producer), 'status', '--porcelain'], text=True).strip()
    source = producer / 'sdk/native/sealed-candidate/python/owner-template-interop.mjs'
    fixture = json.loads(subprocess.check_output(['node', str(source)], text=True, encoding='utf-8', timeout=60))
    argv = [args.binary] if args.binary else json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(argv, list) and argv and all(isinstance(v, str) and v and '\0' not in v for v in argv)
    envelope = base64.b64decode(fixture['envelope'])
    differential = []
    count = 0
    with tempfile.TemporaryDirectory(prefix='zrotext-owner-template-tls-') as directory:
        folder = Path(directory); roots = tls.certificates(folder)
        with tls.Server((socket.gethostbyname('localhost'), 0), Handler) as server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(folder/'cert.pem', folder/'key.pem')
            server.socket = context.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                origin = 'https://' + server.server_address[0] + ':' + str(server.server_address[1])
                path = '/v1/owner/workflow/templates/' + str(uuid.UUID(bytes=base64.b64decode(fixture['scope']['templateId'])))

                def run(accepted=True, calls=1, *, mode='normal', body=None, status=200, content=CONTENT, bodies=None, expected=None, oracle=False, **changes):
                    nonlocal count
                    server.calls=[];server.mode=mode;server.status=status;server.content=content;server.bodies=bodies or [body if body is not None else envelope]
                    value=dict(Fixture=fixture,Origin=origin,Roots=roots,Cookie='synthetic-owner=opaque',CSRF='synthetic-csrf',Enabled=True,TimeoutMS=2000,ValidForMS=10000,Reads=1,Now=[10000],Mode='')
                    value.update(changes)
                    env={k:v for k,v in os.environ.items() if not k.upper().endswith('_PROXY') and k.upper()!='NO_PROXY'};env['HTTPS_PROXY']='http://invalid.invalid:1'
                    output=subprocess.run(argv,input=json.dumps(value),text=True,encoding='utf-8',capture_output=True,check=True,timeout=15,env=env)
                    actual=json.loads(output.stdout);wanted=expected or [accepted]
                    assert [r['accepted'] for r in actual['results']]==wanted,(count,mode,changes,actual,wanted)
                    assert len(server.calls)==calls,(count,mode,changes,len(server.calls),calls)
                    for i,r in enumerate(actual['results']):
                        if r['accepted']:
                            assert r['ack'] is False and r['pending'] is False
                            assert r['digest']==hashlib.sha256(server.bodies[min(i,len(server.bodies)-1)]).hexdigest()
                    for request_path,headers in server.calls:
                        assert request_path==path and headers['cookie']==value['Cookie'] and headers['x-zrotext-csrf']==value['CSRF']
                        assert headers['accept']==CONTENT and headers['cache-control']=='no-store'
                        assert 'authorization' not in headers and 'x-zrotext-output-authorization' not in headers
                    assert all(not value[k] or value[k] not in output.stdout+output.stderr for k in ['Cookie','CSRF'])
                    if mode=='trickle' or changes.get('CurrentSleepAt'):
                        assert actual['elapsed'] < value['TimeoutMS']/1000 + .6,actual
                    if changes.get('CurrentSleepAt'):
                        assert actual['currentCalls'] >= changes['CurrentSleepAt'],actual
                    if oracle:
                        item={'envelope':base64.b64encode(server.bodies[0]).decode(),'status':status,'contentType':content,'ownerLive':changes.get('Mode')!='owner-dead'}
                        differential.append((item,accepted,calls))
                    count+=1

                run(oracle=True)
                run(calls=2,Reads=2,expected=[True,True])
                for status in [400,401,403,404,409,429,503]:run(False,status=status,oracle=True)
                run(False,mode='redirect',status=307,oracle=True)
                for mode in ['drop','truncated','trickle']:run(False,mode=mode,TimeoutMS=max(150,args.deadline_case_ms) if mode=='trickle' else 2000)
                for content in ['application/json',CONTENT+'; charset=utf-8','']:run(False,content=content,oracle=True)
                for mode in ['owner-dead','consent-dead','inactive','binding']:run(False,0,Mode=mode,oracle=mode=='owner-dead')
                for at in [1,2,3]:run(False,0 if at==1 else 1,CurrentFailAt=at)
                for at in [2,3,4,5]:run(False,0 if at<4 else 1,SessionChangeAt=at)
                run(False,0,Enabled=False)
                for cookie in ['', 'missing-equals', 'x=y\r\nInjected: no']:run(False,0,Cookie=cookie)
                for csrf in ['', 'with space', 'x\n']:run(False,0,CSRF=csrf)
                run(False,0,SessionOrigin='https://different.example.invalid')
                run(False,0,Roots='')
                for origin_bad in [origin+'/',origin+'?x',origin+'#x',urlunsplit(urlsplit(origin)._replace(netloc='@'+urlsplit(origin).netloc)),origin+'/a/../']:
                    run(False,0,Origin=origin_bad)
                run(False,0,Now=[9999]);run(False,Now=[10001,10000]);run(False,Now=[20000])
                run(False,0,ValidForMS=0);run(False,0,ValidForMS=60001)
                for at in [1,2,3]:
                    budget=100 if at==1 else args.deadline_case_ms
                    sleep=max(400,budget+400) if at>1 else 400
                    run(False,0 if at==1 else 1,CurrentSleepAt=at,SleepMS=sleep,TimeoutMS=budget,SettleMS=sleep+50)
                run(False,0,CurrentSleepAt=1,SleepMS=400,TimeoutMS=100,SettleMS=450,Reads=2,expected=[False,False])
                for at in [0,5,6,22,38,54,70,86,94,102,110,118,126,158,190,222,287]:
                    changed=bytearray(envelope);changed[at]^=1;run(False,body=bytes(changed),oracle=True)
                point_bad=bytearray(envelope);point_bad[223:287]=bytes(64);run(False,body=bytes(point_bad),oracle=True)
                for bad in [b'',envelope[:-1],envelope+b'\0',bytes(33076)]:run(False,body=bad,oracle=True)
                # Cold loading returns opaque bytes; AEAD validity is checked only on
                # explicit opening. Same-revision contradiction remains forbidden.
                changed=bytearray(envelope);changed[-1]^=1
                run(body=bytes(changed),oracle=True)
                run(False,calls=2,bodies=[envelope,bytes(changed)],Reads=2,expected=[True,False])
                revision2=bytearray(envelope);revision2[94:102]=(2).to_bytes(8,'big')
                run(False,calls=2,bodies=[bytes(revision2),envelope],Reads=2,expected=[True,False])
                run(calls=2,bodies=[envelope,bytes(revision2)],Reads=2,expected=[True,True])
            finally:
                server.shutdown()
    oracle=json.loads(subprocess.check_output(['node',str(source),'--cases'],input=json.dumps({'fixture':fixture,'cases':[row[0] for row in differential]}),text=True,encoding='utf-8',timeout=90))
    for native,maintained in zip(differential,oracle):
        assert (maintained['accepted'],maintained['calls'])==(native[1],native[2]),(native,maintained)
    assert len(oracle)==len(differential)
    print(f'{count} native owner-template TLS controls passed; {len(oracle)} maintained differential controls passed; post-dispatch caller deadline={args.deadline_case_ms}ms; pre-dispatch=100ms')


if __name__=='__main__':main()
