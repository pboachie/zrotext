"""Actual synthetic TLS authoring acceptance against the maintained state machine."""
import argparse
import base64
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

spec=importlib.util.spec_from_file_location('cold',Path(__file__).with_name('test-owner-template.py'))
cold=importlib.util.module_from_spec(spec);spec.loader.exec_module(cold)
ORACLE='8982ee9e96be15801a424708afa603ef708a8a5b'
CONTENT='application/vnd.zrotext.workflow-context.v1'
DEFAULT_TEXT='Synthetic reviewed facts 🌱'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*_):pass
    def do_GET(self):self.reply()
    def do_POST(self):self.reply()
    def reply(self):
        s=self.server;index=len(s.calls)
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        s.calls.append((self.command,self.path,dict((k.lower(),v) for k,v in self.headers.items()),body))
        r=s.responses[index] if index<len(s.responses) else {}
        if r.get('network'):self.close_connection=True;return
        status=r.get('status',200)
        if self.command=='POST':
            if status==200:s.head=body;wire=b'{"revision":1}';ctype='application/json'
            else:wire=b'';ctype='application/json'
        else:
            wire=s.head if status==200 else b'';ctype=CONTENT
        self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(wire)));self.end_headers()
        self.wfile.write(wire);self.wfile.flush();self.close_connection=True


def main():
    p=argparse.ArgumentParser();p.add_argument('--producer',type=Path,required=True)
    group=p.add_mutually_exclusive_group(required=True);group.add_argument('--binary');group.add_argument('--command-file',type=Path)
    args=p.parse_args()
    assert subprocess.check_output(['git','-C',str(args.producer),'rev-parse','HEAD'],text=True).strip()==ORACLE
    assert not subprocess.check_output(['git','-C',str(args.producer),'status','--porcelain'],text=True).strip()
    fixture=json.loads(subprocess.check_output(['node',str(args.producer/'sdk/native/sealed-candidate/python/context-authoring-interop.mjs')],text=True,encoding='utf-8',timeout=60))
    argv=[args.binary] if args.binary else json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(argv,list) and argv and all(isinstance(v,str) and v and '\0' not in v for v in argv)
    envelope=[None]
    count=0
    with tempfile.TemporaryDirectory(prefix='zrotext-context-authoring-') as tmp:
        folder=Path(tmp);roots=cold.tls.certificates(folder)
        with cold.tls.Server((socket.gethostbyname('localhost'),0),Handler) as server:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(folder/'cert.pem',folder/'key.pem');server.socket=ctx.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            origin='https://'+server.server_address[0]+':'+str(server.server_address[1])
            env={k:v for k,v in os.environ.items() if not k.upper().endswith('_PROXY') and k.upper()!='NO_PROXY'};env['HTTPS_PROXY']='http://invalid.invalid:1'
            def run(ops,responses=None,**changes):
                nonlocal count
                server.calls=[];server.responses=list(responses or []);server.head=b''
                value=dict(Fixture=fixture,Origin=origin,Roots=roots,Cookie='synthetic-owner=opaque',CSRF='synthetic-csrf',Enabled=True,TimeoutMS=4000,ValidForMS=10000,Epoch=1,Revision=1,Ops=ops)
                value.update(changes)
                output=subprocess.run(argv,input=json.dumps(value),text=True,encoding='utf-8',capture_output=True,timeout=40,env=env)
                if output.returncode!=0:raise RuntimeError(f'probe failed ({output.returncode}): {output.stderr[-2000:]}')
                actual=json.loads(output.stdout);rows=actual['results']
                posts=[v for v in server.calls if v[0]=='POST'];gets=[v for v in server.calls if v[0]!='POST']
                if posts:envelope[0]=posts[0][3]
                for method,path,headers,body in server.calls:
                    assert headers['cookie']==value['Cookie'] and headers['x-zrotext-csrf']==value['CSRF'] and 'authorization' not in headers
                    if method=='POST':
                        assert path=='/v1/owner/workflow/contexts' and headers.get('idempotency-key') and headers['x-zrotext-context-revision']=='0'
                    else:assert path.startswith('/v1/owner/workflow/contexts/') and not body
                count+=1
                return rows,posts,gets,actual
            def snapshots(ops,responses=None,oracle=True,**changes):
                rows=[]
                for k in range(1,len(ops)+1):
                    prefix,posts,gets,_=run(ops[:k],responses,**changes)
                    row=dict(prefix[-1]);row['posts']=len(posts);row['gets']=len(gets)
                    row['exactRetry']=all(v[3]==posts[0][3] and v[2].get('idempotency-key')==posts[0][2].get('idempotency-key') for v in posts)
                    row['pending']=bool(row['pending']);row['source']=bool(row['source'])
                    rows.append({key:row[key] for key in ('phase','pending','source','posts','gets','exactRetry','reviews')})
                return rows
            try:
                corpus=[]
                def differential(ops,responses=None,**changes):
                    got=snapshots(ops,responses,**changes)
                    case=dict(ops=ops,responses=responses or [])
                    if changes.get('ReviewFail'):case['reviewReject']=True
                    if changes.get('Rotate'):case['rotate']=True
                    if 'Text' in changes:case['text']=changes['Text']
                    corpus.append((case,got));return got
                differential(['author','verify','retry','close'])
                differential(['author'],ReviewFail=True)
                differential(['author'],Rotate=True)
                for status in (400,401,403,404,409,413,429,503,302):
                    differential(['author','verify','retry'],[dict(status=status),{},{}])
                differential(['author','verify','retry'],[dict(network=True),{},{}])
                differential(['author','retry','retry','retry'],[dict(status=503)]*3)
                differential(['author','verify','verify','verify','verify'],[dict(network=True),{},{},{}])
                for text in ('','x'*32769,'☃'*12000,'\ud800','\ud83c\udf31','\ufefffacts','x\0y'):
                    differential(['author'],Text=text)
                maintained=json.loads(subprocess.check_output(['node',str(args.producer/'sdk/native/sealed-candidate/python/context-authoring-interop.mjs'),'--cases'],input=json.dumps(dict(fixture=fixture,cases=[case for case,_ in corpus])),text=True,encoding='utf-8',timeout=120))
                assert len(maintained)==len(corpus)
                for (case,got),want in zip(corpus,maintained):
                    assert len(got)==len(want),(case,got,want)
                    for a,b in zip(got,want):assert a==b,(case,a,b)
                rows,posts,gets,actual=run(['author-close-review'],ReviewBlock=True)
                assert rows[-1]['phase']=='closed' and rows[-1]['reviews']==1 and not posts and not gets,rows
                rows,posts,gets,actual=run(['author','retry'],[dict(status=503)],TimeoutMS=150,DelayMS=[0,400])
                assert rows[0]['phase']=='unknown' and rows[1]['phase']=='closed' and len(posts)==1 and not gets,(rows,posts,gets)
                rows,posts,gets,actual=run(['author'],DraftChange=True)
                assert rows[-1]['phase']=='closed' and rows[-1]['reviews']==1 and not posts,rows
                rows,posts,gets,actual=run(['author'],CurrentFailAt=1)
                assert rows[-1]['phase'] in ('closed','refused') and rows[-1]['reviews']==0 and not posts,rows
                rows,posts,gets,actual=run(['author'],SessionChangeAt=2)
                assert rows[-1]['phase'] in ('closed','refused') and not posts,rows
                rows,posts,gets,actual=run(['author'],Mode='owner-dead')
                assert rows[-1]['phase'] in ('closed','refused') and not posts,rows
                rows,posts,gets,actual=run(['author'])
                assert rows[-1]['phase']=='saved' and rows[-1]['source'] and len(posts)==1 and len(gets)==1,rows
            finally:server.shutdown()
    output=dict(envelope=base64.b64encode(envelope[0]).decode(),plaintext=base64.b64encode(DEFAULT_TEXT.encode()).decode())
    value=json.loads(subprocess.check_output(['node',str(args.producer/'sdk/native/sealed-candidate/python/context-authoring-interop.mjs'),'--consume'],input=json.dumps(dict(fixture=fixture,outputs=[output])),text=True,encoding='utf-8',timeout=60))
    assert value==dict(verified=True,opened=1),value
    print(f'{count} native context-authoring TLS controls passed; {len(corpus)} maintained state-machine differential controls passed; native ciphertext opens with the maintained context reader')


if __name__=='__main__':main()
