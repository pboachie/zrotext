"""Actual synthetic TLS and maintained workflow-context recovery comparison."""
import argparse
import base64
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

spec=importlib.util.spec_from_file_location('cold',Path(__file__).with_name('test-owner-template.py'))
cold=importlib.util.module_from_spec(spec);spec.loader.exec_module(cold)
ORACLE='8982ee9e96be15801a424708afa603ef708a8a5b'
cold.CONTENT='application/vnd.zrotext.workflow-context.v1'
REQUEST='00000000-0000-0000-0000-000000000041'

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
        wire=base64.b64decode(s.newer if r.get('newer') else r.get('envelope',s.envelope)) if self.command=='GET' else r.get('body','{"revision":1}').encode()
        self.send_response(r.get('status',200));self.send_header('Content-Type',r.get('contentType',cold.CONTENT if self.command=='GET' else 'application/json'))
        if r.get('status')==307:self.send_header('Location','/unexpected')
        self.send_header('Content-Length',str(len(wire)+(10 if r.get('truncated') else 0)));self.end_headers()
        if r.get('trickle'):
            for b in wire:self.wfile.write(bytes([b]));self.wfile.flush();time.sleep(max(.06,s.deadline_ms/1000+.4))
        else:self.wfile.write(wire);self.wfile.flush()
        self.close_connection=True

def main():
    p=argparse.ArgumentParser();p.add_argument('--producer',type=Path,required=True)
    group=p.add_mutually_exclusive_group(required=True);group.add_argument('--binary');group.add_argument('--command-file',type=Path)
    p.add_argument('--deadline-case-ms',type=int,default=200)
    args=p.parse_args()
    if not 100<=args.deadline_case_ms<=2000:p.error('--deadline-case-ms must be100..2000')
    for folder,pin in [(args.producer,ORACLE)]:
        assert subprocess.check_output(['git','-C',str(folder),'rev-parse','HEAD'],text=True).strip()==pin
        assert not subprocess.check_output(['git','-C',str(folder),'status','--porcelain'],text=True).strip()
    fixture=json.loads(subprocess.check_output(['node',str(args.producer/'sdk/native/sealed-candidate/python/owner-context-interop.mjs')],text=True,encoding='utf-8',timeout=60))
    argv=[args.binary] if args.binary else json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(argv,list) and argv and all(isinstance(v,str) and v and '\0' not in v for v in argv)
    envelope=base64.b64decode(fixture['envelope']);digest=hashlib.sha256(envelope).hexdigest();corpus=[];count=0
    with tempfile.TemporaryDirectory(prefix='zrotext-template-save-') as tmp:
        folder=Path(tmp);roots=cold.tls.certificates(folder)
        with cold.tls.Server((socket.gethostbyname('localhost'),0),Handler) as server:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(folder/'cert.pem',folder/'key.pem');server.socket=ctx.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            origin='https://'+server.server_address[0]+':'+str(server.server_address[1])
            def run(ops,expected,calls,responses=None,oracle=True,**changes):
                nonlocal count
                server.calls=[];server.responses=responses or [{}];server.envelope=fixture['envelope'];server.newer=fixture['newer']
                value=dict(Fixture=fixture,Origin=origin,Roots=roots,Cookie='synthetic-owner=opaque',CSRF='synthetic-csrf',Enabled=True,TimeoutMS=4000,ValidForMS=10000,Now=[10000],Mode='',Ops=ops,RequestID=REQUEST,Expected=0)
                value.update(changes);server.deadline_ms=value["TimeoutMS"];env={k:v for k,v in os.environ.items() if not k.upper().endswith('_PROXY') and k.upper()!='NO_PROXY'};env['HTTPS_PROXY']='http://invalid.invalid:1'
                output=subprocess.run(argv,input=json.dumps(value),text=True,encoding='utf-8',capture_output=True,check=True,timeout=20,env=env)
                actual=json.loads(output.stdout);rows=actual['results'];assert [r['accepted'] for r in rows]==expected,(count,ops,changes,actual,expected)
                assert len(server.calls)==calls,(count,ops,len(server.calls),calls,actual)
                for method,path,headers,body in server.calls:
                    assert headers['cookie']==value['Cookie'] and headers['x-zrotext-csrf']==value['CSRF'] and 'authorization' not in headers
                    if method=='POST':
                        assert path=='/v1/owner/workflow/contexts' and headers['idempotency-key']==REQUEST and headers['x-zrotext-context-revision']=='0' and body==envelope
                    else:assert path.startswith('/v1/owner/workflow/contexts/') and not body
                for row in rows:
                    if row.get('ack'):assert row['accepted'] and not row['pending'] and row['digest']==digest
                    if row.get('pending'):assert row['pendingID']==REQUEST and row['pendingDigest']==digest
                actual['trace']=[dict(method=m,path=p,body=base64.b64encode(b).decode() if m=='POST' else None,requestId=h.get('idempotency-key'),revision=h.get('x-zrotext-context-revision')) for m,p,h,b in server.calls]
                if oracle:corpus.append((dict(ops=ops,responses=responses or [],reviewReject=changes.get('ReviewFail',False)),actual))
                if changes.get("CurrentSleepAt"):
                    assert actual["currentCalls"]>=changes["CurrentSleepAt"]
                    assert actual["elapsed"]<value["TimeoutMS"]/1000+.6
                if changes.get("ReviewSleepMS"):assert actual["elapsed"]<value["TimeoutMS"]/1000+.6
                count+=1;return actual
            try:
                run(['prepare','commit'],[True,True],2)
                run(['prepare','commit'],[True,True],2,[dict(body='\ufeff{"revision":1}')])
                run(['prepare','commit'],[True,True],2,[dict(contentType='Application/Json; Charset=UTF-8')])
                run(['race-prepare','commit'],[True,True],2,oracle=False)
                run(['prepare','mutate','commit'],[True,True,True],2,oracle=False)

                run(['prepare','prepare','commit'],[True,False,True],2)
                run(['prepare','wrong','commit'],[True,False,True],2)
                run(['prepare','retry','commit','commit'],[True,False,True,False],2)
                run(['prepare','verify','commit'],[True,False,True],2)
                run(['prepare','close','commit'],[True,True,False],0)
                run(['prepare','commit'],[False,False],0,ReviewFail=True)
                for status in [400,401,403,404,409,413,429,500,503,307]:
                    run(['prepare','commit'],[True,False],1,[dict(status=status)])
                for body in ['{}','{"revision":2}',' {"revision":1}','{"revision":1.0}','{"revision":1,"revision":1}','{"revision":1,"x":0}','x'*257]:
                    run(['prepare','commit','retry'],[True,False,True],3,[dict(body=body),{},{}])
                for typ in ['text/plain','application/json; charset=ascii','application/json; other=1','application/json; charset="utf-8"']:
                    run(['prepare','commit'],[True,False],1,[dict(contentType=typ)])
                run(['prepare','commit','prepare','retry'],[True,False,False,True],3,[dict(network=True),{},{}])
                a=run(['prepare','commit','verify','retry'],[True,False,True,True],4,[dict(network=True),{},{},{}]);assert a['results'][2]['pending'] and not a['results'][2]['ack']
                run(['prepare','commit','retry'],[True,False,False],2,[dict(network=True),dict(status=409)])
                run(['prepare','commit'],[True,False],2,[{},dict(newer=True)])
                run(['prepare','commit','verify'],[True,False,False],2,[dict(network=True),dict(newer=True)])
                run(['prepare','commit','retry','retry','retry'],[True,False,False,False,False],3,[dict(network=True)]*3)
                run(['prepare','commit','verify','verify','verify','verify'],[True,False,True,True,True,False],4,[dict(network=True),{},{},{}])
                for response in [dict(truncated=True),dict(trickle=True)]:
                    run(['prepare','commit'],[True,False],1,[response],oracle=False,TimeoutMS=max(200,args.deadline_case_ms),SettleMS=max(200,args.deadline_case_ms)+500)
                for at in [1,2,3,4,5]:
                    run(['prepare','commit'],[False,False] if at<3 else [True,False],0 if at<4 else at-3,oracle=False,CurrentFailAt=at)
                a=run(['prepare','close-commit'],[True,False],1,oracle=False,CurrentBlockAt=4);assert a['results'][1]['pending'] and a['results'][1]['unknown']
                run(['prepare','commit'],[False,False],0,oracle=False,ReviewSleepMS=400,TimeoutMS=100,SettleMS=450)
                run(['prepare','commit'],[True,False],0,oracle=False,DelayMS=[0,150],TimeoutMS=100)
                a=run(['prepare','commit','close','commit','retry','verify'],[True,False,True,False,False,False],1,[dict(network=True)])
                assert all(row['pending'] and row['state']=='unknown' and row['code']=='closed' for row in a['results'][3:])
                a=run(['prepare','commit','retry','verify'],[True,False,False,False],1,[dict(network=True)],oracle=False,TimeoutMS=max(200,args.deadline_case_ms),DelayMS=[0,0,max(200,args.deadline_case_ms)+100,0])
                assert all(row['pending'] and row['state']=='unknown' and row['code']=='expired' for row in a['results'][2:])
                for at in [0,4,5,6,22,38,54,70,86,94,102,110,118,126,158,190,222,287]:
                    changed=bytearray(envelope);changed[at]^=128
                    run(['prepare','commit'],[False,False],0,oracle=False,Envelope=base64.b64encode(changed).decode())
                for mode in ['binding','owner-dead','consent-dead','inactive']:
                    run(['prepare','commit'],[False,False],0,oracle=False,Mode=mode)
                run(['prepare','commit'],[False,False],0,oracle=False,Enabled=False)
                for at in [2,3]:
                    run(['prepare','commit'],[False,False],0,oracle=False,SessionChangeAt=at)
                original_fixture,original_envelope,original_digest=fixture,envelope,digest
                for kind in [1,2]:
                    fixture=dict(original_fixture,scope=dict(original_fixture['scope'],kind=kind),envelope=original_fixture['kinds'][str(kind)])
                    envelope=base64.b64decode(fixture['envelope']);digest=hashlib.sha256(envelope).hexdigest()
                    run(['prepare','commit'],[True,True],2,oracle=False)
                fixture,envelope,digest=original_fixture,original_envelope,original_digest
            finally:server.shutdown()
    source=args.producer/'sdk/native/sealed-candidate/python/owner-context-state-interop.mjs'
    oracle=json.loads(subprocess.check_output(['node',str(source)],input=json.dumps(dict(fixture=fixture,cases=[c for c,_ in corpus])),text=True,encoding='utf-8',timeout=90))
    assert len(oracle)==len(corpus)
    for (case,native),maintained in zip(corpus,oracle):
        assert [r['ok'] for r in maintained['results']]==[r['accepted'] for r in native['results']],(case,native,maintained)
        assert maintained['trace']==native['trace'],(case,native,maintained)
        assert maintained['review']==native['reviewCalls'],(case,native,maintained)
        for a,b in zip(native['results'],maintained['results']):
            if not a['accepted']:assert (a['code'],a['state'])==(b['code'],b['state']),(case,a,b)
            elif isinstance(b.get('value'),dict) and 'requestAcknowledged' in b['value']:assert a['ack']==b['value']['requestAcknowledged'],(case,a,b)
    print(f'{count} native context-save TLS controls passed; {len(corpus)} maintained state-machine differential controls passed; post-dispatch caller profile={args.deadline_case_ms}ms, review pre-dispatch=100ms')
if __name__=='__main__':main()
