"""Typed proposal effects and same saved-intent status over synthetic TLS."""
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
import socket
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
        method=request['method'];s.calls.append(method);s.all_calls.append(method)
        assert self.headers['Authorization']=='Bearer '+s.grant
        assert self.headers.get('X-Zrotext-Output-Authorization') == ('Bearer '+s.output if method=='consume' else None)
        if method=='current':
            expected=3 if s.resume or len(s.calls)>1 else 2
            assert request==dict(v=1,method='current',accepted_manifest_version=expected)
            result=copy.deepcopy(s.proof)
            if expected==3:result['manifest_chain']=result['manifest_chain'][-1:]
            if s.mode=='pre-failure' or (s.mode=='post-failure' and len(s.calls)>1):
                self.send_response(403);self.send_header('Content-Length','0');self.end_headers();return
            if s.mode=='post-wrong-scope' and len(s.calls)>1:result['reader_id']='00'*32
        else:
            if method=='consume':
                assert request==dict(v=1,method='consume',accepted_manifest_version=3,params=dict(request_id=s.request_id,event_id=s.event,active_request_id=s.active,descriptor=s.descriptor))
                s.committed=True
            else:
                assert method=='status' and request==dict(v=1,method='status',accepted_manifest_version=3,consumption_id=s.request_id)
            if s.mode=='lost':self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
            if s.mode in ('404','403','redirect'):
                self.send_response(302 if s.mode=='redirect' else int(s.mode));self.send_header('Content-Length','0')
                if s.mode=='redirect':self.send_header('Location','/v1/reply-events')
                self.end_headers();return
            result=s.result
        body=json.dumps(dict(kind=method,result=result)).encode()
        if method!='current' and s.mode=='malformed':body=b'{'
        if method!='current' and s.mode=='duplicate':body=body.replace(b'"disposition": "proposal"',b'"disposition": "proposal","disposition": "proposal"')
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)



def main():
    p = argparse.ArgumentParser(); p.add_argument('--producer',required=True)
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
    vector=json.loads((Path(__file__).resolve().parents[3]/'protocol/v1/vectors/workflow-action-01.json').read_text())
    canonical_count=0
    def check_binding(value,good=True,raw=None):
        nonlocal canonical_count
        wire=raw if raw is not None else json.dumps(value)
        result=json.loads(subprocess.check_output(argv,input=json.dumps({'Canonical':wire}),text=True,encoding='utf-8',timeout=10))
        assert result['ok']==good,result
        if good:
            expected=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)
            assert result['canonical']==expected and result['digest']==hashlib.sha256(expected.encode()).hexdigest(),result
        canonical_count+=1
    check_binding(vector['action'])
    for lexical in ('1.0','1e0'):
        check_binding(vector['action'],raw=json.dumps(vector['action']).replace('"revision": 1','"revision": '+lexical))
    assert hashlib.sha256(json.dumps(vector['action'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==vector['binding_digest']
    for field,value in vector['field_edits'].items():
        changed=copy.deepcopy(vector['action']);changed[field]=value;check_binding(changed)
    for text in ('quote"slash\\', ''.join(map(chr,range(32)))+chr(127), '<>&'):
        changed=copy.deepcopy(vector['action']);changed['window_id']=text;check_binding(changed)
    for field,value in [('revision',True),('revision',9007199254740992),('not_before',-1),('commitment','unknown'),('content_digest','GG'*32),('timezone',''),('extra',1)]:
        changed=copy.deepcopy(vector['action']);changed[field]=value;check_binding(changed,False)
    for field in vector['action']:
        changed=copy.deepcopy(vector['action']);del changed[field];check_binding(changed,False)
    check_binding(None,False,raw=json.dumps(vector['action'])[:-1]+',"revision":1}')
    decode = lambda name: base64.b64decode(f[name],validate=True)
    proof = {field:str(uuid.UUID(bytes=decode(name))) for field,name in {
        'account_id':'account','interval_id':'interval','device_id':'device','line_id':'line',
        'connector_id':'connector','read_grant_id':'readGrant'}.items()}
    proof.update(reader_id=decode('originalReader').hex(),root_generation=1,authority_revision=1,
        expires_at_ms=20000,observed_at_ms=10000,current_manifest_version=3,
        current_manifest_digest=hashlib.sha256(decode('successor')[:-64]).hexdigest(),
        manifest_chain=[{'version':2,'accepted_at_ms':10000,'manifest_b64':f['activation']},
                        {'version':3,'accepted_at_ms':10000,'manifest_b64':f['successor']}])
    request_id=str(uuid.UUID(int=1));active_id=str(uuid.UUID(int=2));event=str(uuid.UUID(bytes=decode('event')))
    scopebytes=b'ZTSE/native/original-checkpoint-scope/v1\0'+b''.join(decode(n) for n in ['account','device','line','interval','connector','readGrant','originalReader'])+bytes([3])+b'+12'
    descriptor=dict(account_id=proof['account_id'],line_id=proof['line_id'],action_id=str(uuid.UUID(int=10)),recipient_id=str(uuid.UUID(int=11)),purpose_id=str(uuid.UUID(int=1)),content_ref=str(uuid.UUID(int=12)),routine_id=str(uuid.UUID(int=13)),revision=1,authority_generation=1,content_version=1,content_digest='ab'*32,commitment='informational',not_before=0,expires_at=100,timezone='UTC',window_id='window')
    canonical=lambda d:json.dumps(d,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    key=dict(account_id=descriptor['account_id'],action_id=descriptor['action_id'],revision=1,binding_digest=hashlib.sha256(canonical(descriptor)).hexdigest())
    count=0
    with tempfile.TemporaryDirectory(prefix='zrotext-consumption-tls-') as directory:
        folder=Path(directory);roots=tls.certificates(folder)
        with tls.Server(('localhost',0),Handler) as server:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(folder/'cert.pem',folder/'key.pem')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            server.grant='ztr_'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=');server.all_calls=[];server.output='ztw_'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            def run(name,*,status=False,active=True,mode='',ok=False,unknown=False,calls=3,mutate=lambda _:None,corrupt=-1,invalid=False,resume=False,state=None,descriptor_mutate=lambda _:None,output=None,grant=None,invalid_descriptor=False):
                nonlocal count
                state=state or Path(tempfile.mkdtemp(prefix='intent-',dir=folder))
                server.proof=copy.deepcopy(proof);server.mode=mode;server.calls=[];server.resume=resume;server.event=event;server.request_id=request_id;server.active=active_id if active else None;server.committed=False
                server.descriptor=copy.deepcopy(descriptor);descriptor_mutate(server.descriptor)
                server.result=dict(event_id=event,consumption_id=request_id,active_request_id=server.active,disposition='proposal',action=copy.deepcopy(key));mutate(server.result)
                payload=dict(Fixture=f,Origin=f'https://{server.server_address[0]}:{server.server_port}',Roots=roots,Grant=server.grant if grant is None else grant,Output=server.output if output is None else output,Descriptor=server.descriptor,Clock=[10000],Directory=str(state),Resume=resume,Status=status,Active=active,Corrupt=corrupt,Invalid=invalid)
                r=subprocess.run(argv,input=json.dumps(payload),text=True,encoding='utf-8',capture_output=True,check=True,timeout=10);actual=json.loads(r.stdout)
                assert actual['ok']==ok and actual['unknown']==unknown and len(server.calls)==calls,(name,actual,server.calls)
                assert server.calls.count('consume')==(1 if not status and calls>=2 else 0),(name,server.calls)
                if not invalid and not invalid_descriptor:
                    raw=b'ZTOP\x01'+decode('rootPin')[29:]+hashlib.sha256(scopebytes).digest()+decode('event')+uuid.UUID(request_id).bytes+bytes([int(active)])+uuid.UUID(active_id).bytes+canonical(server.descriptor)
                    assert (state/'intent.bin').read_bytes()==raw,(name,'saved identity changed')
                    if corrupt==-1:assert actual['record']==raw.hex(),(name,'record mismatch')
                if ok:
                    assert actual['proposal']==(server.result['disposition']=='proposal'),(name,actual)
                    assert actual['event']==uuid.UUID(event).hex and actual['consumption']==uuid.UUID(request_id).hex and actual['active']==(uuid.UUID(active_id).hex if active else None),(name,actual)
                else:
                    assert 'event' not in actual and actual['error']==('original reply outcome unknown' if unknown else 'original reply unavailable'),(name,actual)
                count+=1;return state
            for active in (True,):
                run('consume exact saved identity',active=active,ok=True)
                run('status exact saved identity',active=active,status=True,ok=True)
            for status in (False,True):
                run('preproof refusal',status=status,mode='pre-failure',calls=1)
                for mode in ('lost','404','403','redirect','malformed','duplicate'):
                    run(mode,status=status,mode=mode,unknown=not status,calls=2)
                for mode in ('post-failure','post-wrong-scope'):
                    run(mode,status=status,mode=mode,unknown=not status)
                for field,value in [('event_id',str(uuid.UUID(int=3))),('consumption_id',str(uuid.UUID(int=3))),('active_request_id',None),('disposition','owner_review'),('action',{}),('extra',True)]:
                    run('mismatched '+field,status=status,unknown=not status,calls=2,mutate=lambda r,field=field,value=value:r.update({field:value}))
                for field in ('event_id','consumption_id','active_request_id','disposition','action'):
                    run('missing '+field,status=status,unknown=not status,calls=2,mutate=lambda r,field=field:r.pop(field))
            run('caller nil request no attempt',invalid=True,calls=0)
            for corrupt in (0,4,5,69,70,101,134,151,-2):run('invalid saved frame',corrupt=corrupt,calls=0)
            for status in (False,True):
                run('legitimate owner review fallback',status=status,ok=True,mutate=lambda r:r.update(disposition='owner_review',action=None))
                for field,value in [('account_id',str(uuid.UUID(int=99))),('action_id',str(uuid.UUID(int=99))),('revision',2),('binding_digest','00'*32)]:
                    run('wrong action '+field,status=status,unknown=not status,calls=2,mutate=lambda r,field=field,value=value:r['action'].update({field:value}))
            for token in ('',server.grant,'ztw_'+'A'*42+'B','Bearer '+server.output):run('invalid output no network',output=token,calls=0)
            run('output cannot replace read grant',grant=server.output,calls=0)
            for field,value in [('account_id',str(uuid.UUID(int=99))),('line_id',str(uuid.UUID(int=99))),('revision',129),('content_digest','GG'*32),('not_before',100),('timezone','\u00e9'),('extra',True)]:
                run('bad descriptor '+field,descriptor_mutate=lambda d,field=field,value=value:d.update({field:value}),invalid_descriptor=True,calls=0)
            server.all_calls=[]
            state=run('committed response lost',mode='lost',unknown=True,calls=2)
            assert server.committed
            run('fresh process status same saved intent',status=True,resume=True,state=state,ok=True)
            assert server.all_calls==['current','consume','current','status','current'],server.all_calls
            server.shutdown()
    print(f'{canonical_count} canonical binding controls and {count} saved-proposal consumption/status TLS controls passed')

if __name__=='__main__':main()
