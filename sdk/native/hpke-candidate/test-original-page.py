"""Authenticated page metadata, exact cursor correlation and durable proof fences."""
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
        assert request == s.request,(request,s.request)
        assert self.headers['Authorization'] == 'Bearer '+s.grant
        s.calls += 1
        body = json.dumps({'kind':'page','result':s.page}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)


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
    decode = lambda name: base64.b64decode(f[name],validate=True)
    proof = {field:str(uuid.UUID(bytes=decode(name))) for field,name in {
        'account_id':'account','interval_id':'interval','device_id':'device','line_id':'line',
        'connector_id':'connector','read_grant_id':'readGrant'}.items()}
    proof.update(reader_id=decode('originalReader').hex(),root_generation=1,authority_revision=1,
        expires_at_ms=20000,observed_at_ms=10000,current_manifest_version=3,
        current_manifest_digest=hashlib.sha256(decode('successor')[:-64]).hexdigest(),
        manifest_chain=[{'version':2,'accepted_at_ms':10000,'manifest_b64':f['activation']},
                        {'version':3,'accepted_at_ms':10000,'manifest_b64':f['successor']}])
    one=str(uuid.UUID(int=1));two=str(uuid.UUID(int=2));three=str(uuid.UUID(int=3))
    def row(event=one,at=10000):return dict(event_id=event,accepted_at_ms=at,observed_at_ms=9999,historical_manifest_version=2,activation_manifest_version=2,disposition='request_available',active_request_ids=[three])
    page=dict(events=[row()],next=None,proof=proof)
    count=0
    with tempfile.TemporaryDirectory(prefix='zrotext-page-tls-') as directory:
        folder=Path(directory);roots=tls.certificates(folder)
        with tls.Server(('localhost',0),Handler) as server:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(folder/'cert.pem',folder/'key.pem')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            server.grant='ztr_'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
            def run(name,mutate=lambda _:None,ok=False,calls=1,limit=2,cursor=None,clock=(10000,)):
                nonlocal count
                server.page=copy.deepcopy(page);mutate(server.page);server.calls=0
                wirecursor=None if cursor is None else dict(accepted_at_ms=cursor['AcceptedAt'],event_id=str(uuid.UUID(bytes=bytes(cursor['Event']))))
                server.request=dict(v=1,method='page',accepted_manifest_version=2,cursor=wirecursor,limit=limit)
                payload=dict(Fixture=f,Origin=f'https://{server.server_address[0]}:{server.server_port}',Roots=roots,Grant=server.grant,Clock=clock,Limit=limit,Cursor=cursor)
                result=subprocess.run(argv,input=json.dumps(payload),text=True,encoding='utf-8',capture_output=True,check=True,timeout=10)
                actual=json.loads(result.stdout)
                assert actual['ok']==ok and server.calls==calls and actual['rollback_refused'],(name,actual,server.calls)
                if ok:
                    expected=[dict(event=uuid.UUID(r['event_id']).hex,at=r['accepted_at_ms'],observed=r['observed_at_ms'],historical=r['historical_manifest_version'],activation=r['activation_manifest_version'],disposition=r['disposition'],requests=[uuid.UUID(i).hex for i in r['active_request_ids']]) for r in server.page['events']]
                    next=server.page['next'];next=None if next is None else dict(event=uuid.UUID(next['event_id']).hex,at=next['accepted_at_ms'])
                    assert actual['events']==expected and actual['next']==next and actual['revision']==2 and actual['history']==3,(name,actual)
                else:assert 'events' not in actual,(name,actual)
                count+=1
            run('signed short page',ok=True)
            run('empty page',lambda p:p.update(events=[]),ok=True)
            run('full page correlated next',lambda p:p.update(next=dict(event_id=one,accepted_at_ms=10000)),ok=True,limit=1)
            run('exclusive same-time cursor',lambda p:p.update(events=[row(two)]),ok=True,cursor=dict(AcceptedAt=10000,Event=list(uuid.UUID(one).bytes)))
            run('ordered same-time rows',lambda p:p.update(events=[row(),row(two)],next=dict(event_id=two,accepted_at_ms=10000)),ok=True)
            for state in ('unassociated','owner_review'):
                run(state,lambda p,state=state:p['events'][0].update(disposition=state,active_request_ids=[]),ok=True)
            for limit in (0,33):run('invalid limit',limit=limit,calls=0)
            run('zero cursor time',cursor=dict(AcceptedAt=0,Event=list(uuid.UUID(one).bytes)),calls=0)
            run('zero cursor event',cursor=dict(AcceptedAt=10000,Event=[0]*16),calls=0)
            run('same cursor repeated',cursor=dict(AcceptedAt=10000,Event=list(uuid.UUID(one).bytes)))
            run('before cursor',cursor=dict(AcceptedAt=10001,Event=list(uuid.UUID(one).bytes)))
            run('duplicate event',lambda p:p.update(events=[row(),row()]))
            run('descending rows',lambda p:p.update(events=[row(two),row()],next=dict(event_id=one,accepted_at_ms=10000)))
            run('response exceeds limit',lambda p:p.update(events=[row(),row(two),row(three)]))
            run('next on short page',lambda p:p.update(next=dict(event_id=one,accepted_at_ms=10000)))
            run('next missing on full page',limit=1)
            run('wrong next event',lambda p:p.update(next=dict(event_id=two,accepted_at_ms=10000)),limit=1)
            run('wrong next time',lambda p:p.update(next=dict(event_id=one,accepted_at_ms=10001)),limit=1)
            run('next extra field',lambda p:p.update(next=dict(event_id=one,accepted_at_ms=10000,extra=0)),limit=1)
            for field in tuple(page):run('missing '+field,lambda p,field=field:p.pop(field))
            for field in tuple(row()):run('missing row '+field,lambda p,field=field:p['events'][0].pop(field))
            for field,value in [('event_id',str(uuid.UUID(int=0))),('accepted_at_ms',0),('observed_at_ms',0),('historical_manifest_version',0),('activation_manifest_version',9007199254740992),('disposition','approved'),('active_request_ids',None),('extra',1)]:
                run('bad row '+field,lambda p,field=field,value=value:p['events'][0].update({field:value}))
            run('duplicate request',lambda p:p['events'][0].update(active_request_ids=[three,three]))
            run('too many requests',lambda p:p['events'][0].update(active_request_ids=[str(uuid.UUID(int=i)) for i in range(1,10)]))
            run('nil request',lambda p:p['events'][0].update(active_request_ids=[str(uuid.UUID(int=0))]))
            run('null events',lambda p:p.update(events=None))
            run('wrong proof scope',lambda p:p['proof'].update(reader_id='00'*32))
            run('expired proof',lambda p:p['proof'].update(expires_at_ms=10000))
            run('proof signature corrupt',lambda p:p['proof']['manifest_chain'][1].update(manifest_b64=f['activation']))
            run('local clock rollback',clock=(10000,9999))
            server.shutdown()
    print(f'{count} authenticated TLS page/cursor controls passed')

if __name__=='__main__':main()
