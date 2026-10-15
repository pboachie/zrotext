"""Native explicit template opening, real synthetic TLS and maintained oracle."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

spec=importlib.util.spec_from_file_location('cold',Path(__file__).with_name('test-owner-template.py'))
cold=importlib.util.module_from_spec(spec);spec.loader.exec_module(cold)
PIN='c843543f13e3bbd6ac17a260a4b0523f0748324f'

class Handler(cold.Handler):
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        self.server.calls.append(('POST',body))
        self.close_connection=True

def main():
    p=argparse.ArgumentParser();p.add_argument('--producer',type=Path,required=True);p.add_argument('--opening-oracle',type=Path,required=True)
    p.add_argument('--deadline-case-ms',type=int,default=1000)
    g=p.add_mutually_exclusive_group(required=True);g.add_argument('--binary');g.add_argument('--command-file',type=Path)
    args=p.parse_args();assert 100<=args.deadline_case_ms<=2000
    for folder,pin in [(args.producer,cold.PIN),(args.opening_oracle,PIN)]:
        assert subprocess.check_output(['git','-C',str(folder),'rev-parse','HEAD'],text=True).strip()==pin
        assert not subprocess.check_output(['git','-C',str(folder),'status','--porcelain'],text=True).strip()
    f=json.loads(subprocess.check_output(['node',str(args.producer/'sdk/native/sealed-candidate/python/owner-template-interop.mjs')],text=True,encoding='utf-8',timeout=60))
    argv=[args.binary] if args.binary else json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(argv,list) and argv and all(isinstance(v,str) and v and '\0' not in v for v in argv)
    wire=base64.b64decode(f['envelope']);count=0;cases=[];native=[]
    with tempfile.TemporaryDirectory(prefix='zrotext-template-opening-') as tmp:
        folder=Path(tmp);roots=cold.tls.certificates(folder)
        with cold.tls.Server((socket.gethostbyname('localhost'),0),Handler) as server:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(folder/'cert.pem',folder/'key.pem');server.socket=ctx.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start()
            origin='https://'+server.server_address[0]+':'+str(server.server_address[1])
            def run(accepted=True,calls=1,body=None,status=200,oracle=None,**changes):
                nonlocal count
                server.calls=[];server.mode='normal';server.status=status;server.content=cold.CONTENT;server.bodies=[wire if body is None else body]
                data=dict(Fixture=f,Origin=origin,Roots=roots,Cookie='synthetic-owner=opaque',CSRF='synthetic-csrf',Enabled=True,TimeoutMS=4000,ValidForMS=10000,Reads=1,Now=[10000],Mode='');data.update(changes)
                output=subprocess.run(argv,input=json.dumps(data),text=True,encoding='utf-8',capture_output=True,check=True,timeout=20)
                result=json.loads(output.stdout);assert len(result['results'])==data['Reads']
                assert [r['accepted'] for r in result['results']]==[accepted]*data['Reads'],(count,changes,result)
                assert len(server.calls)==calls,(count,changes,len(server.calls),calls,result)
                for row in result['results']:
                    if accepted:
                        assert row['text']==f['preview']['text'] and row['segments']==f['preview']['estimate'] and not row['ack'] and row['pending']==bool(changes.get('SetupPending'))
                        assert row['digest']==hashlib.sha256(wire).hexdigest()
                    else:assert 'text' not in row and f['preview']['text'] not in output.stdout
                if changes.get('CurrentSleepAt'):
                    assert result['currentCalls']>=changes['CurrentSleepAt']
                    assert result['elapsed']<data['TimeoutMS']/1000+.6
                if oracle is not None:cases.append(oracle);native.append(dict(accepted=accepted,calls=calls))
                count+=1;return result
            try:
                run(oracle={});run(calls=2,Reads=2)
                # A matching read can open content but cannot acknowledge the
                # prior dropped POST, including on a second explicit opening.
                run(calls=3,Reads=2,SetupPending=True)
                run(False,0,Mode='owner-dead',oracle=dict(ownerLive=False))
                run(False,0,Mode='consent-dead');run(False,0,Mode='inactive');run(False,0,Mode='binding')
                run(False,0,Enabled=False);run(False,0,WrongKey=True)
                for at in range(1,8):run(False,0 if at<=2 else 1,CurrentFailAt=at,oracle=dict(ownerLostAfterRead=True) if at==3 else None)
                # Supplied dedicated client closure after its GET must invalidate
                # independent opening publication even when guard authority stays live.
                for at in [5,6,7]:run(False,1,ClientCloseAt=at)
                for at in [1,5,7,10]:run(False,0 if at<=5 else 1,SessionChangeAt=at)
                tamper=bytearray(wire);tamper[-1]^=1;run(False,1,bytes(tamper),oracle=dict(tamper=True))
                run(False,1,status=302,oracle=dict(status=302))
                for body in [b'',wire[:-1],wire+b'\0',bytes(33076)]:run(False,1,body)
                run(False,0,Roots='');run(False,0,Now=[9999]);run(False,1,Now=[10001]*6+[10000])
                budget=args.deadline_case_ms;sleep=budget+400
                run(False,1,CurrentSleepAt=7,SleepMS=sleep,SettleMS=sleep+50,TimeoutMS=budget)
                run(False,0,CurrentSleepAt=1,SleepMS=400,SettleMS=450,TimeoutMS=100,Reads=2)
            finally:server.shutdown()
    source=args.opening_oracle/'sdk/native/sealed-candidate/python/template-opening-interop.mjs'
    actual=json.loads(subprocess.check_output(['node',str(source)],input=json.dumps(dict(fixture=f,cases=cases)),text=True,encoding='utf-8',timeout=90))
    for a,b in zip(actual,native):assert a['accepted']==b['accepted'] and a['calls']==b['calls'],(a,b)
    assert len(actual)==len(native)
    print(f'{count} native template-opening TLS controls passed; {len(cases)} maintained lifecycle differentials passed; post-dispatch={args.deadline_case_ms}ms')
if __name__=='__main__':main()
