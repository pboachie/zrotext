"""Owned Windows PCP opening lifecycle through synthetic TLS, no live owner."""
import argparse
import base64
import concurrent.futures
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

def main():
    p=argparse.ArgumentParser();p.add_argument('--producer',type=Path,required=True)
    p.add_argument('--allow-unqualified',action='store_true')
    g=p.add_mutually_exclusive_group(required=True);g.add_argument('--binary');g.add_argument('--command-file',type=Path)
    args=p.parse_args();source=args.producer.resolve(strict=True)
    assert subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()=='c843543f13e3bbd6ac17a260a4b0523f0748324f'
    assert not subprocess.check_output(['git','-C',str(source),'status','--porcelain'],text=True).strip()
    argv=[args.binary] if args.binary else json.loads(args.command_file.read_text(encoding='utf-8'))
    assert isinstance(argv,list) and argv and all(isinstance(v,str) and v and '\0' not in v for v in argv)
    available=json.loads(subprocess.check_output(argv+['--probe'],text=True,encoding='utf-8',timeout=30))
    if available!={'available':True}:
        assert available=={'available':False} and args.allow_unqualified,'protected provider unavailable'
        print('Protected provider unavailable; hardware acceptance NOT qualified')
        return
    with tempfile.TemporaryDirectory(prefix='zrotext-protected-opening-') as tmp:
        folder=Path(tmp);roots=cold.tls.certificates(folder)
        with cold.tls.Server((socket.gethostbyname('localhost'),0),cold.Handler) as server:
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(folder/'cert.pem',folder/'key.pem');server.socket=ctx.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start();origin='https://'+server.server_address[0]+':'+str(server.server_address[1])
            count=0
            try:
                for changes in [{},dict(Tamper=True),dict(ProviderCloseAt=6),dict(ProviderCloseAt=7),dict(ClientCloseAt=7),dict(Mode='owner-dead'),dict(SetupFailure=True)]:
                    process=subprocess.Popen(argv+['--hardware'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
                    try:
                        with concurrent.futures.ThreadPoolExecutor() as pool:
                            future=pool.submit(process.stdout.readline)
                            try:point=json.loads(future.result(timeout=60))['public']
                            except BaseException:
                                process.stdin.close()
                                try:process.wait(timeout=30)
                                except subprocess.TimeoutExpired:process.terminate()
                                raise
                        assert len(bytes.fromhex(point))==65
                        if changes.get('SetupFailure'):
                            out,_=process.communicate('',timeout=30);assert process.returncode!=0 and json.loads(out.splitlines()[-1])==dict(owned_key_deleted=True);count+=1;continue
                        f=json.loads(subprocess.check_output(['node',str(source/'sdk/native/sealed-candidate/python/owner-template-interop.mjs'),'--recipient-point',point],text=True,encoding='utf-8',timeout=90))
                        assert 'archiveScalar' not in f
                        wire=bytearray(base64.b64decode(f['envelope']))
                        if changes.get('Tamper'):wire[-1]^=1
                        server.calls=[];server.mode='normal';server.status=200;server.content=cold.CONTENT;server.bodies=[bytes(wire)]
                        value=dict(Fixture=f,Origin=origin,Roots=roots,Cookie='synthetic-owner=opaque',CSRF='synthetic-csrf',Enabled=True,TimeoutMS=4000,ValidForMS=10000,Reads=1,Now=[10000],Mode='');value.update(changes)
                        out,err=process.communicate(json.dumps(value),timeout=60);assert process.returncode==0,'protected native probe failed: '+err
                        lines=out.splitlines();assert json.loads(lines[-1])==dict(owned_key_deleted=True)
                        row=json.loads(lines[0])['results'][0];accept=not changes
                        assert row['accepted']==accept,(changes,row)
                        assert len(server.calls)==(0 if changes.get('Mode')=='owner-dead' else 1)
                        if accept:assert row['text']==f['preview']['text'] and not row['ack'] and not row['pending']
                        else:assert 'text' not in row and f['preview']['text'] not in out
                        count+=1
                    finally:
                        if process.poll() is None:
                            if not process.stdin.closed:process.stdin.close()
                            process.stdin=None
                            try:process.communicate(timeout=30)
                            except subprocess.TimeoutExpired:
                                process.terminate();process.communicate(timeout=10)
                                raise AssertionError('unresponsive owned child; private receipt retained')
            finally:server.shutdown()
    print(f'{count} protected template-opening controls passed including setup-failure EOF cleanup; owned deletion verified')
if __name__=='__main__':main()
