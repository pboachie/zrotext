"""Build a managed native profile02 composer and independently consume its output."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import urllib.request

HERE = Path(__file__).resolve().parent
PIN = 'a13ea1e3d6f6db594485c19b36c43fe642e67c7a'
JNA_HASH = 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=['java','csharp','ruby'], required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--controls', type=Path, required=True)
    parser.add_argument('--jna', type=Path)
    parser.add_argument('--ruby', default='ruby')
    args = parser.parse_args()
    producer = args.producer.resolve()
    def run(command, **kw):
        return subprocess.run([str(v) for v in command], check=True, **kw)
    if run(['git','-C',producer,'rev-parse','HEAD'],capture_output=True,text=True).stdout.strip() != PIN:
        raise ValueError('Unexpected producer revision')
    run(['git','-C',producer,'diff','--quiet','HEAD','--'])
    controls=args.controls.resolve()
    if run(['git','-C',controls,'rev-parse','HEAD'],capture_output=True,text=True).stdout.strip()!='1b7732ec36bf705f78e69a2cea95b792f04dc772':raise ValueError('Unexpected control revision')
    run(['git','-C',controls,'diff','--quiet','HEAD','--'])
    env = {k:v for k,v in os.environ.items() if k not in ('NODE_OPTIONS','NODE_PATH','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','RUBYOPT','RUBYLIB')}
    with tempfile.TemporaryDirectory(prefix='zrotext-managed-compose02-') as folder:
        temp = Path(folder)
        if args.language == 'java':
            jar = args.jna.resolve() if args.jna else temp/'jna.jar'
            if not args.jna:
                urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar',jar)
            if hashlib.sha256(jar.read_bytes()).hexdigest()!=JNA_HASH:
                raise ValueError('JNA checksum mismatch')
            java=HERE/'java'
            sources=sorted(java.glob('*.java'))+sorted((java/'reader').glob('*.java'))+[java/'custody/ProtectedSigner.java']+sorted((java/'composition02').glob('*.java'))+[HERE.parent/'crypto-candidate/java/CandidateBody.java']
            run(['javac','--release','17','-Xlint:all','-Werror','-cp',jar,'-d',temp,*sources],env=env)
            command=['java','-cp',str(temp)+os.pathsep+str(jar),'org.zrotext.candidate.Compose02Test']
        elif args.language == 'csharp':
            run(['dotnet','build',HERE/'csharp/composition02/Compose02Test.csproj','-o',temp],env=env)
            command=['dotnet',str(temp/'Compose02Test.dll')]
        else:
            command=[args.ruby,str(HERE/'ruby/composition02/compose_test.rb')]
        probe=subprocess.run(command+['--probe'],env=env,timeout=30)
        if probe.returncode==77:
            print('UNQUALIFIED: read-only native signing probe refused before creation')
            return
        probe.check_returncode()
        receipt=Path(tempfile.gettempdir())/('zrotext-compose02-pending-'+temp.name+'.txt')
        child=subprocess.Popen(command+[str(receipt)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',env=env)
        ready=queue.Queue()
        threading.Thread(target=lambda:ready.put(child.stdout.readline()),daemon=True).start()
        try:
            point=ready.get(timeout=30).strip()
            if len(point)!=130 or not point.startswith('04'):
                raise ValueError('Native signer handshake failed')
            bytes.fromhex(point)
            directory=producer/'sdk/native/sealed-candidate/python'
            fixture=json.loads(run(['node',directory/'produce-fixture.mjs','--signer-point',point],capture_output=True,text=True,encoding='utf-8',env=env).stdout)
            fixture=json.loads(run(['node',controls/'sdk/native/hpke-candidate/root-controls.mjs',producer],input=json.dumps(fixture),capture_output=True,text=True,encoding='utf-8',env=env).stdout)
            wanted=['transition','newPoint','newManifest','currentRetained','currentRevoked','manifest','rootPin','fingerprint','device','line']
            text=''.join(k+'\t'+base64.b64decode(fixture[k],validate=True).hex()+'\n' for k in wanted)
            output,error=child.communicate(text,timeout=90)
            if child.returncode:
                raise RuntimeError('Native composition failed: '+error)
            envelopes=[line[9:] for line in output.splitlines() if line.startswith('ENVELOPE ')]
            if len(envelopes)!=4:
                raise ValueError('Missing native ciphertext cases')
            for envelope in envelopes:
                result=json.loads(run(['node',directory/'consume-native02.mjs'],input=json.dumps(dict(fixture=fixture,envelope=envelope,expectedText='Native composed02 🌱')),capture_output=True,text=True,encoding='utf-8',env=env).stdout)
                if result!={'verified':True,'openedRecipients':2}:
                    raise ValueError('Independent consumer did not accept both recipients')
            rotated=[line[8:] for line in output.splitlines() if line.startswith('ROTATED ')]
            if len(rotated)!=1:raise ValueError('Missing rotated-root candidate')
            result=json.loads(run(['node',controls/'sdk/native/hpke-candidate/consume-rotated02.mjs',producer],input=json.dumps(dict(fixture=fixture,envelope=rotated[0],expectedText='Native composed02 🌱')),capture_output=True,text=True,encoding='utf-8',env=env).stdout)
            if result!={'verified':True,'openedRecipients':2}:raise ValueError('Rotated candidate consumer refused')
            for line in output.splitlines():
                if line.startswith('QUALIFIED:'):print(line)
            if receipt.exists():raise ValueError('Owned key cleanup receipt remains')
            print('Maintained TypeScript verified and opened both recipients for four native profile02 candidates plus rotated-root journal output')
        finally:
            if child.poll() is None:
                child.kill();child.wait()
                raise RuntimeError('Native process interrupted; preserve pending receipt for exact owned cleanup')

if __name__=='__main__':main()
