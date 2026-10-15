"""Build managed root-transition journals and run the public signed corpus."""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
HERE=Path(__file__).resolve().parent

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language',choices=['java','csharp','ruby'],required=True)
    parser.add_argument('--ruby',default='ruby')
    parser.add_argument('--producer',type=Path,required=True)
    parser.add_argument('--controls',type=Path,required=True)
    parser.add_argument('--command-file', type=Path, help='Trusted installed-consumer command JSON; skip source compilation')
    args=parser.parse_args()
    env={k:v for k,v in os.environ.items() if k not in ('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','RUBYOPT','RUBYLIB')}
    fixture=subprocess.check_output(['python',str(HERE/'root-journal-vectors.py')],env=env)
    for directory,pin in ((args.producer,'93a65d737dfb0de603c732241c667f90771f60dd'),(args.controls,'26e73753c4ff5e3b27abdca6f5b67ed3ce5a0273')):
        actual=subprocess.check_output(['git','-C',str(directory),'rev-parse','HEAD'],text=True).strip()
        if actual!=pin:raise ValueError('Unexpected independent fixture revision')
        subprocess.run(['git','-C',str(directory),'diff','--quiet','HEAD','--'],check=True)
    env={k:v for k,v in env.items() if k not in ('NODE_OPTIONS','NODE_PATH')}
    original=subprocess.check_output(['node',str(args.producer/'sdk/native/sealed-candidate/python/produce-fixture.mjs')],env=env)
    fresh=json.loads(subprocess.check_output(['node',str(args.controls/'sdk/native/hpke-candidate/root-controls.mjs'),str(args.producer)],input=original,env=env))
    names=['rootPin','fingerprint','manifest','transition','newPoint','newManifest','newSuccessor','newInbound','inbound','archiveScalar','reader']
    fixture+=''.join('dynamic.'+k+'\t'+base64.b64decode(fresh[k],validate=True).hex()+'\n' for k in names).encode()
    fixture+=('dynamic.text\t'+fresh['text'].encode('utf-8').hex()+'\n').encode()
    with tempfile.TemporaryDirectory(prefix='zrotext-root-build-') as folder:
        temp=Path(folder)
        if args.command_file:
            command=json.loads(args.command_file.read_text(encoding='utf-8'))
            if not isinstance(command,list) or not command or not all(isinstance(v,str) and v for v in command):
                raise ValueError('Invalid installed consumer command')
        else:
            if args.language=='java':
                sources=[HERE/'java/HpkeRecipient.java',HERE/'java/ManifestChain.java',HERE/'java/SignedEnvelope.java',HERE/'java/reader/SealedReader02.java',HERE.parent/'crypto-candidate/java/CandidateBody.java',*sorted((HERE/'java/root-journal').glob('*.java'))]
                subprocess.run(['javac','--release','17','-Xlint:all','-Werror','-d',str(temp),*[str(p) for p in sources]],env=env,check=True)
                command=['java','-cp',str(temp),'org.zrotext.candidate.RootJournalTest']
            elif args.language=='csharp':
                subprocess.run(['dotnet','build',str(HERE/'csharp/root-journal/RootJournalTest.csproj'),'-o',str(temp)],env=env,check=True)
                command=['dotnet',str(temp/'RootJournalTest.dll')]
            else:command=[args.ruby,str(HERE/'ruby/root-journal/test.rb')]
        subprocess.run(command,input=fixture,env=env,check=True,timeout=120)

if __name__=='__main__':main()
