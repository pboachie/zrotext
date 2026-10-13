"""Run native durable election acceptance using a pinned maintained producer."""
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
    parser.add_argument('--producer',type=Path,required=True)
    parser.add_argument('--ruby',default='ruby')
    args=parser.parse_args();producer=args.producer.resolve()
    env={k:v for k,v in os.environ.items() if k not in ('NODE_OPTIONS','NODE_PATH','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS','RUBYOPT','RUBYLIB')}
    if subprocess.check_output(['git','-C',str(producer),'rev-parse','HEAD'],text=True).strip()!='304d512b7a420a3102278f32baed095f3e778989':raise ValueError('Unexpected producer revision')
    subprocess.run(['git','-C',str(producer),'diff','--quiet','HEAD','--'],check=True)
    raw=subprocess.check_output(['node',str(producer/'sdk/native/sealed-candidate/python/produce-election03.mjs')],env=env)
    raw=subprocess.check_output(['node',str(HERE/'election-journal-controls.mjs'),str(producer)],input=raw,env=env)
    fixture=subprocess.check_output(['python',str(HERE/'java/reader/elected_rows.py')],input=raw,env=env)
    fixture+=('successor\tb\t'+base64.b64decode(json.loads(raw)['successor'],validate=True).hex()+'\n').encode()
    with tempfile.TemporaryDirectory(prefix='zrotext-election-journal-') as folder:
        temp=Path(folder)
        if args.language=='java':
            base=HERE/'java';sources=[base/'HpkeRecipient.java',base/'SignedEnvelope.java',base/'ManifestChain.java',base/'Election03.java',base/'reader/ElectedReader03.java',HERE.parent/'crypto-candidate/java/CandidateBody.java',*sorted((base/'election-journal').glob('*.java'))]
            subprocess.run(['javac','--release','17','-Xlint:all','-Werror','-d',str(temp),*[str(p) for p in sources]],env=env,check=True)
            command=['java','-cp',str(temp),'org.zrotext.candidate.ElectionJournalTest']
        elif args.language=='csharp':
            subprocess.run(['dotnet','build',str(HERE/'csharp/election-journal/ElectionJournalTest.csproj'),'-o',str(temp)],env=env,check=True)
            command=['dotnet',str(temp/'ElectionJournalTest.dll')]
        else:command=[args.ruby,str(HERE/'ruby/election-journal/test.rb')]
        subprocess.run(command,input=fixture,env=env,check=True,timeout=120)

if __name__=='__main__':main()
