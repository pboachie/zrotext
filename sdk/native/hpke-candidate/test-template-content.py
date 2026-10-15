"""Compare installed or source-built probes with an independent maintained oracle."""
import argparse
import json
from pathlib import Path
import subprocess

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--producer',required=True)
    command=parser.add_mutually_exclusive_group(required=True);command.add_argument('--binary');command.add_argument('--command-file')
    args=parser.parse_args()
    argv=[str(Path(args.binary).resolve(strict=True))] if args.binary else json.loads(Path(args.command_file).read_text(encoding='utf-8'))
    if not isinstance(argv,list) or not argv or any(not isinstance(v,str) or not v or '\0' in v for v in argv):parser.error('trusted nonempty argv required')
    corpus=json.loads(subprocess.check_output(['node',str(Path(__file__).with_name('produce-template-content.mjs')),args.producer],text=True,encoding='utf-8',timeout=30))
    assert corpus['format']=='native-template-content-v1'
    # Never send expected answers to the native probe.
    request={'cases':[{'raw':c['raw']} for c in corpus['cases']],'segments':[{'units':c['units']} for c in corpus['segments']]}
    actual=json.loads(subprocess.check_output(argv,input=json.dumps(request),text=True,encoding='utf-8',timeout=30))
    assert set(actual)=={'cases','segments'}
    for field in ('cases','segments'):
        assert len(actual[field])==len(corpus[field])
        for i,(expected,got) in enumerate(zip(corpus[field],actual[field])):assert got==expected['expected'],(field,i,expected.get('name'),got,expected['expected'])
    print(f"{len(corpus['cases'])} template content and {len(corpus['segments'])} segment oracle controls passed")

if __name__=='__main__':main()
