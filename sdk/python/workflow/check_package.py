"""Build bounded workflow archives and test installed native clients over HTTPS."""
import argparse
from email.parser import BytesParser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile

ROOT=Path(__file__).resolve().parent
PACKAGE='zrotext_workflow'
DIST='zrotext_workflow_candidate-0.1.0a1'
FILES={'__init__.py','client.py','validation.py','workflow_contract.json'}


def run(args,**kwargs):
    return subprocess.check_output([str(v) for v in args],text=True,encoding='utf-8',**kwargs)


def environment(path):
    venv.EnvBuilder(with_pip=True).create(path)
    python=path/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
    run([python,'-I',ROOT.parents[2]/'scripts/bootstrap_python_pip.py',
         '--wheel-dir',path.parent/'pip-bootstrap'],cwd=path.parent)
    return python


def verify(wheel,sdist):
    with zipfile.ZipFile(wheel) as archive:
        expected={PACKAGE+'/'+name for name in FILES}
        expected|={DIST+'.dist-info/'+name for name in ('METADATA','WHEEL','top_level.txt','RECORD','licenses/LICENSE')}
        assert set(archive.namelist())==expected
        metadata=BytesParser().parsebytes(archive.read(DIST+'.dist-info/METADATA'))
        assert metadata['Name']=='zrotext-workflow-candidate' and metadata['Version']=='0.1.0a1'
        assert metadata['Requires-Python']=='>=3.11' and metadata['License-Expression']=='AGPL-3.0-only'
        assert metadata.get_all('Requires-Dist') is None
        assert archive.read(DIST+'.dist-info/licenses/LICENSE')==ROOT.joinpath('LICENSE').read_bytes()
    with tarfile.open(sdist) as archive:
        expected={DIST+'/'+PACKAGE+'/'+name for name in FILES}
        expected|={DIST+'/'+name for name in ('LICENSE','README.md','pyproject.toml','MANIFEST.in','PKG-INFO','setup.cfg')}
        expected|={DIST+'/zrotext_workflow_candidate.egg-info/'+name for name in ('PKG-INFO','SOURCES.txt','top_level.txt','dependency_links.txt')}
        assert {v.name for v in archive.getmembers() if v.isfile()}==expected
        assert not any(v.issym() or v.islnk() for v in archive.getmembers())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--alpha-source',type=Path,help='Reviewed alpha package source for optional co-installation acceptance')
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    summaries=[]
    with tempfile.TemporaryDirectory(prefix='zrotext-workflow-package-') as directory:
        temporary=Path(directory);source=temporary/'source';source.mkdir()
        for name in ('LICENSE','README.md','pyproject.toml','MANIFEST.in'):shutil.copyfile(ROOT/name,source/name)
        shutil.copytree(ROOT/PACKAGE,source/PACKAGE,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        builder=environment(temporary/'builder')
        run([builder,'-m','pip','--disable-pip-version-check','install','setuptools==84.0.0'],cwd=temporary)
        run([builder,'-c',"from setuptools.build_meta import build_wheel,build_sdist;build_wheel('dist');build_sdist('dist')"],cwd=source)
        wheel=next((source/'dist').glob('*.whl'));sdist=next((source/'dist').glob('*.tar.gz'))
        verify(wheel,sdist)
        alpha=None
        if args.alpha_source is not None:
            alpha_output=temporary/'alpha';alpha_output.mkdir()
            run([builder,'-m','pip','--disable-pip-version-check','wheel','--no-deps','--wheel-dir',alpha_output,args.alpha_source.resolve()],cwd=temporary)
            alpha=next(alpha_output.glob('zrotext_client-0.1.7rc1-*.whl'))
        for i,artifact in enumerate((wheel,sdist)):
            python=environment(temporary/f'consumer-{i}')
            run([python,'-m','pip','--disable-pip-version-check','install',artifact],cwd=temporary)
            if alpha is not None:run([python,'-m','pip','--disable-pip-version-check','install',alpha],cwd=temporary)
            run([python,'-m','pip','--disable-pip-version-check','check'],cwd=temporary)
            probe='''import sys,json,importlib.metadata
from pathlib import Path
import zrotext_workflow as p
from zrotext_workflow import validation
assert Path(p.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
assert len(p.workflow_functions())==8
assert importlib.metadata.requires('zrotext-workflow-candidate') is None
f=json.load(sys.stdin)
assert p.action_digest(f['action'])==f['binding_digest']
assert validation.CONTRACT['tools']
'''
            vector=(ROOT.parents[2]/'protocol/v1/vectors/workflow-action-01.json').read_text()
            run([python,'-I','-c',probe],cwd=temporary,input=vector)
            if alpha is not None:
                alpha_probe='''import sys,importlib.metadata
from pathlib import Path
import zrotext_client as a,zrotext_workflow as w
assert all(Path(p.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()) for p in (a,w))
assert importlib.metadata.version('zrotext-client')=='0.1.7rc1'
assert a.requires_reconciliation('unknown') and len(w.workflow_functions())==8
key=bytes([7])*32;body=b'{"synthetic":true}';timestamp='1000'
signature=a.sign_webhook(key,1000,body)
a.verify_webhook(signing_key=key,timestamp=timestamp,signature=signature,body=body,now_seconds=1000)
'''
                run([python,'-I','-c',alpha_probe],cwd=temporary)
            env=dict(os.environ,ZT_WORKFLOW_INSTALLED_PYTHON=str(python))
            # Node only hosts the independent synthetic TLS fixture. The isolated
            # installed Python client has no source path or subprocess bridge.
            output=run(['node','--test','--test-reporter=tap',ROOT.parents[1]/'typescript/test/workflow-python-http.test.mjs'],cwd=temporary,env=env)
            assert re.search(r'^# fail 0$',output,re.MULTILINE),output
            count=re.search(r'^# pass (\d+)$',output,re.MULTILINE)
            assert count and int(count.group(1))>0,output
            summaries.append(int(count.group(1)))
        for artifact in (wheel,sdist):shutil.copyfile(artifact,args.output/artifact.name)
    print(json.dumps(dict(wheel_and_sdist='passed',installed_https_cases=summaries,source_imports=False,alpha_coinstalled=alpha is not None)))


if __name__=='__main__':main()
