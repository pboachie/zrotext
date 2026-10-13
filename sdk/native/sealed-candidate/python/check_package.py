"""Build bounded archives and execute isolated wheel/sdist consumers."""
import argparse
from email.parser import BytesParser
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile

ROOT=Path(__file__).resolve().parent
MODULES={'__init__','sealed_candidate','checkpoint_store','cng_custody','cng_signing','election03','election_journal','compose03','compose02','outbound_journal','root_checkpoint','reply_selection','outbound02_journal'}
PACKAGE='zrotext_native_candidate'
DIST=PACKAGE+'-0.1.0a1'


def run(args,**kwargs):
    return subprocess.check_output([str(a) for a in args],text=True,encoding='utf-8',**kwargs)


def environment(path):
    venv.EnvBuilder(with_pip=True).create(path)
    return path/('Scripts/python.exe' if os.name=='nt' else 'bin/python')


def check_wheel(path):
    with zipfile.ZipFile(path) as archive:
        expected={PACKAGE+'/'+name+'.py' for name in MODULES}
        expected|={DIST+'.dist-info/'+name for name in ('METADATA','WHEEL','top_level.txt','RECORD','licenses/LICENSE')}
        assert set(archive.namelist())==expected, sorted(set(archive.namelist())^expected)
        metadata=BytesParser().parsebytes(archive.read(DIST+'.dist-info/METADATA'))
        assert metadata['Name']=='zrotext-native-candidate' and metadata['Version']=='0.1.0a1'
        assert metadata['Requires-Python']=='>=3.12' and metadata['License-Expression']=='AGPL-3.0-only'
        assert set(metadata.get_all('Requires-Dist'))=={'cryptography==50.0.2','cffi==2.1.1','pycparser==3.11'}
        assert archive.read(DIST+'.dist-info/licenses/LICENSE')==ROOT.joinpath('LICENSE').read_bytes()


def check_sdist(path):
    with tarfile.open(path) as archive:
        files={m.name for m in archive.getmembers() if m.isfile()}
        expected={DIST+'/'+PACKAGE+'/'+name+'.py' for name in MODULES}
        expected|={DIST+'/'+name for name in ('LICENSE','README.md','pyproject.toml','MANIFEST.in','PKG-INFO','setup.cfg')}
        expected|={DIST+'/'+PACKAGE+'.egg-info/'+name for name in ('PKG-INFO','SOURCES.txt','dependency_links.txt','requires.txt','top_level.txt')}
        assert files==expected, sorted(files^expected)
        assert not any(m.issym() or m.islnk() for m in archive.getmembers())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='zrotext-native-package-') as directory:
        temporary=Path(directory);source=temporary/'source';source.mkdir()
        for name in ('LICENSE','README.md','pyproject.toml','MANIFEST.in'):
            shutil.copyfile(ROOT/name,source/name)
        shutil.copytree(ROOT/PACKAGE,source/PACKAGE,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        builder=environment(temporary/'builder')
        run([builder,'-m','pip','install','setuptools==84.0.0'],cwd=temporary)
        run([builder,'-c',"from setuptools.build_meta import build_wheel,build_sdist;build_wheel('dist');build_sdist('dist')"],cwd=source)
        wheel=next((source/'dist').glob('*.whl'));sdist=next((source/'dist').glob('*.tar.gz'))
        check_wheel(wheel);check_sdist(sdist)
        fixtures={name:json.loads(run(['node',ROOT/producer],cwd=temporary)) for name,producer in
                  (('archive','produce-fixture.mjs'),('election','produce-election03.mjs'),('selection','produce-selected-reply02.mjs'))}
        fixtures['rotation']=json.loads((ROOT.parents[3]/'sdk/typescript/test/vectors/draft02-rotation.json').read_text())
        consumer=temporary/'consumer.py';shutil.copyfile(ROOT/'installed_consumer.py',consumer)
        for index,artifact in enumerate((wheel,sdist)):
            python=environment(temporary/f'consumer-{index}')
            run([python,'-m','pip','install',artifact],cwd=temporary)
            run([python,'-m','pip','check'],cwd=temporary)
            result=json.loads(run([python,'-I',consumer],cwd=temporary,input=json.dumps(fixtures)))
            payload=json.dumps(dict(fixture=fixtures['election'],envelope=result['envelope'],expectedText='Native composed 🌱'))
            accepted=json.loads(run(['node',ROOT/'consume-native03.mjs'],cwd=temporary,input=payload))
            assert result['installed'] and accepted=={'verified':True,'openedRecipients':2}
            payload02=json.dumps(dict(fixture=fixtures['archive'],envelope=result['envelope02'],expectedText='Native composed02 🌱'))
            assert json.loads(run(['node',ROOT/'consume-native02.mjs'],cwd=temporary,input=payload02))=={'verified':True,'openedRecipients':2}
        shutil.copyfile(wheel,args.output/wheel.name);shutil.copyfile(sdist,args.output/sdist.name)
    print(json.dumps({'wheel_and_sdist':'passed','isolated_consumers':2,'installed_crypto_and_durability':'passed'}))


if __name__=='__main__':main()
