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
MODULES={'__init__','sealed_candidate','checkpoint_store','cng_custody','cng_signing','election03','election_journal','compose03','compose02','outbound_journal','root_checkpoint','reply_selection','outbound02_journal','sealed_http','original_reply_reader','original_reply_client','original_reply_checkpoint','encrypted_template','contact_integrity'}
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
        assert set(metadata.get_all('Requires-Dist'))=={'cryptography==50.0.2','cffi==2.1.1','pycparser==3.11','zrotext-workflow-candidate==0.1.0a1; extra == "workflow"'}
        assert metadata['Provides-Extra']=='workflow'
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
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--workflow-source',type=Path,required=True)
    parser.add_argument('--time-policy-source',type=Path,required=True);args=parser.parse_args()
    time_cli=args.time_policy_source.resolve()/'sdk/typescript/test/fixtures/profile03-time-cli.mjs'
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
        workflow_output=temporary/'workflow';workflow_output.mkdir()
        run([builder,'-m','pip','wheel','--no-deps','--wheel-dir',workflow_output,args.workflow_source.resolve()],cwd=temporary)
        workflow_wheel=next(workflow_output.glob('zrotext_workflow_candidate-0.1.0a1-*.whl'))
        fixtures={name:json.loads(run(['node',ROOT/producer],cwd=temporary)) for name,producer in
                  (('archive','produce-fixture.mjs'),('election','produce-election03.mjs'),('selection','produce-selected-reply02.mjs'),('template','template-interop.mjs'),('contact','contact-interop.mjs'))}
        fixtures['rotation']=json.loads((ROOT.parents[3]/'sdk/typescript/test/vectors/draft02-rotation.json').read_text())
        consumer=temporary/'consumer.py';shutil.copyfile(ROOT/'installed_consumer.py',consumer)
        http_consumer=temporary/'http_consumer.py';shutil.copyfile(ROOT/'installed_http_consumer.py',http_consumer)
        reply_consumer=temporary/'reply_consumer.py';shutil.copyfile(ROOT/'installed_reply_consumer.py',reply_consumer)
        template_consumer=temporary/'template_consumer.py';shutil.copyfile(ROOT/'installed_template_consumer.py',template_consumer)
        contact_consumer=temporary/'contact_consumer.py';shutil.copyfile(ROOT/'installed_contact_consumer.py',contact_consumer)
        time_consumer=temporary/'time_consumer.py';shutil.copyfile(ROOT/'installed_time_consumer.py',time_consumer)
        time_cases=json.loads(run(['node',time_cli,'--reader-cases'],cwd=temporary))
        assert len(time_cases['cases'])==14
        for index,artifact in enumerate((wheel,sdist)):
            python=environment(temporary/f'consumer-{index}')
            run([python,'-m','pip','install',artifact],cwd=temporary)
            run([python,'-I','-c',"import zrotext_native_candidate,importlib.util;assert importlib.util.find_spec('zrotext_workflow') is None"],cwd=temporary)
            assert json.loads(run([python,'-I',contact_consumer],cwd=temporary,input=json.dumps(fixtures['contact'])))==dict(installed=True,historical_contact_integrity=True)
            time_result=json.loads(run([python,'-I',time_consumer],cwd=temporary,input=json.dumps(time_cases)))
            assert time_result['installed'] and len(time_result['outputs'])==sum(f['accept'] for f in time_cases['cases'])
            for output in time_result['outputs']:
                assert json.loads(run(['node',time_cli,'--consume'],cwd=temporary,input=json.dumps(output)))==dict(verified=True,name=output['fixture']['name'],recipients=3)
            template_result=json.loads(run([python,'-I',template_consumer],cwd=temporary,input=json.dumps(fixtures['template'])))
            template_open=json.loads(run(['node',ROOT/'template-interop.mjs','--consume'],cwd=temporary,
                input=json.dumps(dict(fixture=fixtures['template'],envelope=template_result['envelope'],expectedCanonical=template_result['canonical']))))
            assert template_result['installed'] and template_open['verified'] and template_open['preview']==fixtures['template']['preview']
            base_reply=json.loads(run([python,'-I',reply_consumer,'--without-workflow'],cwd=temporary,input=json.dumps(fixtures['selection'])))
            assert base_reply==dict(installed=True,workflow_coinstalled=False,original_reply_https=True)
            run([python,'-m','pip','install',workflow_wheel],cwd=temporary)
            run([python,'-m','pip','check'],cwd=temporary)
            result=json.loads(run([python,'-I',consumer],cwd=temporary,input=json.dumps(fixtures)))
            payload=json.dumps(dict(fixture=fixtures['election'],envelope=result['envelope'],expectedText='Native composed 🌱'))
            accepted=json.loads(run(['node',ROOT/'consume-native03.mjs'],cwd=temporary,input=payload))
            assert result['installed'] and accepted=={'verified':True,'openedRecipients':2}
            payload02=json.dumps(dict(fixture=fixtures['archive'],envelope=result['envelope02'],expectedText='Native composed02 🌱'))
            assert json.loads(run(['node',ROOT/'consume-native02.mjs'],cwd=temporary,input=payload02))=={'verified':True,'openedRecipients':2}
            http_result=json.loads(run([python,'-I',http_consumer],cwd=temporary,input=json.dumps({'envelope':result['envelope02']})))
            assert http_result==dict(installed=True,https_requests=4,exact_ciphertext_replay=True)
            reply_result=json.loads(run([python,'-I',reply_consumer],cwd=temporary,input=json.dumps(fixtures['selection'])))
            assert reply_result==dict(installed=True,workflow_coinstalled=True,original_reply_https=True)
        shutil.copyfile(wheel,args.output/wheel.name);shutil.copyfile(sdist,args.output/sdist.name)
    print(json.dumps({'wheel_and_sdist':'passed','isolated_consumers':2,'installed_crypto_and_durability':'passed'}))


if __name__=='__main__':main()
