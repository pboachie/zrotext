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
MODULES={'__init__','sealed_candidate','checkpoint_store','cng_custody','cng_signing','election03','election_journal','compose03','compose02','outbound_journal','root_checkpoint','reply_selection','outbound02_journal','sealed_http','original_reply_reader','original_reply_client','original_reply_checkpoint','encrypted_template','contact_integrity','contact_history','contact_producer','workflow_context','sealed_lifecycle','template_store','owner_template','owner_template_save','owner_context','template_authoring','template_opening','conversation_proposals','genesis_ceremony'}
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
        assert set(metadata.get_all('Requires-Dist'))=={'cryptography==50.0.2','cffi==2.1.1','pycparser==3.11','ada-url==1.27.0','zrotext-workflow-candidate==0.1.0a1; extra == "workflow"'}
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
        store_consumer=temporary/'store_consumer.py';shutil.copyfile(ROOT/'installed_template_store_consumer.py',store_consumer)
        template_consumer=temporary/'template_consumer.py';shutil.copyfile(ROOT/'installed_template_consumer.py',template_consumer)
        contact_consumer=temporary/'contact_consumer.py';shutil.copyfile(ROOT/'installed_contact_consumer.py',contact_consumer)
        producer_consumer=temporary/'producer_consumer.py';shutil.copyfile(ROOT/'installed_contact_producer_consumer.py',producer_consumer)
        lifecycle_consumer=temporary/'installed_lifecycle_consumer.py';shutil.copyfile(ROOT/'installed_lifecycle_consumer.py',lifecycle_consumer)
        owner_consumer=temporary/'installed_owner_template_consumer.py';shutil.copyfile(ROOT/'installed_owner_template_consumer.py',owner_consumer)
        owner_save_consumer=temporary/'owner_save_consumer.py';shutil.copyfile(ROOT/'installed_owner_template_save_consumer.py',owner_save_consumer)
        genesis_consumer=temporary/'genesis_consumer.py';shutil.copyfile(ROOT/'installed_genesis_ceremony_consumer.py',genesis_consumer)
        genesis_fixture=json.loads(run(['node',ROOT/'genesis-ceremony-interop.mjs'],cwd=temporary))
        proposal_consumer=temporary/'proposal_consumer.py';shutil.copyfile(ROOT/'installed_conversation_proposals_consumer.py',proposal_consumer)
        proposal_fixture=json.loads(run(['node',ROOT/'conversation-proposals-interop.mjs'],cwd=temporary))
        opening_consumer=temporary/'opening_consumer.py';shutil.copyfile(ROOT/'installed_template_opening_consumer.py',opening_consumer)
        authoring_consumer=temporary/'authoring_consumer.py';shutil.copyfile(ROOT/'installed_template_authoring_consumer.py',authoring_consumer)
        owner_context_consumer=temporary/'owner_context_consumer.py';shutil.copyfile(ROOT/'installed_owner_context_consumer.py',owner_context_consumer)
        owner_context_fixture=json.loads(run(['node',ROOT/'owner-context-interop.mjs'],cwd=temporary))
        owner_fixture=json.loads(run(['node',ROOT/'owner-template-interop.mjs'],cwd=temporary))
        context_consumer=temporary/'context_consumer.py';shutil.copyfile(ROOT/'installed_context_consumer.py',context_consumer)
        context_fixtures=[json.loads(run(['node',ROOT/'workflow-context-interop.mjs',str(role)],cwd=temporary)) for role in (2,3)]
        time_consumer=temporary/'time_consumer.py';shutil.copyfile(ROOT/'installed_time_consumer.py',time_consumer)
        time_cases=json.loads(run(['node',time_cli,'--reader-cases'],cwd=temporary))
        assert len(time_cases['cases'])==14
        opening_qualifications=[]
        genesis_qualifications=[]
        for index,artifact in enumerate((wheel,sdist)):
            python=environment(temporary/f'consumer-{index}')
            run([python,'-m','pip','install',artifact],cwd=temporary)
            run([python,'-I','-c',"import zrotext_native_candidate,importlib.util;assert importlib.util.find_spec('zrotext_workflow') is None"],cwd=temporary)
            assert json.loads(run([python,'-I',contact_consumer],cwd=temporary,input=json.dumps(fixtures['contact'])))==dict(installed=True,historical_contact_integrity=True)
            produced=json.loads(run([python,'-I',producer_consumer],cwd=temporary,input=json.dumps(fixtures['contact'])))
            accepted_contact=json.loads(run(['node',ROOT/'contact-producer-interop.mjs'],cwd=temporary,input=json.dumps(produced)))
            assert accepted_contact['verified'] and accepted_contact['fields']==3 and accepted_contact['transitions']==4
            time_result=json.loads(run([python,'-I',time_consumer],cwd=temporary,input=json.dumps(time_cases)))
            assert time_result['installed'] and len(time_result['outputs'])==sum(f['accept'] for f in time_cases['cases'])
            for output in time_result['outputs']:
                assert json.loads(run(['node',time_cli,'--consume'],cwd=temporary,input=json.dumps(output)))==dict(verified=True,name=output['fixture']['name'],recipients=3)
            template_result=json.loads(run([python,'-I',template_consumer],cwd=temporary,input=json.dumps(fixtures['template'])))
            template_open=json.loads(run(['node',ROOT/'template-interop.mjs','--consume'],cwd=temporary,
                input=json.dumps(dict(fixture=fixtures['template'],envelope=template_result['envelope'],expectedCanonical=template_result['canonical']))))
            assert template_result['installed'] and template_open['verified'] and template_open['preview']==fixtures['template']['preview']
            assert json.loads(run([python,'-I',lifecycle_consumer],cwd=temporary))==dict(installed=True,real_tls_groups=5)
            for context_fixture in context_fixtures:
                context_result=json.loads(run([python,'-I',context_consumer],cwd=temporary,input=json.dumps(context_fixture)))
                context_open=json.loads(run(['node',ROOT/'workflow-context-interop.mjs','--consume'],cwd=temporary,input=json.dumps(dict(fixture=context_fixture,envelope=context_result['envelope'],plaintext=context_fixture['plaintext']))))
                assert context_result['installed'] and context_open['verified'] and context_open['role']==context_fixture['role']
            genesis_result=json.loads(run([python,'-I',genesis_consumer,ROOT/'genesis-ceremony-interop.mjs'],cwd=temporary,input=json.dumps(genesis_fixture)))
            assert genesis_result['installed'] and genesis_result['genesis_verified']
            genesis_qualifications.append(genesis_result)
            proposal_result=json.loads(run([python,'-I',proposal_consumer],cwd=temporary,input=json.dumps(proposal_fixture)))
            assert proposal_result==dict(installed=True,typed_proposals=3,public_comparisons=2)
            opening_result=json.loads(run([python,'-I',opening_consumer,ROOT/'owner-template-interop.mjs'],cwd=temporary,input=json.dumps(owner_fixture)))
            assert opening_result['installed'] and opening_result['template_opening_tls']==7
            opening_qualifications.append(dict(protected_opening=opening_result['protected_opening'],skipped=opening_result['skipped']))
            authoring_result=json.loads(run([python,'-I',authoring_consumer],cwd=temporary,input=json.dumps(owner_fixture)))
            assert authoring_result['installed'] and authoring_result['template_authoring_tls']==3
            authoring_open=json.loads(run(['node',ROOT/'template-interop.mjs','--consume'],cwd=temporary,input=json.dumps(dict(fixture=owner_fixture,envelope=authoring_result['envelope'],expectedCanonical=owner_fixture['canonical']))))
            assert authoring_open['verified']
            owner_context_result=json.loads(run([python,'-I',owner_context_consumer],cwd=temporary,input=json.dumps(owner_context_fixture)))
            assert owner_context_result['installed'] and owner_context_result['owner_context_tls']==9
            owner_context_open=json.loads(run(['node',ROOT/'workflow-context-interop.mjs','--consume'],cwd=temporary,input=json.dumps(dict(fixture=owner_context_fixture,envelope=owner_context_result['envelope'],plaintext=owner_context_fixture['plaintext']))))
            assert owner_context_open['verified'] and owner_context_open['role']==2
            owner_save_result=json.loads(run([python,'-I',owner_save_consumer],cwd=temporary,input=json.dumps(owner_fixture)))
            assert owner_save_result==dict(installed=True,owner_template_save_tls=10)
            owner_result=json.loads(run([python,'-I',owner_consumer],cwd=temporary,input=json.dumps(owner_fixture)))
            assert owner_result==dict(installed=True,owner_template_tls=5)
            store_result=json.loads(run([python,'-I',store_consumer],cwd=temporary,input=json.dumps(fixtures['template'])))
            store_case=dict(scope=fixtures['template']['scope'],requestId='00000000-0000-0000-0000-000000000041',expectedRevision=0,envelope=store_result['request']['body'])
            store_accepted=json.loads(run(['node',ROOT/'template-store-interop.mjs'],cwd=temporary,input=json.dumps([store_case])))
            assert store_result['installed'] and store_accepted==[dict(accepted=True,value=store_result['request'])]
            store_open=json.loads(run(['node',ROOT/'template-interop.mjs','--consume'],cwd=temporary,input=json.dumps(dict(fixture=fixtures['template'],envelope=store_result['request']['body'],expectedCanonical=fixtures['template']['canonical']))))
            assert store_open['verified']
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
    print(json.dumps({'wheel_and_sdist':'passed','isolated_consumers':2,'installed_crypto_and_durability':'passed','template_opening':opening_qualifications,'genesis':genesis_qualifications}))


if __name__=='__main__':main()
