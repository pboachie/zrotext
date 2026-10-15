"""Clean installed genesis signer/ceremony and independent maintained readback."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate.genesis_ceremony import ConversationGenesis,GenesisRootSigner,SoftwareGenesisRootSigner,GenesisCeremonyError

def material(f):
    value=dict(f['input']);value['selection']=dict(value['selection'])
    for key in ('rootPin','comparedRootFingerprint','phoneReaderPoint','archiveReaderPoint','phoneSignerPoint'):value[key]=base64.b64decode(value[key])
    for key in ('account','session','device','line','phoneSigningFingerprint'):value['selection'][key]=base64.b64decode(value['selection'][key])
    return value

def provision(f,signer,protected,producer):
    value=material(f);state=dict(selection=dict(value['selection']),rootPin=value['rootPin'],nowMs=value['nowMs'],version=0,manifest=None,ownerSessionLive=True,authorityLive=True,deviceKeyLive=True,lineBindingLive=True);effects=[]
    def decide(review):
        assert review['unsigned']==base64.b64decode(f['review']['unsigned']);effects.append('review')
    def install(raw,current):
        assert effects==['review'] and current['version']==0
        effects.append('install');state.update(version=1,manifest=raw)
    flow=ConversationGenesis(value,signer=signer,read_current=lambda:state,consume_owner_decision=decide,install=install,require_protected=protected)
    flow.provision();assert effects==['review','install']
    result=json.loads(subprocess.check_output(['node',str(producer),'--consume'],input=json.dumps(dict(input=f['input'],signed=base64.b64encode(state['manifest']).decode())),encoding='utf-8'))
    assert result['verified'];flow.close()

def check(f,producer):
    scalar=int.from_bytes(base64.b64decode(f['scalar']),'big');signer=SoftwareGenesisRootSigner(ec.derive_private_key(scalar,ec.SECP256R1()))
    provision(f,signer,False,producer)
    protected=False;skipped=0
    if os.name=='nt':
        from zrotext_native_candidate.cng_custody import probe_platform,CngUnavailable
        try:probe_platform()
        except CngUnavailable:skipped=1
        else:
            fd,path=tempfile.mkstemp(prefix='zrotext-genesis-key-',suffix='.json');os.close(fd)
            def receipt(value):
                with open(path,'w',encoding='utf-8') as stream:json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
            key=GenesisRootSigner.create(lambda name:receipt(dict(pending_alias=name)))
            try:
                fixture=json.loads(subprocess.check_output(['node',str(producer),'--root-point',key.public_point().hex()],encoding='utf-8'));assert 'scalar' not in fixture
                provision(fixture,key,True,producer);protected=True
            finally:key.delete();receipt(dict(owned_test_key_deleted=True))
    else:skipped=1
    return dict(installed=True,genesis_verified=True,protected_genesis=protected,skipped=skipped)

if __name__=='__main__':
    import zrotext_native_candidate as package
    assert Path(package.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    print(json.dumps(check(json.load(sys.stdin),Path(sys.argv[1]))))
