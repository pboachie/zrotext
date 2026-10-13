"""Installed enrollment signatures checked by the maintained verifier."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate import enrollment_ceremony as e

def material(f):
    d=base64.b64decode;pin=s.enroll_root02(d(f['rootPin']),d(f['fingerprint']));manifest=s.verify_manifest02(d(f['manifest']),pin,f['now'])
    binding={k:v if k in ('peer','generation') else d(v) for k,v in f['binding'].items()}
    return binding,manifest,d(f['point'])

def provision(f,signer,protected,producer):
    binding,manifest,point=material(f);current=dict(binding=binding,manifest=manifest,nowMs=f['now'],ownerSessionLive=True,consentLive=True);events=[];installed=[]
    def decide(review):
        assert review['unsigned']==base64.b64decode(f['review']['unsigned']);events.append('review')
    def install(expected,accepted,highwater,bound):
        assert events==['review'] and expected==s._bound(s._manifests,manifest).trust.digest
        assert s._bound(s._trusts,highwater)==s._bound(s._manifests,accepted).trust and dict(bound)==binding
        events.append('install');installed.append(accepted)
    flow=e.ConversationEnrollment(binding,point,signer=signer,read_current=lambda:current,consume_owner_decision=decide,install_verified=install,require_protected=protected)
    accepted=flow.enroll();assert accepted is installed[0] and events==['review','install']
    # Maintained contract returns verified successor, with no readback or unlock.
    assert current['manifest'] is manifest
    raw=s._bound(s._manifests,accepted).raw
    result=json.loads(subprocess.check_output(['node',str(producer),'--consume'],input=json.dumps(dict(fixture=f,signed=base64.b64encode(raw).decode())),encoding='utf-8'))
    assert result['verified'];flow.close()

def check(f,producer):
    provision(f,e.SoftwareEnrollmentRootSigner(ec.derive_private_key(7,ec.SECP256R1())),False,producer)
    protected=False;skipped=0
    if os.name=='nt':
        from zrotext_native_candidate.cng_custody import probe_platform,CngUnavailable
        try:probe_platform()
        except CngUnavailable:skipped=1
        else:
            fd,path=tempfile.mkstemp(prefix='zrotext-enrollment-key-',suffix='.json');os.close(fd)
            def receipt(value):
                with open(path,'w',encoding='utf-8') as stream:json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
            key=e.EnrollmentRootSigner.create(lambda name:receipt(dict(pending_alias=name)))
            try:
                setup=json.loads(subprocess.check_output(['node',str(producer),'--root-point',key.public_point().hex()],encoding='utf-8'));unsigned=base64.b64decode(setup.pop('unsigned'))
                # Test-only predecessor provisioning uses a private crypto primitive.
                # This is not an enrollment capability or generic public signer.
                signature=key._sign_digest(s.sha(s.label('ZTSE/manifest/v2')+len(unsigned).to_bytes(4,'big')+unsigned));setup['manifest']=base64.b64encode(unsigned+signature).decode()
                fixture=json.loads(subprocess.check_output(['node',str(producer),'--fixture'],input=json.dumps(setup),encoding='utf-8'))
                binding,manifest,point=material(fixture);review,_=e._review(manifest,binding,point,fixture['now'])
                for raw in (unsigned,review['unsigned']):
                    try:key.sign('ZTSE/manifest/v2',raw)
                    except s.SealedError:pass
                    else:raise AssertionError('generic signing accepted')
                bad=dict(review);bad['unsigned']=unsigned
                try:key._sign_enrollment(bad,manifest,fixture['now'])
                except s.SealedError:pass
                else:raise AssertionError('genesis accepted by enrollment capability')
                bad=dict(review);bad['predecessorDigest']=bytes(32)
                try:key._sign_enrollment(bad,manifest,fixture['now'])
                except s.SealedError:pass
                else:raise AssertionError('wrong predecessor accepted')
                provision(fixture,key,True,producer);protected=True
                with e.EnrollmentRootSigner.open(key.name,key.public_point()) as reopened:
                    effects=[];state=dict(binding=binding,manifest=manifest,nowMs=fixture['now'],ownerSessionLive=True,consentLive=True)
                    flow=e.ConversationEnrollment(binding,point,signer=reopened,read_current=lambda:state,consume_owner_decision=lambda review:reopened.close(),install_verified=lambda *args:effects.append('install'))
                    try:flow.enroll()
                    except e.EnrollmentError as error:assert error.state=='refused'
                    else:raise AssertionError('revoked custody accepted')
                    assert not effects
            finally:key.delete();receipt(dict(owned_test_key_deleted=True))
    else:skipped=1
    return dict(installed=True,enrollment_verified=True,protected_enrollment=protected,skipped=skipped)

if __name__=='__main__':
    import zrotext_native_candidate as package
    assert Path(package.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    print(json.dumps(check(json.load(sys.stdin),Path(sys.argv[1]))))
