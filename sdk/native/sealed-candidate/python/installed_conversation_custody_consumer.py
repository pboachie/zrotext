"""Independent maintained signatures and installed native custody composition."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from cryptography.hazmat.primitives.asymmetric import ec
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate.conversation_custody import ConversationCustody02
from zrotext_native_candidate.enrollment_ceremony import EnrollmentRootSigner,SoftwareEnrollmentRootSigner,enrollment_installation
from zrotext_native_candidate.checkpoint_store import CheckpointStore


def oracle(source,mode=None,value=None):
    return json.loads(subprocess.check_output(['node',str(source)]+([mode] if mode else []),
        input=None if value is None else json.dumps(value),encoding='utf-8'))


def inputs(f):
    d=base64.b64decode;pin=s.enroll_root02(d(f['rootPin']),d(f['fingerprint']))
    current=s.verify_manifest02(d(f['manifest']),pin,f['now'])
    binding={k:d(f[k]) for k in ('account','device','line','phoneReader')}
    binding.update(interval=bytes([9])*16,session=bytes([8])*16,generation=3,peer='+12',archiveReader=d(f['reader']))
    return dict(binding=binding,manifest=current,nowMs=f['now'],ownerSessionLive=True,consentLive=True)


class Session:
    def __init__(self,f,*,archive=None,root=None,protected=False,record=lambda kind,alias:None,overrides=None):
        self.f=f;self.current=inputs(f);self.events=dict(setup=0,owner=0,install=0,confirmation=0);self.signed=None
        self.temporary=tempfile.TemporaryDirectory(prefix='zrotext-custody-cas-');d=base64.b64decode
        self.store=CheckpointStore(Path(self.temporary.name)/'checkpoint.db',d(f['rootPin']),d(f['fingerprint']))
        self.store.accept_manifest(d(f['manifest']),0,f['now'])
        def setup(_):self.events['setup']+=1
        def owner(_):self.events['owner']+=1
        def install(expected,accepted,high,binding):
            assert expected==s.manifest_identity(self.current['manifest'])['digest'] and dict(binding)==self.current['binding']
            self.events['install']+=1;evidence=enrollment_installation(accepted,high);self.signed=evidence['manifest']
            _,self.current['manifest']=self.store.accept_manifest(self.signed,1,self.current['nowMs'])
        def confirm(proof,body):self.events['confirmation']+=1
        options=dict(archive_custody=archive or s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(d(f['archiveScalar']),'big'),ec.SECP256R1())),
            root_signer=root or SoftwareEnrollmentRootSigner(ec.derive_private_key(7,ec.SECP256R1())),read_current=lambda:self.current,
            consume_setup_decision=setup,consume_owner_decision=owner,install_verified=install,consume_confirmation=confirm,
            record_pending_alias=lambda a:record('pending',a),record_deleted_alias=lambda a:record('deleted',a),
            history_store=self.store,require_protected=protected)
        options.update(overrides or {});self.client=ConversationCustody02(self.current['binding'],**options)

    def close(self):
        self.client.close()
        for _ in range(500):
            if not self.client._busy:break
            time.sleep(.01)
        assert not self.client._busy
        if self.client.cleanup_pending:self.client.cleanup(timeout=5)
        assert not self.client.cleanup_pending
        self.temporary.cleanup()


def exercise(f,source,**options):
    session=Session(f,**options);client=session.client
    try:
        client.setup();authority=client.authority();scope=authority['scope'];text='Scope-bound native 🌱'
        ticket=client.prepare(scope,text);output=client.sign_reviewed(ticket,scope,text)
        result=oracle(source,'--consume',dict(fixture=f,manifest=base64.b64encode(session.signed).decode(),text=text,**dict(output)))
        assert result==dict(verified=True,openedRecipients=1 if options.get('protected') else 2,confirmation=True)
        assert client.open_sealed(base64.b64decode(f['inbound']),scope)==f['text']
        # Independently re-open retained evidence through the public store API.
        old=session.store.history(s.sha(base64.b64decode(f['manifest'])[:-64]),f['now'])
        assert s.manifest_identity(old)['version']==1
        assert client.open_sealed(base64.b64decode(f['inbound']),scope)==f['text']
        assert session.events==dict(setup=1,owner=1,install=1,confirmation=1)
        try:client.sign_reviewed(ticket,scope,text)
        except Exception:pass
        else:raise AssertionError('one-use ticket replayed')
        return result
    finally:session.close()


def check(source):
    f=oracle(source);software=exercise(f,source);protected=None;skipped=0
    if os.name=='nt':
        from zrotext_native_candidate.cng_custody import probe_platform,CngUnavailable,HardwareRecipient
        try:probe_platform()
        except CngUnavailable:skipped=1
        else:
            fd,name=tempfile.mkstemp(prefix='zrotext-custody-owned-',suffix='.jsonl');os.close(fd);receipt=Path(name);events=[]
            def record(kind,alias):
                with receipt.open('a',encoding='utf-8') as stream:
                    stream.write(json.dumps(dict(kind=kind,alias=alias))+'\n');stream.flush();os.fsync(stream.fileno())
                events.append((kind,alias))
            root=archive=None
            try:
                root=EnrollmentRootSigner.create(lambda a:record('pending',a));archive=HardwareRecipient.create(lambda a:record('pending',a))
                material=oracle(source,'--material',dict(rootPoint=root.public_point().hex(),archivePoint=archive.public_point().hex()))
                unsigned=base64.b64decode(material.pop('unsigned'))
                # Test-only root provisioning; the public enrollment signer
                # continues refusing arbitrary/genesis transcript signing.
                signature=root._sign_digest(s.sha(s.label('ZTSE/manifest/v2')+len(unsigned).to_bytes(4,'big')+unsigned))
                material['manifest']=base64.b64encode(unsigned+signature).decode();f=oracle(source,'--fixture',material)
                assert 'archiveScalar' not in f
                protected=exercise(f,source,archive=archive,root=root,protected=True,record=record)
            finally:
                for key in (archive,root):
                    if key is not None:
                        alias=key.name;key.delete();record('deleted',alias)
            pending=[a for k,a in events if k=='pending'];deleted=[a for k,a in events if k=='deleted']
            assert len(pending)==3 and sorted(pending)==sorted(deleted)
            receipt.unlink()
    else:skipped=1
    return dict(installed=True,software=software,protected=protected,skipped=skipped)


if __name__=='__main__':
    import zrotext_native_candidate as package
    assert Path(package.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    print(json.dumps(check(Path(sys.argv[1]))))
