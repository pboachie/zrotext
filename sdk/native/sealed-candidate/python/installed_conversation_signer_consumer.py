"""Installed package + maintained transcript/HPKE acceptance; synthetic host only."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from zrotext_native_candidate import conversation_signer as c
from zrotext_native_candidate import sealed_candidate as s


def oracle(source, mode=None, value=None):
    return json.loads(subprocess.check_output(['node',str(source)]+([mode] if mode else []),
        input=None if value is None else json.dumps(value),encoding='utf-8'))


def inputs(f):
    d=base64.b64decode
    pin=s.enroll_root02(d(f['rootPin']),d(f['fingerprint']))
    manifest=s.verify_manifest02(d(f['manifest']),pin,10000)
    binding={k:d(f[k]) for k in ('account','device','line','phoneReader')}
    binding.update(interval=bytes([9])*16,session=bytes([8])*16,generation=3,peer='+12',archiveReader=d(f['reader']))
    return pin,dict(binding=binding,manifest=manifest,nowMs=10000,ownerSessionLive=True,consentLive=True)


def enroll(source,f,client,pin,current):
    value=oracle(source,'--enroll',dict(fixture=f,point=base64.b64encode(client.public_point).decode()))
    high=s.advance_trust02(pin,current['manifest'])
    current['manifest']=s.verify_manifest02(base64.b64decode(value['manifest']),high,10000)


def check(source,hardware=False):
    f=oracle(source);pin,current=inputs(f);events=[]
    receipt=None
    if hardware:
        fd,name=tempfile.mkstemp(prefix='zrotext-conversation-key-',suffix='.jsonl');os.close(fd);receipt=Path(name)
    def record(kind,alias):
        if receipt:
            with receipt.open('a',encoding='utf-8') as stream:
                stream.write(json.dumps(dict(kind=kind,alias=alias))+'\n');stream.flush();os.fsync(stream.fileno())
        events.append((kind,alias))
    client=c.ConversationSignerSetup02(current['binding'],lambda b:False,lambda:current,
        record_pending_alias=lambda a:record('pending',a),record_deleted_alias=lambda a:record('deleted',a),require_hardware=hardware)
    try:
        client.setup();point=client.public_point
        enroll(source,f,client,pin,current)
        review=client.prepare_review('Session review 🌱')
        seen=[];signature=client.sign_reviewed(review['proof'],review['envelope'],review['body'],lambda p,b:seen.append((p,b)))
        assert seen==[(s.sha(review['proof']),s.sha(review['body'].encode()))]
        b64=lambda v:base64.b64encode(v).decode()
        result=oracle(source,'--consume',dict(fixture=f,point=b64(point),proof=b64(review['proof']),envelope=b64(review['envelope']),signature=b64(signature),text=review['body']))
        assert result==dict(verified=True,openedRecipients=2,confirmation=True)
        if hardware:
            try:client._key.sign('ZTSE/sign/v2',review['envelope'][:-64])
            except c.ConversationSignerError:pass
            else:raise AssertionError('generic signing admitted')
    finally:
        client.close()
        assert not client.cleanup_pending
    if hardware:
        assert len(events)==2 and events[0][0]=='pending' and events[1]==('deleted',events[0][1])
        receipt.unlink()
    return dict(installed=True,protected=hardware,openedRecipients=2,confirmation=True)


if __name__=='__main__':
    assert str(Path(c.__file__).resolve()).startswith(str(Path(sys.prefix).resolve())),c.__file__
    source=Path(sys.argv[1]);software=check(source)
    protected=check(source,True) if os.name=='nt' else None
    print(json.dumps(dict(software=software,protected=protected)))
