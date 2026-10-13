"""Normal installed imports and exact independently produced public proposal bytes."""
import base64
import json
from pathlib import Path
import sys
from collections.abc import Mapping
from zrotext_native_candidate import conversation_proposals as p
from zrotext_native_candidate import sealed_candidate as s

def decode(value):
    numeric={'generation','nowMs','expiresMs','successorVersion','untilMs'}
    return {key:item if key in numeric or key in ('origin','peer') else decode(item) if type(item) is dict else base64.b64decode(item,validate=True) for key,item in value.items()}
def encode(value):
    return base64.b64encode(value).decode() if type(value) is bytes else {k:encode(v) for k,v in value.items()} if isinstance(value,Mapping) else value

def inputs(f):
    manifest=s.verify_manifest02(base64.b64decode(f['manifest']),s.enroll_root02(base64.b64decode(f['rootPin']),base64.b64decode(f['fingerprint'])),f['now'])
    values={name:decode(f[name]) for name in ('genesis','activation','refresh')}
    values['activation']['predecessor']=manifest;values['refresh']['predecessor']=manifest
    return values

def invoke(name,value):
    common=(value['origin'],value['comparedRootFingerprint'],value['nowMs'])
    if name=='activation':return p.encode_conversation_activation_proposal02(value['selection'],value['predecessor'],*common)
    if name=='refresh':return p.encode_conversation_refresh_proposal02(value['review'],value['predecessor'],*common)
    return p.encode_conversation_genesis_proposal02(value['selection'],value['rootPin'],value['comparedRootFingerprint'],value['origin'],value['phoneReaderPoint'],value['archiveReaderPoint'],value['phoneSignerPoint'],value['nowMs'],value['expiresMs'])

def check(f):
    values=inputs(f)
    for name,value in values.items():assert encode(invoke(name,value))==f['expected'][name]
    d=base64.b64decode;v=values['genesis'];assert encode(p.verify_phone_key_export02(d(f['phone']),v['selection'],d(f['phoneFingerprint'])))==f['verifiedPhone']
    assert encode(p.verify_archive_public_header02(d(f['archive']),v['selection']['account'],v['comparedRootFingerprint'],v['origin'],values['activation']['selection']['archiveReader']))==f['verifiedArchive']
    return dict(installed=True,typed_proposals=3,public_comparisons=2)

if __name__=='__main__':
    import zrotext_native_candidate as n
    assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    print(json.dumps(check(json.load(sys.stdin))))
