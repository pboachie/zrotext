"""Typed public conversation proposals; no signing, installation or consent."""
from functools import wraps
import re
from types import MappingProxyType
from . import sealed_candidate as s
from .contact_integrity import _origin

class ConversationProposalError(Exception):
    def __init__(self):super().__init__('Conversation proposal refused')

def _closed(fn):
    @wraps(fn)
    def call(*args,**kwargs):
        try:return fn(*args,**kwargs)
        except Exception:raise ConversationProposalError() from None
    return call

def _record(value,fields):
    s.require(type(value) is dict and set(value)==set(fields),'proposal fields');return dict(value)
def _bytes(value,size):
    value=s.capture(value,size);s.require(any(value),'proposal zero identity');return value
def _number(value):
    value=s.integer(value);s.require(value>0,'proposal number');return value
def _u64(value):return _number(value).to_bytes(8,'big')
def _sized(value):
    s.require(len(value)<=65535,'proposal size');return len(value).to_bytes(2,'big')+value

def _selection(value,kind):
    fields=['account','session','device','line','generation','peer']
    fields+=['phoneSigningFingerprint'] if kind=='genesis' else ['phoneReader','archiveReader','phoneSigner'] if kind=='activation' else ['interval','phoneReader','archiveReader']
    value=_record(value,fields)
    for k in fields:
        if k not in ('generation','peer'):value[k]=_bytes(value[k],32 if k.endswith('Reader') or k in ('phoneSigner','phoneSigningFingerprint') else 16)
    _number(value['generation']);s.require(type(value['peer']) is str and re.fullmatch(r'\+[1-9][0-9]{1,14}',value['peer']) is not None,'proposal peer')
    return value

def _predecessor(token,now,account,fingerprint):
    now=_number(now);original=s._bound(s._manifests,token)
    s.require(original.profile==2,'proposal predecessor profile')
    manifest=s._parse_manifest(original.raw,original.trust,now);identity=manifest.trust
    s.require(identity.generation==1 and identity.account==account,'proposal predecessor identity')
    pin=b'ZTRP\x02'+identity.account+_u64(identity.generation)+identity.root
    s.require(s.sha(s.label('ZTSE/root-pin/v2')+pin)==_bytes(fingerprint,32),'proposal compared root')
    return manifest

def _result(unsigned,proposal,issued,previous,version,expires=None):
    value=dict(unsigned=bytes(unsigned),proposal=bytes(proposal),issuedMs=issued,predecessorDigest=bytes(previous),successorVersion=version)
    if expires is not None:value['expiresMs']=expires
    return MappingProxyType(value)

@_closed
def verify_phone_key_export02(raw,selection,compared_fingerprint):
    raw=s.capture(raw,223);s.require(type(selection) is dict,'phone selection');fp=_bytes(compared_fingerprint,32)
    v={k:s.capture(selection[k],32 if k=='phoneSigningFingerprint' else 16) for k in ('account','device','line','phoneSigningFingerprint')}
    s.require(type(selection['generation']) is int,'phone generation');v['generation']=selection['generation']
    s.require(raw[:5]==b'ZTPK\x01' and raw[5:21]==v['account'] and raw[21:37]==v['device'] and raw[37:53]==v['line'] and raw[53:85]==v['phoneSigningFingerprint'] and int.from_bytes(raw[85:93],'big')==v['generation'] and s.sha(s.label('ZTSE/phone-keys/v1')+raw)==fp,'phone export comparison')
    return MappingProxyType(dict(phoneReaderPoint=raw[93:158],phoneSignerPoint=raw[158:223]))

@_closed
def verify_archive_public_header02(raw,account,root_fingerprint,origin,independent_archive_id):
    raw=s.capture(raw,333,845);account=s.capture(account,16);fingerprint=s.capture(root_fingerprint,32);archive=_bytes(independent_archive_id,32)
    s.require(type(origin) is str,'archive origin');site=origin.encode('utf-8');head=177+len(site)
    s.require(len(raw)==head+156 and raw[:6]==b'ZTAB\x01\x01' and raw[22:38]==account and s.num(raw,38)==1 and raw[46:78]==fingerprint and raw[78:110]==archive and s.num(raw,175,2)==len(site) and raw[177:head]==site and raw[head+104:head+108]==b'\0\0\0\x30' and s.sha(s.label('ZTSE/key/v1')+b'\0\x10'+raw[110:175])==archive,'archive public comparison')
    return raw[110:175]

@_closed
def encode_conversation_genesis_proposal02(selection,root_pin,compared_root_fingerprint,origin,phone_reader_point,archive_reader_point,phone_signer_point,now_ms,expires_ms):
    v=_selection(selection,'genesis');site=_origin(origin).encode('ascii');now=_number(now_ms);until=_number(expires_ms)
    s.require(now<until and until-now<=86400000,'genesis lifetime')
    pinraw=s.capture(root_pin,94);fingerprint=_bytes(compared_root_fingerprint,32);pin=s._bound(s._trusts,s.enroll_root02(pinraw,fingerprint))
    s.require(pin.account==v['account'],'genesis account')
    points=[s.capture(p,65) for p in (phone_reader_point,archive_reader_point,phone_signer_point,pin.root)]
    s.require(len(set(points))==4 and s.sha(points[2])==v['phoneSigningFingerprint'],'genesis points')
    records=[]
    for role,scope,point in zip((1,2,4,6),(4,12,2,0),points):
        s.point(point);bound=role in (1,4)
        records.append(bytes([role])+s.key_id(role,point)+point+(v['device'] if bound else bytes(16))+(v['line'] if bound else bytes(16))+scope.to_bytes(2,'big')+_u64(now)+_u64(until)+b'\x01')
    unsigned=b'ZTMA\x02'+v['account']+_u64(1)+_u64(1)+_u64(now)+_u64(until)+bytes(32)+pin.root+b'\x04'+b''.join(records)
    peer=v['peer'].encode('ascii')
    proposal=b'ZTCG\x01'+b''.join(v[k] for k in ('account','session','device','line','phoneSigningFingerprint'))+_u64(v['generation'])+bytes([len(peer)])+peer+_sized(site)+fingerprint+pinraw+_u64(now)+_u64(until)+_sized(unsigned)
    return _result(unsigned,proposal,now,bytes(32),1,until)

@_closed
def encode_conversation_activation_proposal02(selection,predecessor,origin,compared_root_fingerprint,now_ms):
    v=_selection(selection,'activation');site=_origin(origin).encode('ascii');now=_number(now_ms);fp=_bytes(compared_root_fingerprint,32)
    m=_predecessor(predecessor,now,v['account'],fp);identity=m.trust
    s.require(identity.version<s.MAX and now>=m.issued,'activation predecessor')
    for role,name in ((1,'phoneReader'),(2,'archiveReader'),(4,'phoneSigner')):
        keys=[k for k in m.keys if k.role==role and k.active(now) and (role==2 or (k.device==v['device'] and k.line==v['line']))]
        s.require(len(keys)==1 and keys[0].id==v[name],'activation current keys')
    unsigned=bytearray(m.raw[:-64]);unsigned[29:37]=_u64(identity.version+1);unsigned[37:45]=_u64(now);unsigned[53:85]=identity.digest
    peer=v['peer'].encode('ascii')
    proposal=b'ZTCA\x01'+b''.join(v[k] for k in ('account','session','device','line'))+_u64(v['generation'])+bytes([len(peer)])+peer+_sized(site)+fp+_u64(identity.version)+identity.digest+v['phoneReader']+v['archiveReader']+v['phoneSigner']+_u64(now)+_sized(m.raw)+_sized(unsigned)
    s.require(len(proposal)<=20480,'activation bound')
    return _result(unsigned,proposal,now,identity.digest,identity.version+1)

@_closed
def encode_conversation_refresh_proposal02(review,predecessor,origin,compared_root_fingerprint,now_ms):
    r=_record(review,('binding','publicPoint','keyId','predecessorDigest','successorVersion','untilMs','unsigned'));v=_selection(r['binding'],'refresh')
    point=s.capture(r['publicPoint'],65);signer=s.capture(r['keyId'],32);previous=s.capture(r['predecessorDigest'],32);unsigned=s.capture(r['unsigned'],151,9687)
    version=_number(r['successorVersion']);until=_number(r['untilMs']);now=_number(now_ms);fp=_bytes(compared_root_fingerprint,32);site=_origin(origin).encode('ascii')
    m=_predecessor(predecessor,now,v['account'],fp);identity=m.trust
    s.require(version==identity.version+1 and previous==identity.digest and signer==s.key_id(5,point),'refresh predecessor')
    issued=s.num(unsigned,37)
    s.require(m.issued<=issued<=now<until<=m.expires and until-issued<=1800000 and len(m.keys)<64 and all(k.id!=signer and k.point!=point for k in m.keys),'refresh lifetime/point')
    for role,name in ((1,'phoneReader'),(2,'archiveReader')):
        key=next((k for k in m.keys if k.role==role and k.id==v[name]),None)
        s.require(key is not None and key.active(now) and (role==2 or (key.device==v['device'] and key.line==v['line'])),'refresh reader')
    records=[m.raw[151+n*149:151+(n+1)*149] for n in range(len(m.keys))]
    records.append(b'\x05'+signer+point+bytes(16)+v['line']+b'\0\x01'+_u64(issued)+_u64(until)+b'\x01');records.sort(key=lambda record:record[:33])
    header=bytearray(m.raw[:151]);header[29:37]=_u64(version);header[37:45]=_u64(issued);header[53:85]=previous;header[150]=len(records)
    s.require(unsigned==bytes(header)+b''.join(records),'refresh unchanged authority')
    peer=v['peer'].encode('ascii')
    proposal=b'ZTCF\x01'+b''.join(v[k] for k in ('account','session','interval','device','line'))+_u64(v['generation'])+bytes([len(peer)])+peer+_sized(site)+fp+_u64(identity.version)+previous+v['phoneReader']+v['archiveReader']+signer+point+_u64(until)+_sized(m.raw)+_sized(unsigned)
    s.require(len(proposal)<=20480,'refresh bound');return proposal
