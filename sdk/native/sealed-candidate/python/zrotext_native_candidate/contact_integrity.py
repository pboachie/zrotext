"""Historical contact commitments only; no installed access or current grant."""
import copy
from functools import wraps
import re
from ada_url import URL as _URL
from weakref import WeakKeyDictionary
from . import sealed_candidate as s
from .contact_bidi16 import valid_bidi16_host

_statements,_fields,_mutations,_transitions=(WeakKeyDictionary() for _ in range(4))
_STATEMENT=('authorizationId','accountId','origin','trustGeneration','manifestVersion','readerGeneration','rootFingerprint','manifestDigest','readerId','readerPoint','issuedMs','untilMs','capability')
_FIELD=('kind','accountId','contactId','sealRevision','trustGeneration','manifestVersion','readerGeneration','readerId','manifestDigest','statementDigest','routingDigest','requestId','rootWriterId','encapsulation','ciphertext')
_MUTATION=('operation','accountId','contactId','expectedRevision','revision','requestId','previousDigest','trustGeneration','manifestVersion','manifestDigest','statementDigest','routingDigest','legacyGeneration','name','notes')


class ContactIntegrityError(ValueError):
    def __init__(self):super().__init__('Contact historical integrity unavailable')


def _closed(function):
    @wraps(function)
    def run(*args,**kwargs):
        try:return function(*args,**kwargs)
        except Exception:raise ContactIntegrityError() from None
    return run


def _object(value,fields):
    s.require(type(value) is dict and set(value)==set(fields),'contact fields');return dict(value)


def _bytes(value,width,zero=False):
    value=s.capture(value,width);s.require(zero or any(value),'contact zero field');return value


def _integer(value,zero=False):
    value=s.integer(value);s.require(zero or value>0,'contact positive integer');return value


def _u64(value):return value.to_bytes(8,'big')


def _origin(value):
    s.require(type(value) is str and 9<=len(value)<=512 and re.fullmatch(r'[\x21-\x7e]+',value) is not None,'contact origin')
    u=_URL(value)
    s.require(u.protocol=='https:' and u.origin==value and not u.username and not u.password and
              u.pathname=='/' and not u.search and not u.hash,'contact canonical origin')
    s.require(valid_bidi16_host(u.hostname),'contact directional origin')
    return value


def _signature(raw):
    s.require(len(raw)==64 and 0<int.from_bytes(raw[:32],'big')<s.ORDER and 0<int.from_bytes(raw[32:],'big')<=s.ORDER//2,'contact low-S signature')


def _signed(raw,minimum,maximum,magic):
    raw=s.capture(raw,minimum,maximum);s.require(raw[:5]==magic+b'\x01','contact profile');_signature(raw[-64:])
    return dict(bytes=raw,unsigned=raw[:-64],signature=raw[-64:])


def _statement(value):
    v=_object(value,_STATEMENT)
    for key in ('authorizationId','accountId'):v[key]=_bytes(v[key],16)
    for key in ('rootFingerprint','manifestDigest','readerId'):v[key]=_bytes(v[key],32)
    v['readerPoint']=_bytes(v['readerPoint'],65)
    for key in ('trustGeneration','manifestVersion','readerGeneration','issuedMs','untilMs'):v[key]=_integer(v[key])
    _origin(v['origin']);s.require(v['readerPoint'][0]==4 and type(v['capability']) is int and v['capability']==3 and v['trustGeneration']==1 and 0<v['untilMs']-v['issuedMs']<=86400000,'contact statement')
    return v


@_closed
def encode_contact_reader_statement01(value):
    v=_statement(value);origin=v['origin'].encode('ascii')
    return b'ZTKA\x01\x03'+v['authorizationId']+v['accountId']+len(origin).to_bytes(2,'big')+origin+\
        b''.join(_u64(v[k]) for k in ('trustGeneration','manifestVersion','readerGeneration'))+\
        b''.join(v[k] for k in ('rootFingerprint','manifestDigest','readerId','readerPoint'))+_u64(v['issuedMs'])+_u64(v['untilMs'])


@_closed
def parse_contact_reader_statement01(raw):
    p=_signed(raw,314,817,b'ZTKA');b=p['bytes'];n=s.num(b,38,2)
    s.require(b[5]==3 and 9<=n<=512 and len(b)==305+n,'contact statement length');at=40+n
    v=dict(authorizationId=b[6:22],accountId=b[22:38],origin=b[40:at].decode('utf-8',errors='strict'),capability=3)
    for key in ('trustGeneration','manifestVersion','readerGeneration'):v[key]=s.num(b,at);at+=8
    for key,width in (('rootFingerprint',32),('manifestDigest',32),('readerId',32),('readerPoint',65)):v[key]=b[at:at+width];at+=width
    v.update(issuedMs=s.num(b,at),untilMs=s.num(b,at+8));v=_statement(v)
    s.require(encode_contact_reader_statement01(v)==p['unsigned'] and s.key_id(2,v['readerPoint'])==v['readerId'],'contact canonical reader')
    s.point(v['readerPoint']);return dict(v,**p)


@_closed
def verify_contact_reader_statement01(raw,accepted_manifest,*,account,origin,root_fingerprint,comparison='declared_issued_ms'):
    account=_bytes(account,16);fingerprint=_bytes(root_fingerprint,32);_origin(origin)
    s.require(comparison=='declared_issued_ms','contact historical comparison');v=parse_contact_reader_statement01(raw)
    m=s._bound(s._manifests,accepted_manifest);s.require(m.profile==2 and m.trust.generation==1,'contact accepted history')
    m=s._parse_manifest(m.raw,m.trust,v['issuedMs'])
    reader=next((k for k in m.keys if k.role==2 and k.id==v['readerId'] and k.active(v['issuedMs'])),None)
    root=next((k for k in m.keys if k.role==6 and k.active(v['issuedMs'])),None)
    s.require(reader is not None and reader.scope==12 and root is not None and root.scope==0,'contact records')
    s.require(v['accountId']==account==m.trust.account and v['origin']==origin and v['trustGeneration']==m.trust.generation and
        v['manifestVersion']==m.trust.version and v['manifestDigest']==m.trust.digest and v['readerPoint']==reader.point and
        v['issuedMs']>=m.issued and v['untilMs']<=min(m.expires,reader.end,root.end),'contact statement authority')
    pin=b'ZTRP\x02'+account+_u64(1)+root.point
    s.require(s.sha(s.label('ZTSE/root-pin/v2')+pin)==fingerprint==v['rootFingerprint'],'contact root comparison')
    s.verify_signature(root.point,v['signature'],'ZT/contact-reader/authorization/v1',v['unsigned'])
    return s._accept(_statements,dict(v,digest=s.sha(v['bytes']),rootWriterId=root.id,rootPoint=root.point,
        readerFromMs=reader.start,readerUntilMs=reader.end,rootFromMs=root.start,rootUntilMs=root.end))


def _slot(value):
    v=_object(value,('tag','sealRevision','digest'));s.require(type(v['tag']) is int and v['tag'] in (0,1),'contact slot')
    v['sealRevision']=_integer(v['sealRevision'],True);v['digest']=_bytes(v['digest'],32,True)
    s.require((v['sealRevision']==0 and not any(v['digest'])) if v['tag']==0 else (v['sealRevision']>0 and any(v['digest'])),'contact slot sentinel');return v


def _field(value):
    v=_object(value,_FIELD)
    for key in ('accountId','contactId','requestId'):v[key]=_bytes(v[key],16)
    for key in ('readerId','manifestDigest','statementDigest','routingDigest','rootWriterId'):v[key]=_bytes(v[key],32)
    for key in ('sealRevision','trustGeneration','manifestVersion','readerGeneration'):v[key]=_integer(v[key])
    s.require(v['trustGeneration']==1 and type(v['kind']) is int and v['kind'] in (1,2),'contact field kind')
    v['encapsulation']=_bytes(v['encapsulation'],65);s.require(v['encapsulation'][0]==4,'contact point encoding')
    v['ciphertext']=s.capture(v['ciphertext'],17,272 if v['kind']==1 else 2064);return v


def _mutation(value):
    v=_object(value,_MUTATION)
    for key in ('accountId','contactId','requestId'):v[key]=_bytes(v[key],16)
    for key in ('manifestDigest','statementDigest','routingDigest'):v[key]=_bytes(v[key],32)
    v['previousDigest']=_bytes(v['previousDigest'],32,True)
    for key in ('revision','trustGeneration','manifestVersion'):v[key]=_integer(v[key])
    for key in ('expectedRevision','legacyGeneration'):v[key]=_integer(v[key],True)
    v['name']=_slot(v['name']);v['notes']=_slot(v['notes'])
    s.require(v['trustGeneration']==1 and type(v['operation']) is int and v['name']['sealRevision']<=v['revision'] and v['notes']['sealRevision']<=v['revision'],'contact mutation')
    if v['operation'] in (1,3):s.require(v['expectedRevision']==0 and v['revision']==1 and not any(v['previousDigest']) and (v['legacyGeneration']==0 if v['operation']==1 else v['legacyGeneration']>0),'contact creation')
    else:s.require(v['operation']==2 and 0<v['expectedRevision']<s.MAX and v['revision']==v['expectedRevision']+1 and any(v['previousDigest']) and v['legacyGeneration']==0,'contact update')
    return v


@_closed
def encode_contact_field01(value):
    v=_field(value)
    return b'ZTCO\x01'+bytes([v['kind']])+v['accountId']+v['contactId']+b''.join(_u64(v[k]) for k in ('sealRevision','trustGeneration','manifestVersion','readerGeneration'))+\
        b''.join(v[k] for k in ('readerId','manifestDigest','statementDigest','routingDigest','requestId','rootWriterId','encapsulation'))+len(v['ciphertext']).to_bytes(4,'big')+v['ciphertext']


@_closed
def encode_contact_mutation01(value):
    v=_mutation(value);slot=lambda x:bytes([x['tag']])+_u64(x['sealRevision'])+x['digest']
    return b'ZTCM\x01'+bytes([v['operation']])+v['accountId']+v['contactId']+_u64(v['expectedRevision'])+_u64(v['revision'])+v['requestId']+v['previousDigest']+\
        _u64(v['trustGeneration'])+_u64(v['manifestVersion'])+v['manifestDigest']+v['statementDigest']+v['routingDigest']+_u64(v['legacyGeneration'])+slot(v['name'])+slot(v['notes'])


@_closed
def parse_contact_field01(raw):
    p=_signed(raw,396,2443,b'ZTCO');b=p['bytes'];n=s.num(b,311,4);s.require(len(b)==379+n,'contact field length')
    v=_field(dict(kind=b[5],accountId=b[6:22],contactId=b[22:38],sealRevision=s.num(b,38),trustGeneration=s.num(b,46),manifestVersion=s.num(b,54),readerGeneration=s.num(b,62),
        readerId=b[70:102],manifestDigest=b[102:134],statementDigest=b[134:166],routingDigest=b[166:198],requestId=b[198:214],rootWriterId=b[214:246],encapsulation=b[246:311],ciphertext=b[315:315+n]))
    s.point(v['encapsulation']);return dict(v,**p)


@_closed
def parse_contact_mutation01(raw):
    p=_signed(raw,368,368,b'ZTCM');b=p['bytes'];slot=lambda at:dict(tag=b[at],sealRevision=s.num(b,at+1),digest=b[at+9:at+41])
    v=_mutation(dict(operation=b[5],accountId=b[6:22],contactId=b[22:38],expectedRevision=s.num(b,38),revision=s.num(b,46),requestId=b[54:70],previousDigest=b[70:102],
        trustGeneration=s.num(b,102),manifestVersion=s.num(b,110),manifestDigest=b[118:150],statementDigest=b[150:182],routingDigest=b[182:214],legacyGeneration=s.num(b,214),name=slot(222),notes=slot(263)))
    return dict(v,**p)


def _scope(value,statement,contact,routing):
    s.require(value['accountId']==statement['accountId'] and value['contactId']==contact and value['routingDigest']==routing and
              all(value[k]==statement[k] for k in ('trustGeneration','manifestVersion','manifestDigest')) and value['statementDigest']==statement['digest'],'contact scope')


@_closed
def verify_contact_field01(raw,statement,*,contact,routing_digest):
    st=s._bound(_statements,statement);contact=_bytes(contact,16);routing=_bytes(routing_digest,32);v=parse_contact_field01(raw);_scope(v,st,contact,routing)
    s.require(all(v[k]==st[k] for k in ('readerGeneration','readerId','rootWriterId')),'contact reader binding')
    s.verify_signature(st['rootPoint'],v['signature'],'ZT/contact-field/commitment/v1',v['unsigned'])
    return s._accept(_fields,(dict(v,digest=s.sha(v['bytes'])),st))


@_closed
def verify_contact_mutation01(raw,statement,*,contact,routing_digest,legacy_generation=0):
    st=s._bound(_statements,statement);contact=_bytes(contact,16);routing=_bytes(routing_digest,32);v=parse_contact_mutation01(raw);_scope(v,st,contact,routing)
    s.require(v['legacyGeneration']==_integer(legacy_generation,True),'contact legacy binding')
    s.verify_signature(st['rootPoint'],v['signature'],'ZT/contact-field/mutation/v1',v['unsigned'])
    return s._accept(_mutations,(dict(v,digest=s.sha(v['bytes'])),st))


def _transition_values(previous,n,st,replacement_fields):
    old=None if previous is None else s._bound(_transitions,previous)
    s.require(type(replacement_fields) in (list,tuple) and len(replacement_fields)<=2,'contact replacements')
    supplied=[s._bound(_fields,t) for t in replacement_fields];s.require(len({f[0]['kind'] for f in supplied})==len(supplied),'contact duplicate replacements')
    if old is not None:
        p,ps,prior=old
        s.require(n['operation']==2 and n['expectedRevision']==p['revision'] and n['previousDigest']==p['digest'] and
            all(n[k]==p[k] for k in ('accountId','contactId','routingDigest','trustGeneration')) and st['origin']==ps['origin'] and st['rootFingerprint']==ps['rootFingerprint'] and
            (n['manifestVersion']>p['manifestVersion'] or n['manifestVersion']==p['manifestVersion'] and n['manifestDigest']==p['manifestDigest']) and
            (st['readerGeneration']>ps['readerGeneration'] or st['readerGeneration']==ps['readerGeneration'] and st['readerId']==ps['readerId'] and st['readerPoint']==ps['readerPoint']),'contact transition continuity')
    else:s.require(n['operation']!=2,'contact predecessor required')
    current=[];used=set()
    for kind,key in ((1,'name'),(2,'notes')):
        slot=n[key]
        if slot['tag']==0:current.append(None);continue
        if slot['sealRevision']==n['revision']:
            found=next((item for item in supplied if item[0]['kind']==kind),None);s.require(found is not None,'contact replacement required');q,_=found
            _scope(q,st,n['contactId'],n['routingDigest'])
            s.require(q['digest']==slot['digest'] and q['sealRevision']==n['revision'] and q['requestId']==n['requestId'] and
                      all(q[k]==st[k] for k in ('readerGeneration','readerId','rootWriterId')),'contact replacement binding')
            used.add(kind);current.append(found)
        else:
            s.require(old is not None and slot==p[key] and prior[kind-1] is not None,'contact retained field');current.append(prior[kind-1])
    s.require(len(used)==len(supplied),'contact unused replacements')
    return n,st,tuple(current)


@_closed
def verify_contact_transition01(previous,next_mutation,replacement_fields):
    n,st=s._bound(_mutations,next_mutation)
    return s._accept(_transitions,_transition_values(previous,n,st,replacement_fields))


@_closed
def contact_statement_identity(token):return copy.deepcopy(s._bound(_statements,token))


@_closed
def contact_field_identity(token):return copy.deepcopy(s._bound(_fields,token)[0])


@_closed
def contact_mutation_identity(token):return copy.deepcopy(s._bound(_mutations,token)[0])


@_closed
def contact_transition_identity(token):return copy.deepcopy(s._bound(_transitions,token)[0])
