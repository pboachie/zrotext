"""Client-only ZTWT01 templates; no persistence, grant or dispatch authority."""
from functools import wraps
import json
import math
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import sealed_candidate as s
from .compose03 import _wrap

_IDS=('accountId','deviceId','lineId','intervalId','templateId')
_NUMBERS=('bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion')
_DIGESTS=('peerDigest','readerId','manifestDigest')
_FIELDS=set(_IDS+_NUMBERS+_DIGESTS)
_IDENTIFIER=re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,31}\Z')
_TOKEN=re.compile(r'\{\{([A-Za-z_][A-Za-z0-9_]{0,31})\}\}')
_RESERVED={'__proto__','prototype','constructor'}
_DOMAIN=b'ZT/workflow-template/hpke/v1\0'
_GSM=set('@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà')
_EXTENSION=set('\f^{}\\[~]|€')


class TemplateError(ValueError):
    def __init__(self):super().__init__('Template unavailable')


def _closed(function):
    @wraps(function)
    def run(*args,**kwargs):
        try:return function(*args,**kwargs)
        except Exception:raise TemplateError() from None
    return run


def _text(value,maximum):
    s.require(type(value) is str and len(value)<=maximum,'template text')
    # Match JS UTF-16 limits, accepting paired surrogates but never lone ones.
    encoded=value.encode('utf-16-le',errors='surrogatepass')
    s.require(len(encoded)//2<=maximum,'template text limit')
    return encoded.decode('utf-16-le',errors='strict')


def _units(value):return len(value.encode('utf-16-le'))//2


def _key(value):
    s.require(type(value) is str and _IDENTIFIER.fullmatch(value) is not None and value not in _RESERVED,'template identifier')


def _content(template,values):
    template=_text(template,4096);offset=0
    while offset<len(template):
        if template[offset]=='{':
            match=_TOKEN.match(template,offset);s.require(match is not None,'template token');_key(match[1]);offset=match.end()
        else:s.require(template[offset]!='}','template brace');offset+=1
    s.require(type(values) is dict and len(values)<=32,'template substitutions')
    captured={};total=0
    for key,value in values.items():
        _key(key);value=_text(value,512);total+=len(key)+1+_units(value)+(1 if total else 0)
        s.require(total<=4096,'template substitution bounds');captured[key]=value
    return template,captured


@_closed
def canonical_template_bytes(template,values):
    template,values=_content(template,values)
    return json.dumps(dict(v=1,template=template,values={key:values[key] for key in sorted(values)}),
                      ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')


@_closed
def template_digest(template,values):return s.sha(canonical_template_bytes(template,values)).hex()


@_closed
def estimate_segments(text):
    text=_text(text,8192)
    s.require(not any(ord(c)<32 and c not in '\n\r\f' for c in text),'SMS control')
    gsm=all(c in _GSM or c in _EXTENSION for c in text)
    length=sum(2 if c in _EXTENSION else 1 for c in text) if gsm else _units(text)
    single=160 if gsm else 70;multipart=153 if gsm else 67
    per=single if length<=single else multipart;parts=max(1,math.ceil(length/per))
    s.require(parts<=6,'SMS parts')
    return dict(encoding='gsm' if gsm else 'ucs2',parts=parts,perPart=per,length=length,empty=not text)


@_closed
def preview_encrypted_template(content):
    s.require(type(content) is dict and set(content)=={'template','values'},'template content')
    template,values=_content(content['template'],content['values']);parts=[];offset=0;length=0
    for match in _TOKEN.finditer(template):
        s.require(match[1] in values,'template missing substitution')
        piece=template[offset:match.start()]+values[match[1]];length+=_units(piece)
        s.require(length<=8192,'template output');parts.append(piece);offset=match.end()
    tail=template[offset:];s.require(length+_units(tail)<=8192,'template output');parts.append(tail)
    text=''.join(parts);return dict(text=text,estimate=estimate_segments(text))


@_closed
def encrypted_template_aad(scope):
    s.require(type(scope) is dict and set(scope)==_FIELDS,'template scope')
    parts=[b'ZTWT\x01\x01']
    for key in _IDS:
        value=s.capture(scope[key],16);s.require(any(value),'template zero identity');parts.append(value)
    for key in _NUMBERS:
        value=s.integer(scope[key]);s.require(value>0 and (key!='revision' or value<=128),'template integer');parts.append(value.to_bytes(8,'big'))
    for key in _DIGESTS:
        value=s.capture(scope[key],32);s.require(any(value),'template zero digest');parts.append(value)
    return b''.join(parts)


def _authorize(manifest,aad,now):
    now=s.integer(now);expiry=s.num(aad,102)
    s.require(0<now<expiry and expiry-now<=30*86400000,'template expiry')
    m=s._bound(s._manifests,manifest);s.require(m.profile==2,'template profile')
    m=s._parse_manifest(m.raw,m.trust,now)
    s.require((m.trust.account,m.trust.generation,m.trust.version,m.trust.digest)==
              (aad[6:22],s.num(aad,110),s.num(aad,118),aad[190:222]),'template manifest binding')
    reader=next((k for k in m.keys if k.role==2 and k.id==aad[158:190]),None)
    signer=next((k for k in m.keys if k.role==4 and k.active(now) and k.device==aad[22:38] and k.line==aad[38:54]),None)
    s.require(reader is not None and reader.active(now) and reader.scope&8 and signer is not None and signer.scope==2,'template archive/line authority')
    return reader.point


@_closed
def seal_encrypted_template_bytes(manifest,scope,now_ms,plaintext):
    aad=encrypted_template_aad(scope);content=bytearray(s.capture(plaintext,1,32768))
    try:
        public=_authorize(manifest,aad,now_ms)
        wrapped=_wrap(public,content,_DOMAIN+aad,aad)
        return aad+wrapped[:65]+(len(wrapped)-65).to_bytes(4,'big')+wrapped[65:]
    finally:content[:]=bytes(len(content))


def _open(manifest,scope,now,custody,envelope,protected):
    s.require(type(protected) is bool,'template protected flag')
    if protected or type(custody) is not s.SoftwareRecipient:s.require_protected_custody(custody)
    envelope=s.capture(envelope,308,33075);aad=encrypted_template_aad(scope)
    s.require(envelope[:222]==aad and s.num(envelope,287,4)==len(envelope)-291,'template envelope')
    public=_authorize(manifest,aad,now);ephemeral=envelope[222:287];s.point(ephemeral)
    s.require(custody.public_point()==public,'template custody binding')
    ciphertext=envelope[291:];buffers=[]
    def retain(value):result=bytearray(value);buffers.append(result);return result
    try:
        kem,suite=b'KEM\x00\x10',b'HPKE\x00\x10\x00\x01\x00\x01'
        dh=retain(custody.exchange(ephemeral));eae=retain(s._extract(kem,b'',b'eae_prk',dh))
        shared=retain(s._expand(kem,eae,b'shared_secret',ephemeral+public,32))
        context=b'\0'+s._extract(suite,b'',b'psk_id_hash',b'')+s._extract(suite,b'',b'info_hash',_DOMAIN+aad)
        secret=retain(s._extract(suite,shared,b'secret',b''));key=retain(s._expand(suite,secret,b'key',context,16))
        nonce=s._expand(suite,secret,b'base_nonce',context,12);plain=retain(bytes(len(ciphertext)-16))
        s.require(AESGCM(key).decrypt_into(nonce,ciphertext,aad,plain)==len(plain),'template authentication')
        return bytearray(plain)
    finally:
        for value in buffers:value[:]=bytes(len(value))


@_closed
def open_encrypted_template_bytes(manifest,scope,now_ms,custody,envelope,*,require_protected=True):
    plain=_open(manifest,scope,now_ms,custody,envelope,require_protected)
    try:return bytes(plain)
    finally:plain[:]=bytes(len(plain))


@_closed
def seal_encrypted_template(manifest,scope,now_ms,content):
    s.require(type(content) is dict and set(content)=={'template','values'},'template content')
    return seal_encrypted_template_bytes(manifest,scope,now_ms,canonical_template_bytes(content['template'],content['values']))


@_closed
def open_encrypted_template(manifest,scope,now_ms,custody,envelope,*,require_protected=True):
    plain=_open(manifest,scope,now_ms,custody,envelope,require_protected)
    try:
        value=json.loads(plain.decode('utf-8',errors='strict'))
        s.require(type(value) is dict and set(value)=={'v','template','values'} and type(value['v']) is int and value['v']==1,'template canonical content')
        canonical=canonical_template_bytes(value['template'],value['values']);s.require(canonical==plain,'template canonical bytes')
        return dict(template=value['template'],values=dict(value['values']))
    finally:plain[:]=bytes(len(plain))


@_closed
def encrypted_template_digest(envelope):return s.sha(s.capture(envelope,308,33075))
