"""Selected original role-3 opening under initial and final current authority."""
import re
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import sealed_candidate as s
from .reply_selection import _selections,_authorize_archive


def capture_scope(scope):
    s.require(type(scope) is dict and set(scope)=={'account','device','line','interval','connector','read_grant','reader','peer'},'original scope')
    captured={k:s.capture(scope[k],32 if k=='reader' else 16) for k in scope if k!='peer'}
    s.require(all(any(v) for v in captured.values()),'original scope identity')
    s.require(type(scope['peer']) is str and re.fullmatch(r'\+[1-9][0-9]{1,14}',scope['peer']) is not None,'original peer')
    return dict(captured,peer=scope['peer'])


def _authority(value,scope):
    s.require(type(value) is dict and set(value)=={'scope','revision','expires_ms','now_ms','manifest'},'original authority')
    s.require(capture_scope(value['scope'])==scope and type(value['revision']) is str and 1<=len(value['revision'])<=128,'original authority binding')
    now,expires=s.integer(value['now_ms']),s.integer(value['expires_ms'])
    s.require(0<now<expires,'original authority expired')
    manifest=s._bound(s._manifests,value['manifest'])
    s.require(now>=manifest.comparison and manifest.profile==2,'original authority comparison')
    current=s._parse_manifest(manifest.raw,manifest.trust,now)
    return current,now,expires,value['revision']


def open_original_reply02(raw,*,scope,event,historical,selection,custody,read_current,require_protected=True):
    """No plaintext leaves before the final independently obtained grant check.

    read_current is a trusted grant-client integration, not event metadata.
    The dedicated OriginalReplyClient supplies the authenticated HTTPS proofs.
    Software keys require explicit opt-out; unknown providers never downgrade.
    """
    scope=capture_scope(scope);event=s.capture(event,16)
    s.require(any(event) and callable(read_current) and type(require_protected) is bool,'original reader input')
    if require_protected or type(custody) is not s.SoftwareRecipient:s.require_protected_custody(custody)
    selected=s._bound(_selections,selection)
    s.require((scope['connector'],scope['read_grant'],scope['reader']) in selected.readers,'original selected grant')
    p=s.parse_envelope(raw)
    s.require(p.profile==2 and p.kind==2 and p.message==event,'original event binding')
    current,now,expires,revision=_authority(read_current(),scope)
    old=s._bound(s._manifests,historical)
    s.require((old.trust.account,old.trust.generation,old.trust.root)==(current.trust.account,current.trust.generation,current.trust.root),
              'original historical root')
    s.require((old.trust.generation,old.trust.version,old.trust.digest) in current.trust.lineage,'original historical lineage')
    _authorize_archive(selection,p,old,current,scope['interval'],selected.archive)
    p=s.verify_envelope(p.raw,historical,account=scope['account'],device=scope['device'],line=scope['line'],peer=scope['peer'],comparison_ms=p.observed)
    s.require(p.observed<=now,'original future event')
    reader=next((k for k in current.keys if k.role==3 and k.id==scope['reader']),None)
    s.require(reader is not None and reader.active(now) and reader.scope&8,'original reader revoked')
    wrap=next((w for w in p.wraps if w[:2]==(3,scope['reader'])),None)
    s.require(wrap is not None,'original role3 wrap')
    cek,body=None,None
    try:
        cek=s._unwrap(custody,reader.point,wrap[2],wrap[3],s.label('ZTSE/wrap/v2')+p.prefix+b'\x03'+scope['reader'],b'')
        body=bytearray(len(p.body)-16);count=None
        try:count=AESGCM(cek).decrypt_into(p.nonce,p.body,s.label('ZTSE/body/v2')+p.prefix,body)
        except InvalidTag:pass
        s.require(count==len(body),'original body authentication')
        final,at,deadline,final_revision=_authority(read_current(),scope)
        s.require(final_revision==revision and now<=at<expires and at<reader.end and
                  (final.trust.generation,final.trust.version,final.trust.digest,final.trust.root)==
                  (current.trust.generation,current.trust.version,current.trust.digest,current.trust.root),'original final authority changed')
        s.require(1<=len(body)<=32768 and 0 not in body and not body.startswith(b'\xef\xbb\xbf'),'original body text')
        text=None
        try:text=body.decode('utf-8',errors='strict')
        except UnicodeDecodeError:pass
        s.require(text is not None,'original body UTF-8')
        return text
    finally:
        for value in (cek,body):
            if value is not None:value[:]=bytes(len(value))
