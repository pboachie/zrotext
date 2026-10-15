"""Profile02 public-composer wire compatibility; candidate bytes, not permission."""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import sealed_candidate as s
from .compose03 import Composition, SoftwareSigner, _wrap
from .cng_signing import require_hardware_signer

SEALED_CONTENT_TYPE = 'application/vnd.zrotext.sealed.v1'


class SealedEnvelopeError(s.SealedError):
    def __init__(self, code):
        self.code = code
        super().__init__('sealed outbound composition refused: ' + code)


def require(value, code):
    if not value:
        raise SealedEnvelopeError(code)


def capture(value, width, code):
    require(type(value) in (bytes, bytearray) and len(value) == width, code)
    return bytes(value)


def authorize(*, manifest, now_ms, message_id, device_id, line_id, peer,
                       observed_ms, expires_ms, content, signer, recipients,
                       require_hardware=True, **unsupported):
    """Snapshot a validated profile02 composition plan before secret operations.

    Recipients are (role, key_id, public_point) tuples. No randomness override is
    accepted. The maintained profile02 composer allows zero message IDs and
    candidate times that are not live; this function does not mint live authority.
    """
    require(not unsupported, 'key_material' if any(k in unsupported for k in ('deterministicKeyMaterial','deterministic_key_material')) else 'composition')
    message, device, line = (capture(v,16,'identity') for v in (message_id,device_id,line_id))
    require(type(peer) is str and 3 <= len(peer) <= 16 and peer[0] == '+' and peer[1] in '123456789' and
            all(v in '0123456789' for v in peer[2:]), 'peer')
    require(all(type(v) is int and 0 <= v <= s.MAX for v in (now_ms,observed_ms,expires_ms)), 'time_range')
    require(observed_ms < expires_ms and expires_ms-observed_ms <= 900000, 'intent_expiry')
    require(type(content) is str and 1 <= len(content) <= 32768, 'content')
    text = None
    try:
        text = content.encode('utf-8','strict')
    except UnicodeEncodeError:
        pass
    require(text is not None and len(text) <= 32768 and b'\0' not in text and not text.startswith(b'\xef\xbb\xbf'), 'content')
    require(type(recipients) in (list,tuple) and 2 <= len(recipients) <= 8, 'wrap_count')
    requested = []
    for value in recipients:
        require(type(value) in (list,tuple) and len(value) == 3 and type(value[0]) is int and value[0] in (1,2,3), 'recipient')
        role, ident, point = value[0], capture(value[1],32,'recipient'), capture(value[2],65,'recipient')
        require(point[0] == 4, 'recipient')
        valid_point = False
        try:
            valid_point = s.key_id(role,point) == ident
        except s.SealedError:
            pass
        require(valid_point, 'recipient_key_id')
        requested.append((role,ident,point))
    require(len({(r,i) for r,i,_ in requested}) == len(requested) and sum(r==1 for r,_,_ in requested)==1 and
            sum(r==2 for r,_,_ in requested)==1,'recipient')
    require(type(require_hardware) is bool, 'signer')
    if require_hardware or type(signer) is not SoftwareSigner:
        try:
            require_hardware_signer(signer)
        except s.SealedError:
            raise SealedEnvelopeError('signer') from None
    public = capture(signer.public_point(),65,'signer')
    signer_id = s.key_id(5,public)
    m = None
    try:
        m = s._bound(s._manifests,manifest)
        s.window(m.issued,m.expires,now_ms)
    except s.SealedError:
        m = None
    require(m is not None and m.profile == 2 and now_ms < m.expires and m.issued <= now_ms+300000, 'authorization')
    key = next((k for k in m.keys if k.role == 5 and k.id == signer_id),None)
    require(key is not None and key.active(now_ms) and key.scope == 1 and key.line == line and key.point == public,'authorization')
    for role,ident,point in requested:
        key = next((k for k in m.keys if k.role == role and k.id == ident),None)
        require(key is not None and key.active(now_ms) and key.scope & 4 and key.point == point,'authorization')
        require(role != 1 or (key.device,key.line) == (device,line),'authorization')
    protected = (m.trust.account+message+device+line+m.trust.version.to_bytes(8,'big')+m.trust.digest+signer_id+
                 observed_ms.to_bytes(8,'big')+expires_ms.to_bytes(8,'big')+bytes([1,len(peer)])+peer.encode('ascii'))
    prefix = b'ZTSE\x02\x01\0\0'+len(protected).to_bytes(2,'big')+protected
    return prefix, text, tuple(sorted(requested)), signer, public


def _compose(plan):
    prefix, text, requested, signer, public = plan
    cek, mutable_text = None, bytearray(text)
    try:
        try:
            cek, nonce = bytearray(os.urandom(32)), os.urandom(12)
        except (OSError,RuntimeError):
            raise SealedEnvelopeError('key_material') from None
        body = AESGCM(cek).encrypt(nonce,mutable_text,s.label('ZTSE/body/v2')+prefix)
        wraps = [bytes([role])+ident+_wrap(point,cek,s.label('ZTSE/wrap/v2')+prefix+bytes([role])+ident,b'')
                 for role,ident,point in sorted(requested)]
        unsigned = prefix+nonce+len(body).to_bytes(4,'big')+body+bytes([len(wraps)])+b''.join(wraps)
        signature = signer.sign('ZTSE/sign/v2',unsigned)
        s.verify_signature(public,signature,'ZTSE/sign/v2',unsigned)
        envelope = unsigned+signature
        require(557 <= len(envelope) <= 34213,'envelope_size')
        s.parse_envelope(envelope)
        return Composition(envelope,s.sha(unsigned),s.sha(envelope))
    except SealedEnvelopeError:
        raise
    except (ValueError,TypeError,RuntimeError,OSError):
        raise SealedEnvelopeError('composition') from None
    finally:
        if cek is not None: cek[:] = bytes(len(cek))
        mutable_text[:] = bytes(len(mutable_text))


def compose_outbound02(*, manifest, now_ms, message_id, device_id, line_id, peer,
                       observed_ms, expires_ms, content, signer, recipients,
                       require_hardware=True, **unsupported):
    """Fresh profile02 candidate. No randomness overrides or live grant minted."""
    return _compose(authorize(manifest=manifest,now_ms=now_ms,message_id=message_id,device_id=device_id,
        line_id=line_id,peer=peer,observed_ms=observed_ms,expires_ms=expires_ms,content=content,
        signer=signer,recipients=recipients,require_hardware=require_hardware,**unsupported))
