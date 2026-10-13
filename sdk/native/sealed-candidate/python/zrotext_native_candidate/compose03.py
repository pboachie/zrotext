"""Native outbound candidate composition; no grant, HTTP or SMS authority."""
from dataclasses import dataclass
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import election03 as e
from . import sealed_candidate as s
from .cng_signing import require_hardware_signer


class SoftwareSigner:
    """Explicit test/experimental software key, never protected custody."""
    def __init__(self, key):
        s.require(isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1), 'signing key')
        self.key = key

    def public_point(self):
        return self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def sign(self, domain, unsigned):
        r, value = utils.decode_dss_signature(self.key.sign(s.label(domain) + len(unsigned).to_bytes(4, 'big') + unsigned, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, 'big') + min(value, s.ORDER-value).to_bytes(32, 'big')


@dataclass(frozen=True)
class Composition:
    envelope: bytes
    unsigned_digest: bytes
    envelope_digest: bytes


def authorize(*, manifest, proof, current_authority, now_ms, message_id, observed_ms,
              expires_ms, peer, content, signer, recipients, require_hardware=True):
    now, observed, expires = e.positive(now_ms), e.positive(observed_ms), e.positive(expires_ms)
    message = s.capture(message_id, 16)
    s.require(any(message), 'zero message id')
    s.require(type(peer) is str and 3 <= len(peer) <= 16 and peer[0] == '+' and
              peer[1] in '123456789' and all(c in '0123456789' for c in peer[2:]), 'peer')
    s.require(type(content) is str and 1 <= len(content) <= 32768, 'content type/size')
    text = None
    try:
        text = content.encode('utf-8', 'strict')
    except UnicodeEncodeError:
        pass
    s.require(text is not None and 1 <= len(text) <= 32768 and b'\0' not in text and not text.startswith(b'\xef\xbb\xbf'), 'strict body text')
    s.require(observed <= now < expires and expires-observed <= 900000, 'intent expiry')
    s.require(type(require_hardware) is bool, 'hardware policy')
    if require_hardware or type(signer) is not SoftwareSigner:
        require_hardware_signer(signer)
    public = s.capture(signer.public_point(), 65)
    signer_id = s.key_id(5, public)
    bound = e.require_current_election03(proof, manifest, current_authority, now)
    m = s._bound(s._manifests, manifest)
    key = next((k for k in m.keys if k.role == 5 and k.id == signer_id), None)
    s.require(key is not None and key.active(now) and key.start <= observed and key.scope == 1 and key.line == bound['lineId'] and key.point == public, 'signer authority')
    s.require(type(recipients) in (list, tuple) and 2 <= len(recipients) <= 8, 'recipient count')
    requested = []
    for item in recipients:
        s.require(type(item) in (tuple, list) and len(item) == 2 and type(item[0]) is int and item[0] in (1,2,3), 'recipient shape')
        requested.append((item[0], s.capture(item[1], 32)))
    s.require(len(set(requested)) == len(requested) and sum(role == 1 for role,_ in requested) == 1 and
              sum(role == 2 for role,_ in requested) == 1, 'recipient set')
    authorized, deadline = [], min(m.expires, key.end, bound['permissionExpiresAtMs'])
    for role, ident in sorted(requested):
        key = next((k for k in m.keys if k.role == role and k.id == ident), None)
        s.require(key is not None and key.active(now) and key.start <= observed and key.scope & 4, 'recipient authority')
        s.require(role != 1 or (key.device,key.line,key.id) == (bound['deviceId'],bound['lineId'],bound['selectedReaderKeyId']), 'elected recipient')
        deadline = min(deadline, key.end)
        authorized.append((role, ident, key.point))
    s.require(expires <= deadline, 'authority deadline')
    protected = (bound['accountId'] + message + bound['deviceId'] + bound['lineId'] + bound['manifestVersion'].to_bytes(8,'big') +
        bound['manifestDigest'] + signer_id + observed.to_bytes(8,'big') + expires.to_bytes(8,'big') + bytes([1,len(peer)]) + peer.encode('ascii'))
    prefix = b'ZTSE\x03\x01\x00\x00' + len(protected).to_bytes(2,'big') + protected
    # Immutable captured plan; authority validation completes before randomness.
    return prefix, text, tuple(authorized), signer, public, bound


def _wrap(public, cek, info, aad):
    private = ec.generate_private_key(ec.SECP256R1())
    ephemeral = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    buffers = []
    def retain(value):
        out = bytearray(value); buffers.append(out); return out
    try:
        dh = retain(private.exchange(ec.ECDH(), s.point(public)))
        kem, suite = b'KEM\x00\x10', b'HPKE\x00\x10\x00\x01\x00\x01'
        eae = retain(s._extract(kem, b'', b'eae_prk', dh))
        shared = retain(s._expand(kem, eae, b'shared_secret', ephemeral + public, 32))
        context = b'\0' + s._extract(suite,b'',b'psk_id_hash',b'') + s._extract(suite,b'',b'info_hash',info)
        secret = retain(s._extract(suite,shared,b'secret',b''))
        key = retain(s._expand(suite,secret,b'key',context,16))
        nonce = s._expand(suite,secret,b'base_nonce',context,12)
        return ephemeral + AESGCM(key).encrypt(nonce, cek, aad)
    finally:
        for value in buffers:
            value[:] = bytes(len(value))


def _compose(plan):
    prefix, text, recipients, signer, public, _ = plan
    cek, mutable_text = bytearray(os.urandom(32)), bytearray(text)
    try:
        nonce = os.urandom(12)
        body = AESGCM(cek).encrypt(nonce, mutable_text, s.label('ZTSE/body/v3') + prefix)
        wraps = []
        for role, ident, point in recipients:
            suffix = prefix + bytes([role]) + ident
            wraps.append(bytes([role]) + ident + _wrap(point, cek, s.label('ZTSE/wrap/v3') + suffix, s.label('ZTSE/wrap-aad/v3') + suffix))
        unsigned = prefix + nonce + len(body).to_bytes(4,'big') + body + bytes([len(wraps)]) + b''.join(wraps)
        signature = signer.sign('ZTSE/sign/v3', unsigned)
        s.verify_signature(public, signature, 'ZTSE/sign/v3', unsigned)
        envelope = unsigned + signature
        s.parse_envelope(envelope)
        return Composition(envelope, s.sha(unsigned), s.sha(envelope))
    finally:
        cek[:] = bytes(len(cek)); mutable_text[:] = bytes(len(mutable_text))


def compose_outbound03(**inputs):
    """Fresh candidate each call. Use durable replay storage before transport."""
    return _compose(authorize(**inputs))
