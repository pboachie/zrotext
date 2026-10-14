"""Experimental native sealed reader. Cryptographic provenance is not live authority.

No HTTP, SMS, grant, journal or protected persistent provider is implemented here.
"""
from dataclasses import dataclass, replace
import hashlib
import hmac
from typing import Protocol
from weakref import WeakKeyDictionary

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
MAX = (1 << 63) - 1
ZERO = bytes(32)


class SealedError(ValueError):
    """A closed refusal with no plaintext or provider exception attached."""


def require(value, reason):
    if not value:
        raise SealedError(reason)


def capture(value, minimum, maximum=None):
    require(type(value) in (bytes, bytearray), 'byte input type')
    require(minimum <= len(value) <= (minimum if maximum is None else maximum), 'byte input size')
    return bytes(value)


def integer(value):
    require(type(value) is int and 0 <= value <= MAX, 'integer range/type')
    return value


def num(data, offset, length=8):
    require(offset + length <= len(data), 'truncated integer')
    return integer(int.from_bytes(data[offset:offset + length], 'big'))


def label(text):
    return text.encode('ascii') + b'\0'


def sha(data):
    return hashlib.sha256(data).digest()


def point(data):
    data = capture(data, 65)
    require(data[0] == 4, 'point encoding')
    result = None
    try:
        result = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)
    except ValueError:
        pass
    require(result is not None, 'point curve')
    return result


def key_id(role, public):
    point(public)
    return sha(label('ZTSE/key/v1') + (16 if role <= 3 else 257).to_bytes(2, 'big') + public)


def verify_signature(public, signature, domain, unsigned):
    signature = capture(signature, 64)
    r, s = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')
    require(0 < r < ORDER and 0 < s <= ORDER // 2, 'signature scalar/low-S')
    ok = False
    try:
        point(public).verify(utils.encode_dss_signature(r, s),
                             label(domain) + len(unsigned).to_bytes(4, 'big') + unsigned,
                             ec.ECDSA(hashes.SHA256()))
        ok = True
    except InvalidSignature:
        pass
    require(ok, 'signature verification')


def window(issued, expires, now):
    integer(now)
    require(issued > 0 and issued < expires and expires - issued <= 86400000,
            'signed validity window')
    require(issued <= now + 300000 and now < expires, 'stale or future signed object')


class Evidence:
    """Opaque process-local verifier token; copying metadata does not mint evidence."""
    __slots__ = ('__weakref__',)


@dataclass(frozen=True)
class _Trust:
    account: bytes
    generation: int
    root: bytes
    version: int = 0
    digest: bytes = ZERO
    anchor: bytes = ZERO
    lineage: tuple = ()


@dataclass(frozen=True)
class _Key:
    role: int
    id: bytes
    point: bytes
    device: bytes
    line: bytes
    scope: int
    start: int
    end: int
    state: int

    def active(self, now):
        return self.state == 1 and self.start <= now < self.end


@dataclass(frozen=True)
class _Manifest:
    raw: bytes
    trust: _Trust
    before: _Trust
    profile: int
    predecessor: int
    issued: int
    expires: int
    comparison: int
    keys: tuple


_trusts = WeakKeyDictionary()
_manifests = WeakKeyDictionary()


def _accept(registry, value):
    token = Evidence()
    registry[token] = value
    return token


def _bound(registry, token):
    require(type(token) is Evidence and token in registry, 'verified evidence required')
    return registry[token]


def enroll_root02(raw, independently_compared_fingerprint):
    raw = capture(raw, 94)
    compared = capture(independently_compared_fingerprint, 32)
    require(raw[:5] == b'ZTRP\x02', 'root pin profile')
    require(raw[5:21] != bytes(16) and num(raw, 21) == 1, 'root pin identity')
    point(raw[29:])
    require(hmac.compare_digest(sha(label('ZTSE/root-pin/v2') + raw), compared), 'root comparison')
    return _accept(_trusts, _Trust(raw[5:21], 1, raw[29:]))


def _parse_manifest(raw, trust, now):
    raw = capture(raw, 364, 9753)
    profile = raw[4]
    require(raw[:4] == b'ZTMA' and profile in (2, 3), 'manifest profile')
    shift = 2 if profile == 3 else 0
    predecessor = raw[6] if shift else 2
    if shift:
        require(raw[5] == 3 and predecessor in (2, 3), 'unsupported genesis/predecessor')
    count = raw[150 + shift]
    require(1 <= count <= 64 and len(raw) == 215 + shift + 149 * count, 'manifest exact size')
    account = raw[5 + shift:21 + shift]
    generation, version = num(raw, 21 + shift), num(raw, 29 + shift)
    issued, expires = num(raw, 37 + shift), num(raw, 45 + shift)
    previous, root = raw[53 + shift:85 + shift], raw[85 + shift:150 + shift]
    require(account != bytes(16) and generation > 0 and version > 0, 'manifest identity')
    require((account, generation, root) == (trust.account, trust.generation, trust.root), 'manifest pin')
    if profile == 3:
        require(generation == 1 and trust.anchor == ZERO, 'unsupported profile03 generation/anchor')
    window(issued, expires, now)
    records, seen = [], set()
    for i in range(count):
        at = 151 + shift + 149 * i
        role, ident, public = raw[at], raw[at + 1:at + 33], raw[at + 33:at + 98]
        device, line = raw[at + 98:at + 114], raw[at + 114:at + 130]
        scope = num(raw, at + 130, 2)
        start, end, state = num(raw, at + 132), num(raw, at + 140), raw[at + 148]
        require(1 <= role <= 6, 'manifest role')
        require(scope in ((4, 8, 12) if role == 3 else ((0, 4, 12, 4, 2, 1, 0)[role],)), 'role scope')
        require((device != bytes(16)) == (role in (1, 4)), 'device subject')
        require((line != bytes(16)) == (role in (1, 4, 5)), 'line subject')
        require(start <= end and state in (1, 2), 'key validity/state')
        require(not records or (role, ident) > (records[-1].role, records[-1].id), 'key order')
        require(ident == key_id(role, public) and public not in seen, 'key identity/reuse')
        seen.add(public)
        if role == 6:
            require(public == root and state == 1 and start <= issued and end >= expires, 'owner record')
        records.append(_Key(role, ident, public, device, line, scope, start, end, state))
    require(sum(k.role == 6 for k in records) == 1 and
            sum(k.role == 2 and k.state == 1 for k in records) == 1, 'owner/archive cardinality')
    verify_signature(root, raw[-64:], f'ZTSE/manifest/v{profile}', raw[:-64])
    digest = sha(raw[:-64])
    if profile == 2 and trust.version == 0:
        require(version == 1 and previous == trust.anchor, 'genesis chain')
    elif version == trust.version and digest == trust.digest:
        pass
    else:
        require(version == trust.version + 1 and previous == trust.digest, 'rollback/fork/chain gap')
    entry = (generation, version, digest)
    lineage = trust.lineage if trust.lineage and trust.lineage[-1] == entry else trust.lineage + (entry,)
    return _Manifest(raw, replace(trust, version=version, digest=digest, lineage=lineage), trust,
                     profile, predecessor, issued, expires, now, tuple(records))


def verify_manifest02(raw, trust, now):
    parsed = _parse_manifest(raw, _bound(_trusts, trust), integer(now))
    require(parsed.profile == 2, 'profile02 required')
    return _accept(_manifests, parsed)


def advance_trust02(trust, manifest):
    parsed = _bound(_manifests, manifest)
    require(parsed.profile == 2 and _bound(_trusts, trust) == parsed.before, 'advance predecessor')
    # This is a proposed immutable high-water. Caller must persist with atomic CAS.
    return _accept(_trusts, parsed.trust)


def verify_manifest03(raw, predecessor, now):
    prior = _bound(_manifests, predecessor)
    now = integer(now)
    require(now >= prior.comparison, 'comparison rollback')
    if prior.profile == 2:
        window(prior.issued, prior.expires, now)
        require(prior.trust.generation == 1 and prior.trust.anchor == ZERO, 'unsupported02 predecessor')
        _parse_manifest(prior.raw, prior.trust, now)  # Reverify original signed02 evidence.
    parsed = _parse_manifest(raw, prior.trust, now)
    require(parsed.profile == 3 and parsed.predecessor == prior.profile and
            parsed.trust.version == prior.trust.version + 1, 'profile03 successor required')
    return _accept(_manifests, parsed)


def verify_manifest03_current(raw, current, now):
    """Verify received current03 evidence without advancing or replacing history.

    Alternate valid signatures can establish semantic identity. They do not
    replace immutable stored election bytes or establish exact transport replay.
    The returned token owns a new comparison floor; the original is unchanged.
    """
    prior = _bound(_manifests, current)
    now = integer(now)
    require(prior.profile == 3 and now >= prior.comparison, 'current03 provenance/comparison')
    parsed = _parse_manifest(raw, prior.trust, now)
    require(parsed.profile == 3 and parsed.predecessor == prior.predecessor and
            (parsed.trust.version, parsed.trust.digest) == (prior.trust.version, prior.trust.digest),
            'current03 identity fork/rollback')
    return _accept(_manifests, parsed)


def verify_root_transition02(raw, trust, now, independently_compared_new_root):
    old = _bound(_trusts, trust)
    raw = capture(raw, 343)
    expected = capture(independently_compared_new_root, 65)
    require(raw[:5] == b'ZTRT\x02', 'transition profile')
    new_generation = num(raw, 29)
    require(old.version > 0 and raw[5:21] == old.account and num(raw, 21) == old.generation and
            new_generation == old.generation + 1 and raw[37:102] == old.root and
            raw[102:167] == expected and expected != old.root and raw[167:199] == old.digest,
            'transition binding')
    window(num(raw, 199), num(raw, 207), integer(now))
    verify_signature(old.root, raw[215:279], 'ZTSE/root-transition/v2', raw[:215])
    verify_signature(expected, raw[279:], 'ZTSE/root-transition/v2', raw[:215])
    return _accept(_trusts, _Trust(old.account, new_generation, expected, anchor=sha(raw[:215])))


def manifest_identity(token):
    parsed = _bound(_manifests, token)
    return {'profile': parsed.profile, 'account': parsed.trust.account,
            'generation': parsed.trust.generation, 'version': parsed.trust.version,
            'digest': parsed.trust.digest, 'root': parsed.trust.root}


@dataclass(frozen=True)
class Envelope:
    raw: bytes
    profile: int
    kind: int
    prefix: bytes
    account: bytes
    message: bytes
    device: bytes
    line: bytes
    version: int
    digest: bytes
    signer: bytes
    observed: int
    expires: int | None
    peer: str
    nonce: bytes
    body: bytes
    wraps: tuple


def parse_envelope(raw):
    raw = capture(raw, 426, 34213)
    require(raw[:4] == b'ZTSE' and raw[4] in (2, 3), 'envelope profile')
    profile, kind = raw[4], raw[5]
    require(kind in (1, 2) and raw[6:8] == b'\0\0', 'kind/flags')
    require(kind != 2 or len(raw) <= 34082, 'inbound size')
    n = num(raw, 8, 2)
    base = 154 if kind == 1 else 169
    require(base + 3 <= n <= base + 16, 'protected size')
    end = 10 + n
    protected = raw[10:end]
    require(profile != 3 or protected[16:32] != bytes(16), 'profile03 zero message')
    require(protected[base - 1] + base == n, 'peer width')
    peer = protected[base:]
    require(peer[:1] == b'+' and 49 <= peer[1] <= 57 and all(48 <= x <= 57 for x in peer[2:]), 'peer')
    version, observed = num(protected, 64), num(protected, 136)
    expires = num(protected, 144) if kind == 1 else None
    if kind == 1:
        require(protected[152] == 1 and observed < expires <= observed + 900000, 'intent expiry')
    else:
        require(protected[16:32] == protected[144:160] and num(protected, 160) > 0, 'event sequence')
    body_size = num(raw, end + 12, 4)
    require(17 <= body_size <= 32784, 'body size')
    body_end = end + 16 + body_size
    require(body_end < len(raw), 'body truncated')
    count = raw[body_end]
    require((2 if kind == 1 else 1) <= count <= (8 if kind == 1 else 7), 'wrap count')
    require(body_end + 1 + 146 * count + 64 == len(raw), 'exact envelope size')
    wraps = []
    for i in range(count):
        at = body_end + 1 + 146 * i
        role, ident, ephemeral, ciphertext = raw[at], raw[at + 1:at + 33], raw[at + 33:at + 98], raw[at + 98:at + 146]
        require(role in (1, 2, 3) and (not wraps or (role, ident) > wraps[-1][:2]), 'wrap role/order')
        point(ephemeral)
        wraps.append((role, ident, ephemeral, ciphertext))
    require(sum(w[0] == 1 for w in wraps) == (1 if kind == 1 else 0) and sum(w[0] == 2 for w in wraps) == 1, 'recipient roles')
    return Envelope(raw, profile, kind, raw[:end], protected[:16], protected[16:32],
                    protected[32:48], protected[48:64], version, protected[72:104],
                    protected[104:136], observed, expires, peer.decode('ascii'), raw[end:end + 12],
                    raw[end + 16:body_end], tuple(wraps))


def verify_envelope(raw, manifest, *, account, device, line, peer, comparison_ms):
    """Verify signed origin and historical key authority; return no execution capability."""
    p = parse_envelope(raw)
    m = _bound(_manifests, manifest)
    now = integer(comparison_ms)
    window(m.issued, m.expires, now)
    require((p.account, p.device, p.line, p.peer) ==
            (capture(account, 16), capture(device, 16), capture(line, 16), peer), 'routing binding')
    require(p.profile == m.profile and (p.account, p.version, p.digest) ==
            (m.trust.account, m.trust.version, m.trust.digest), 'envelope manifest')
    require(0 < p.observed <= now, 'observation time')
    require(p.kind != 1 or now < p.expires, 'expired intent')
    signer = next((k for k in m.keys if k.role == (5 if p.kind == 1 else 4) and k.id == p.signer), None)
    require(signer is not None and signer.active(now) and signer.line == p.line and
            (p.kind == 1 or signer.device == p.device), 'signer authority')
    if p.profile == 3 and p.kind == 1:
        require(signer.start <= p.observed and p.expires <= signer.end, 'outbound signer lifetime')
    for role, ident, _, _ in p.wraps:
        k = next((k for k in m.keys if k.role == role and k.id == ident), None)
        require(k is not None and k.active(now) and bool(k.scope & (4 if p.kind == 1 else 8)), 'recipient authority')
        require(role != 1 or (k.device, k.line) == (p.device, p.line), 'recipient binding')
        if p.profile == 3 and p.kind == 1:
            require(k.start <= p.observed and p.expires <= k.end, 'outbound recipient lifetime')
    verify_signature(signer.point, p.raw[-64:], f'ZTSE/sign/v{p.profile}', p.raw[:-64])
    return p


class RecipientCustody(Protocol):
    """Provider must hold the selected P-256 key and bind ECDH to its public point.

    A concrete protected provider needs independent platform validation; claiming
    this protocol or returning a boolean does not qualify protected custody.
    """
    def public_point(self) -> bytes: ...
    def exchange(self, ephemeral: bytes) -> bytes: ...


class SoftwareRecipient:
    """Explicit experimental software custody. Keys remain exportable in Python."""
    def __init__(self, key):
        require(isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1), 'recipient key')
        self._key = key

    def public_point(self):
        return self._key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def exchange(self, ephemeral):
        return self._key.exchange(ec.ECDH(), point(ephemeral))


def require_protected_custody(provider):
    from .cng_custody import require_hardware
    return require_hardware(provider)


def _extract(suite, salt, name, ikm):
    return hmac.digest(salt or ZERO, b'HPKE-v1' + suite + name + ikm, 'sha256')


def _expand(suite, prk, name, info, length):
    return HKDFExpand(hashes.SHA256(), length,
                      length.to_bytes(2, 'big') + b'HPKE-v1' + suite + name + info).derive(prk)


def _unwrap(provider, expected_point, ephemeral, ciphertext, info, aad):
    if type(provider) is not SoftwareRecipient:
        require_protected_custody(provider)
    require(provider.public_point() == expected_point, 'custody public binding')
    kem = b'KEM\x00\x10'
    suite = b'HPKE\x00\x10\x00\x01\x00\x01'
    secret_buffers = []
    try:
        dh = bytearray(provider.exchange(ephemeral)); secret_buffers.append(dh)
        eae = bytearray(_extract(kem, b'', b'eae_prk', dh)); secret_buffers.append(eae)
        shared = bytearray(_expand(kem, eae, b'shared_secret', ephemeral + expected_point, 32)); secret_buffers.append(shared)
        context = b'\x00' + _extract(suite, b'', b'psk_id_hash', b'') + _extract(suite, b'', b'info_hash', info)
        secret = bytearray(_extract(suite, shared, b'secret', b'')); secret_buffers.append(secret)
        key = bytearray(_expand(suite, secret, b'key', context, 16)); secret_buffers.append(key)
        nonce = _expand(suite, secret, b'base_nonce', context, 12)
        output = bytearray(32)
        secret_buffers.append(output)
        count = None
        try:
            count = AESGCM(key).decrypt_into(nonce, ciphertext, aad, output)
        except InvalidTag:
            pass
        require(count == 32, 'recipient authentication')
        return bytearray(output)
    finally:
        for value in secret_buffers:
            value[:] = bytes(len(value))


def open_archive_candidate02(raw, historical, current, custody, *, account, device, line, peer, reader_id, now_ms,
                             selection=None, interval=None):
    """Candidate archive read with optional independently verified selected wraps.

    Caller must independently supply trusted current manifest, time and routing.
    This returns text, never a grant, durable replay receipt or dispatch authority.
    """
    parsed = parse_envelope(raw)
    require(parsed.profile == 2 and parsed.kind == 2, 'profile02 inbound required')
    old, live = _bound(_manifests, historical), _bound(_manifests, current)
    now = integer(now_ms)
    require(now >= live.comparison, 'current comparison rollback')
    window(live.issued, live.expires, now)
    require(live.profile == 2 and old.profile == 2 and
            (old.trust.account, old.trust.generation, old.trust.root) ==
            (live.trust.account, live.trust.generation, live.trust.root) and
            old.trust.version <= live.trust.version, 'historical/current root')
    require((old.trust.generation, old.trust.version, old.trust.digest) in live.trust.lineage,
            'historical predecessor not on current chain')
    p = verify_envelope(raw, historical, account=account, device=device, line=line, peer=peer,
                        comparison_ms=parsed.observed)
    require(0 < p.observed <= now, 'future observation')
    reader_id = capture(reader_id, 32)
    if selection is None:
        require(len(p.wraps) == 1 and p.wraps[0][:2] == (2, reader_id), 'archive-only selection required')
    else:
        from .reply_selection import _authorize_archive
        _authorize_archive(selection, p, old, live, interval, reader_id)
    reader = next((k for k in live.keys if k.role == 2 and k.id == reader_id), None)
    require(reader is not None and reader.active(now) and reader.scope & 8, 'current reader revoked')
    wrap = p.wraps[0]
    cek, plaintext = None, None
    try:
        cek = _unwrap(custody, reader.point, wrap[2], wrap[3],
                      label('ZTSE/wrap/v2') + p.prefix + b'\x02' + reader_id, b'')
        plaintext = bytearray(len(p.body) - 16)
        count = None
        try:
            count = AESGCM(cek).decrypt_into(p.nonce, p.body, label('ZTSE/body/v2') + p.prefix, plaintext)
        except InvalidTag:
            pass
        require(count == len(plaintext), 'body authentication')
        require(1 <= len(plaintext) <= 32768 and 0 not in plaintext and not plaintext.startswith(b'\xef\xbb\xbf'), 'body text bounds')
        text = None
        try:
            text = plaintext.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            pass
        require(text is not None, 'body UTF-8')
        return text
    finally:
        for value in (cek, plaintext):
            if value is not None:
                value[:] = bytes(len(value))


def open_archive_protected02(raw, historical, current, custody, **context):
    """Require qualified hardware custody, then use the same closed reader path.

    A current verifier token is not durable authority; use a verified checkpoint
    and independent live authorization before applying any application effect.
    """
    require_protected_custody(custody)
    return open_archive_candidate02(raw, historical, current, custody, **context)
