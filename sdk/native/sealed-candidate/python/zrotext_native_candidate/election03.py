"""Native profile03 election proof relative to independently authenticated records.

No backend read, session/MFA, atomic election commit, device attestation, live
grant or radio authority is supplied. Historical signatures do not renew access.
"""
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakKeyDictionary

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import sealed_candidate as s

_ACCEPTED_UUIDS = ('accountId', 'deviceId', 'lineId', 'oldBindingId', 'newBindingId')
_ACCEPTED_TIMES = ('vaultGeneration', 'oldBindingGeneration', 'newBindingGeneration',
                   'priorManifestVersion', 'acceptedManifestVersion', 'acceptedAtMs')
_ACCEPTED_DIGESTS = ('rootFingerprint', 'oldBindingProofDigest', 'selectedReaderKeyId',
                    'priorManifestDigest', 'priorSignedManifestSha256', 'acceptedManifestDigest',
                    'acceptedSignedManifestSha256', 'electionCoreSha256', 'electionCommitment', 'electionBundleSha256')
_CURRENT_UUIDS = ('accountId', 'deviceId', 'lineId', 'bindingId')
_CURRENT_TIMES = ('bindingGeneration', 'vaultGeneration', 'manifestVersion', 'comparedAtMs', 'permissionExpiresAtMs')
_CURRENT_DIGESTS = ('selectedReaderKeyId', 'rootFingerprint', 'manifestDigest', 'electionCommitment', 'electionBundleSha256')
_proofs = WeakKeyDictionary()


def positive(value):
    s.integer(value)
    s.require(value > 0, 'positive election integer')
    return value


def _record(value, uuids, times, digests, extra=()):
    s.require(type(value) is dict and set(value) == set(uuids + times + digests + extra), 'closed election record')
    out = dict(value)
    for name in uuids + digests:
        out[name] = s.capture(out[name], 16 if name in uuids else 32)
        s.require(any(out[name]), 'zero election identity/digest')
    for name in times:
        positive(out[name])
    return out


def capture_current(value):
    out = _record(value, _CURRENT_UUIDS, _CURRENT_TIMES, _CURRENT_DIGESTS, ('profile', 'manifestProfile'))
    s.require(type(out['profile']) is int and out['profile'] == 3 and
              type(out['manifestProfile']) is int and out['manifestProfile'] == 3 and
              out['permissionExpiresAtMs'] > out['comparedAtMs'], 'current profile/deadline')
    return out


def framed(domain, payload):
    return s.label(domain) + len(payload).to_bytes(4, 'big') + payload


def verify_accepted_election03(*, bundle, expected_core, accepted_record, predecessor02,
                             prior_signed02, accepted_signed03, device_signing_point, owner_approval_point):
    """Verify historical evidence against an authenticated immutable commit record.

    The caller must independently authenticate expected_core, accepted_record,
    and both registry signing points. Echoing received packet fields is unsafe.
    """
    bundle, expected = s.capture(bundle, 628), s.capture(expected_core, 500)
    a = _record(accepted_record, _ACCEPTED_UUIDS, _ACCEPTED_TIMES, _ACCEPTED_DIGESTS)
    signed02, signed03 = s.capture(prior_signed02, 364, 9751), s.capture(accepted_signed03, 366, 9753)
    device_point, owner_point = s.capture(device_signing_point, 65), s.capture(owner_approval_point, 65)
    prior = s._bound(s._manifests, predecessor02)
    s.require(prior.profile == 2 and signed02 == prior.raw and a['acceptedAtMs'] >= prior.comparison,
              'original profile02 evidence/comparison')
    s.window(prior.issued, prior.expires, a['acceptedAtMs'])
    core = bundle[:500]
    s.require(core == expected and core[:8] == b'ZTPE\x03\x01\x02\x03' and
              core[496:] == bytes(4) and any(core[56:72]) and any(core[352:384]), 'election framing/challenge')
    for at, name in ((8, 'accountId'), (24, 'deviceId'), (40, 'lineId'), (72, 'oldBindingId'),
                     (104, 'oldBindingProofDigest'), (136, 'rootFingerprint'), (184, 'priorManifestDigest'),
                     (224, 'acceptedManifestDigest'), (256, 'selectedReaderKeyId')):
        s.require(core[at:at + len(a[name])] == a[name], 'accepted election field')
    for at, name in ((88, 'oldBindingGeneration'), (96, 'newBindingGeneration'), (168, 'vaultGeneration'),
                     (176, 'priorManifestVersion'), (216, 'acceptedManifestVersion')):
        s.require(s.num(core, at) == a[name], 'accepted election integer')
    issued, expires = positive(s.num(core, 384)), positive(s.num(core, 392))
    s.require(issued <= a['acceptedAtMs'] < expires and expires - issued <= 300000 and
              a['newBindingGeneration'] > a['oldBindingGeneration'] and a['vaultGeneration'] == 1 and
              a['priorManifestVersion'] < s.MAX and a['acceptedManifestVersion'] == a['priorManifestVersion'] + 1 and
              all(any(core[at:at + 32]) for at in (400, 432, 464)), 'election acceptance range/context')
    for value, field in ((signed02, 'priorSignedManifestSha256'), (signed03, 'acceptedSignedManifestSha256'),
                         (core, 'electionCoreSha256'), (bundle, 'electionBundleSha256'),
                         (framed('ZTSE/line/payload-profile/commitment/v1', core), 'electionCommitment')):
        s.require(s.sha(value) == a[field], 'original election evidence digest')
    accepted_manifest = s.verify_manifest03(signed03, predecessor02, a['acceptedAtMs'])
    identity = s.manifest_identity(accepted_manifest)
    s.require((identity['account'], identity['generation'], identity['version'], identity['digest']) ==
              (a['accountId'], a['vaultGeneration'], a['acceptedManifestVersion'], a['acceptedManifestDigest']) and
              (prior.trust.version, prior.trust.digest) == (a['priorManifestVersion'], a['priorManifestDigest']),
              'accepted manifest binding')
    root_pin = b'ZTRP\x02' + identity['account'] + identity['generation'].to_bytes(8, 'big') + identity['root']
    s.require(s.sha(s.label('ZTSE/root-pin/v2') + root_pin) == a['rootFingerprint'], 'election root fingerprint')
    s.require(s.key_id(4, device_point) == core[288:320] and s.key_id(6, owner_point) == core[320:352],
              'election registry signing key')
    device_signature = bundle[500:564]
    s.verify_signature(device_point, device_signature, 'ZTSE/line/payload-profile/device/v1', core)
    s.verify_signature(owner_point, bundle[564:], 'ZTSE/line/payload-profile/owner/v1', core + s.sha(device_signature))
    return s._accept(_proofs, (MappingProxyType(a), identity['root']))


def require_current_election03(proof, manifest, current_authority, now_ms):
    """Compare independent present authority; no historical permission renewal."""
    now = positive(now_ms)
    a, root = s._bound(_proofs, proof)
    c = capture_current(current_authority)
    s.require(now >= a['acceptedAtMs'] and now >= c['comparedAtMs'] and now < c['permissionExpiresAtMs'],
              'current election time/permission')
    for current, accepted in (('accountId', 'accountId'), ('deviceId', 'deviceId'), ('lineId', 'lineId'),
                              ('bindingId', 'newBindingId'), ('selectedReaderKeyId', 'selectedReaderKeyId'),
                              ('rootFingerprint', 'rootFingerprint'), ('electionCommitment', 'electionCommitment'),
                              ('electionBundleSha256', 'electionBundleSha256')):
        s.require(c[current] == a[accepted], 'current election binding')
    s.require(c['bindingGeneration'] == a['newBindingGeneration'] and c['vaultGeneration'] == a['vaultGeneration'] and
              c['manifestVersion'] >= a['acceptedManifestVersion'], 'current election generation/version')
    m = s._bound(s._manifests, manifest)
    s.window(m.issued, m.expires, now)
    s.require(now >= m.comparison and m.profile == 3 and
              (m.trust.account, m.trust.root, m.trust.generation, m.trust.version, m.trust.digest) ==
              (c['accountId'], root, c['vaultGeneration'], c['manifestVersion'], c['manifestDigest']), 'current election manifest')
    s.require((a['vaultGeneration'], a['acceptedManifestVersion'], a['acceptedManifestDigest']) in m.trust.lineage,
              'accepted election not on current manifest lineage')
    return MappingProxyType(c)


@dataclass(frozen=True)
class OpenedCandidate:
    text: str
    envelope_digest: bytes
    unsigned_digest: bytes


def open_elected_outbound03(raw, manifest, proof, current_authority, custody, *, expected_message_id, expected_peer,
                           now_ms, require_hardware=True):
    """Authenticate and open current profile03 ciphertext; never authorize SMS.

    Live grant, audience permission, replay journal and maintained receiver checks
    remain mandatory outside this cryptographic candidate. Software tests must
    explicitly opt out of hardware custody; there is no automatic fallback.
    """
    s.require(type(require_hardware) is bool, 'hardware policy type')
    c = require_current_election03(proof, manifest, current_authority, now_ms)
    expected = s.capture(expected_message_id, 16)
    s.require(any(expected), 'nonzero expected message')
    p = s.verify_envelope(raw, manifest, account=c['accountId'], device=c['deviceId'], line=c['lineId'],
                          peer=expected_peer, comparison_ms=now_ms)
    s.require(p.profile == 3 and p.kind == 1 and p.message == expected, 'elected envelope identity/profile')
    m = s._bound(s._manifests, manifest)
    s.require(p.expires <= min(m.expires, c['permissionExpiresAtMs']), 'envelope authority deadline')
    wrap = next((w for w in p.wraps if w[:2] == (1, c['selectedReaderKeyId'])), None)
    reader = next((k for k in m.keys if k.role == 1 and k.id == c['selectedReaderKeyId']), None)
    s.require(wrap is not None and reader is not None and reader.active(now_ms), 'elected reader')
    if require_hardware:
        s.require_protected_custody(custody)
    cek, plaintext = None, None
    try:
        suffix = p.prefix + b'\x01' + wrap[1]
        cek = s._unwrap(custody, reader.point, wrap[2], wrap[3], s.label('ZTSE/wrap/v3') + suffix,
                        s.label('ZTSE/wrap-aad/v3') + suffix)
        plaintext = bytearray(len(p.body) - 16)
        count = None
        try:
            count = AESGCM(cek).decrypt_into(p.nonce, p.body, s.label('ZTSE/body/v3') + p.prefix, plaintext)
        except InvalidTag:
            pass
        s.require(count == len(plaintext), 'profile03 body authentication')
        s.require(1 <= len(plaintext) <= 32768 and 0 not in plaintext and not plaintext.startswith(b'\xef\xbb\xbf'), 'body text bounds')
        text = None
        try:
            text = plaintext.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            pass
        s.require(text is not None, 'body UTF-8')
        return OpenedCandidate(text, s.sha(p.raw), s.sha(p.raw[:-64]))
    finally:
        for value in (cek, plaintext):
            if value is not None:
                value[:] = bytes(len(value))
