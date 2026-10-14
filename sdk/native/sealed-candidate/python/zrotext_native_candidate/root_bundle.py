"""Public root custody integrity; no backup decryption, restore or authority."""
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from . import sealed_candidate as s
from .contact_integrity import _origin


class RootBundleError(ValueError):
    """The bundle does not match the independently compared public identity."""


@dataclass(frozen=True)
class ComparedRootBundle:
    trust: s.Evidence
    root_pin: bytes
    encrypted_backup: bytes
    public_card: bytes


def verify_published_root_bundle(intended_pin, compared_fingerprint, intended_origin, published):
    """Capture public bytes and verify the maintained custody transcript.

    The pin, fingerprint and origin must come from independent comparison.
    Success does not authenticate backup AEAD or establish fresh authority.
    """
    try:
        return _verify(intended_pin, compared_fingerprint, intended_origin, published)
    except Exception:
        raise RootBundleError('Root custody bundle or independent identity invalid') from None


def _verify(intended_pin, compared_fingerprint, intended_origin, published):
    s.require(type(published) is dict, 'published record')
    values=dict(published)
    pin=s.capture(intended_pin,94);compared=s.capture(compared_fingerprint,32)
    received=s.capture(values['rootPin'],94)
    backup=s.capture(values['encryptedBackup'],0,748)
    card=s.capture(values['publicCard'],0,645)
    unsigned=s.capture(values['unsignedEnrollment'],0,663)
    signature=s.capture(values['custodySignature'],64)
    origin=_origin(intended_origin).encode('ascii');n=len(origin)
    s.require(pin==received and len(backup)==236+n and len(card)==133+n and len(unsigned)==151+n,'bundle dimensions')
    s.require(backup[:6]==b'ZTRB\x01\x01' and any(backup[6:22]) and backup[22:38]==pin[5:21]
              and s.num(backup,38)==1 and backup[46:78]==compared and s.num(backup,78,2)==n
              and backup[80:80+n]==origin and s.num(backup,184+n,4)==48,'backup framing')
    s.require(card[:5]==b'ZTRC\x01' and s.num(card,5,2)==n and card[7:7+n]==origin
              and card[7+n:101+n]==pin,'card framing')
    s.require(unsigned[:5]==b'ZTRE\x01' and unsigned[5:21]==pin[5:21] and unsigned[101:133]==compared
              and s.num(unsigned,149,2)==n and unsigned[151:]==origin,'enrollment framing')
    s.require(all(any(unsigned[offset:offset+16]) for offset in (5,21,37,53)),'enrollment identity')
    issued=s.num(unsigned,133);expires=s.num(unsigned,141)
    s.require(issued>0 and 0<expires-issued<=300000,'enrollment interval')
    r=int.from_bytes(signature[:32],'big');low_s=int.from_bytes(signature[32:],'big')
    s.require(0<r<s.ORDER and 0<low_s<=s.ORDER//2,'canonical signature')
    trust=s.enroll_root02(pin,compared)
    backup_digest=s.sha(backup);card_digest=s.sha(card)
    s.require(card[101+n:]==backup_digest,'backup digest')
    # Only unsigned enrollment is length-framed; digest trailers are outside it.
    transcript=s.label('ZTSE/root-custody/v1')+len(unsigned).to_bytes(4,'big')+unsigned+backup_digest+card_digest+compared
    s.point(pin[29:]).verify(utils.encode_dss_signature(r,low_s),transcript,ec.ECDSA(hashes.SHA256()))
    return ComparedRootBundle(trust,pin,backup,card)
