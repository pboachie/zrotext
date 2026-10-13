"""Candidate body authentication only; not a sealed reader or authority verifier."""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CandidateBodyError(ValueError):
    """Redacted failure with a stable code, never plaintext or key diagnostics."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _snapshot(value, minimum, maximum):
    if type(value) not in (bytes, bytearray) or not minimum <= len(value) <= maximum:
        raise CandidateBodyError("shape")
    return bytearray(value)


def _decode(raw):
    if not 1 <= len(raw) <= 32768:
        raise CandidateBodyError("length")
    if 0 in raw:
        raise CandidateBodyError("nul")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise CandidateBodyError("bom")
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    # Raise outside the handler so the returned error retains no decoder error
    # object (UnicodeDecodeError itself carries the rejected plaintext bytes).
    raise CandidateBodyError("utf8")


def decode(raw):
    """Validate text bytes only. This function does not authenticate them."""
    if type(raw) not in (bytes, bytearray):
        raise CandidateBodyError("shape")
    if not 1 <= len(raw) <= 32768:
        raise CandidateBodyError("length")
    owned = bytearray(raw)
    try:
        return _decode(owned)
    finally:
        owned[:] = b"\0" * len(owned)


def open_body(key, nonce, verified_aad, ciphertext):
    """Authenticate with an independently recovered CEK and verified AAD.

    Caller must establish manifest, signer, scope, expiry, replay and HPKE
    provenance independently. Successful authentication grants no permission.
    Caller buffers remain owned by the caller; internal mutable copies are wiped.
    Returned text and provider-internal copies have no secure-erasure guarantee.
    """
    owned = []
    plaintext = None
    try:
        key_copy = _snapshot(key, 32, 32)
        owned.append(key_copy)
        nonce_copy = _snapshot(nonce, 12, 12)
        owned.append(nonce_copy)
        aad_copy = _snapshot(verified_aad, 1, 36864)
        owned.append(aad_copy)
        ciphertext_copy = _snapshot(ciphertext, 17, 32784)
        owned.append(ciphertext_copy)
        plaintext = bytearray(len(ciphertext_copy) - 16)
        try:
            count = AESGCM(key_copy).decrypt_into(nonce_copy, ciphertext_copy, aad_copy, plaintext)
        except InvalidTag:
            raise CandidateBodyError("authentication") from None
        if count != len(plaintext):
            raise CandidateBodyError("authentication")
        # No text decoding or return occurs before authenticated decryption ends.
        return _decode(plaintext)
    finally:
        if plaintext is not None:
            plaintext[:] = b"\0" * len(plaintext)
        for value in owned:
            value[:] = b"\0" * len(value)
