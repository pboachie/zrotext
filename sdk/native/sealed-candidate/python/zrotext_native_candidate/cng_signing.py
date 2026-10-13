"""Locally qualified TPM ECDSA signing, without software fallback."""
import ctypes
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from . import sealed_candidate as s
from .cng_custody import HardwareRecipient, _qualified, SILENT


class HardwareSigner(HardwareRecipient):
    _algorithm = 'ECDSA_P256'
    _prefix = 'zrotext-candidate-sign-p256-'
    _public_magic = 0x31534345

    def _qualify(self):
        self._qualify_policy()
        challenge = os.urandom(32)
        signature = self._sign_digest(challenge)
        s.point(self.public_point()).verify(utils.encode_dss_signature(
            int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')),
            challenge, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    def _sign_digest(self, digest):
        digest = s.capture(digest, 32)
        with self._lock:
            s.require(not self._closed, 'closed signing custody')
            data = ctypes.create_string_buffer(digest)
            output, size = ctypes.create_string_buffer(64), self._api.U()
            self._api.call('NCryptSignHash', self._key, None, data, 32, output, 64, ctypes.byref(size), SILENT)
            s.require(size.value == 64, 'CNG ECDSA signature width')
            r, value = int.from_bytes(output.raw[:32], 'big'), int.from_bytes(output.raw[32:], 'big')
            s.require(0 < r < s.ORDER and 0 < value < s.ORDER, 'ECDSA scalar range')
            return r.to_bytes(32, 'big') + min(value, s.ORDER - value).to_bytes(32, 'big')

    def sign(self, domain, unsigned):
        require_hardware_signer(self)
        s.require(type(domain) is str and domain in ('ZTSE/sign/v2', 'ZTSE/sign/v3'), 'outbound signing domain')
        unsigned = s.capture(unsigned, 493, 34149)
        signature = self._sign_digest(s.sha(s.label(domain) + len(unsigned).to_bytes(4, 'big') + unsigned))
        s.verify_signature(self.public_point(), signature, domain, unsigned)
        return signature

    def exchange(self, ephemeral):
        raise s.SealedError('signing custody cannot derive recipient secrets')


def require_hardware_signer(provider):
    s.require(type(provider) is HardwareSigner and provider in _qualified and not provider._closed,
              'qualified hardware signer required')
    return provider
