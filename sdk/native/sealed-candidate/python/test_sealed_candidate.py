"""Real TypeScript producer/native Python consumer and signed shared corpus."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zrotext_native_candidate import sealed_candidate as sealed

ROOT = Path(__file__).resolve().parents[4]


def b64(value):
    return base64.b64decode(value, validate=True)


def signed(unsigned, scalar, domain):
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    r, s = utils.decode_dss_signature(key.sign(sealed.label(domain) + len(unsigned).to_bytes(4, 'big') + unsigned,
                                             ec.ECDSA(hashes.SHA256())))
    return bytes(unsigned) + r.to_bytes(32, 'big') + min(s, sealed.ORDER - s).to_bytes(32, 'big')


class NativeSealed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(subprocess.check_output(
            ['node', str(Path(__file__).with_name('produce-fixture.mjs'))], cwd=ROOT, encoding='utf-8'))

    def setUp(self):
        f = self.fixture
        self.pin = sealed.enroll_root02(b64(f['rootPin']), b64(f['fingerprint']))
        self.manifest = sealed.verify_manifest02(b64(f['manifest']), self.pin, f['now'])
        self.custody = sealed.SoftwareRecipient(ec.derive_private_key(int.from_bytes(b64(f['archiveScalar']), 'big'), ec.SECP256R1()))
        self.scope = dict(account=b64(f['account']), device=b64(f['device']), line=b64(f['line']), peer='+12')
        self.reader = b64(f['reader'])

    def open(self, raw=None, current=None, custody=None, **overrides):
        args = dict(self.scope, reader_id=self.reader, now_ms=self.fixture['now'])
        args.update(overrides)
        return sealed.open_archive_candidate02(raw or b64(self.fixture['inbound']), self.manifest,
            current or self.manifest, custody or self.custody, **args)

    def test_actual_ts_signed_envelope_hpke_and_body_open_natively(self):
        self.assertEqual(self.open(), self.fixture['text'])
        for kind in ('inbound', 'outbound'):
            p = sealed.verify_envelope(b64(self.fixture[kind]), self.manifest,
                                       **self.scope, comparison_ms=self.fixture['now'])
            self.assertEqual(p.kind, 2 if kind == 'inbound' else 1)
            self.assertEqual(p.raw, b64(self.fixture[kind]))

    def test_scope_key_and_role_refusals(self):
        for field in ('account', 'device', 'line'):
            with self.subTest(field=field), self.assertRaises(sealed.SealedError):
                self.open(**{field: bytes(16)})
        for override in ({'peer': '+13'}, {'reader_id': bytes(32)}, {'now_ms': 9999}):
            with self.assertRaises(sealed.SealedError):
                self.open(**override)
        with self.assertRaisesRegex(sealed.SealedError, 'custody public'):
            self.open(custody=sealed.SoftwareRecipient(ec.derive_private_key(2, ec.SECP256R1())))
        with self.assertRaisesRegex(sealed.SealedError, 'inbound required'):
            self.open(raw=b64(self.fixture['outbound']))

    def test_signature_canonicality_domain_and_authenticated_tamper(self):
        original = b64(self.fixture['inbound'])
        high = original[:-32] + (sealed.ORDER - int.from_bytes(original[-32:], 'big')).to_bytes(32, 'big')
        for raw in (high, signed(original[:-64], 6, 'ZTSE/sign/v3')):
            with self.assertRaises(sealed.SealedError):
                self.open(raw)
        for offset in (20, len(original) - 1, len(original) - 65):
            bad = bytearray(original); bad[offset] ^= 1
            with self.assertRaises(sealed.SealedError):
                self.open(bad)

    def test_valid_signature_cannot_bypass_hpke_or_body_authentication(self):
        original = b64(self.fixture['inbound'])
        p = sealed.parse_envelope(original)
        for offset, expected in ((len(original) - 65, 'recipient authentication'),
                                 (len(p.prefix) + 16, 'body authentication')):
            bad = bytearray(original[:-64]); bad[offset] ^= 1
            with self.assertRaisesRegex(sealed.SealedError, expected):
                self.open(signed(bad, 6, 'ZTSE/sign/v2'))

    def test_noncanonical_lengths_profile_flags_order_and_offcurve_refuse(self):
        original = b64(self.fixture['inbound'])
        for offset, value in ((4, 1), (4, 4), (6, 1), (8, 0xff), (9, 0), (10 + 168, 16)):
            bad = bytearray(original); bad[offset] = value
            with self.subTest(offset=offset), self.assertRaises(sealed.SealedError):
                sealed.parse_envelope(bad)
        for raw in (original[:-1], original + b'\0', bytes(40000)):
            with self.assertRaises(sealed.SealedError):
                sealed.parse_envelope(raw)
        bad = bytearray(original)
        at = len(original) - 64 - 146 + 33
        bad[at:at + 65] = b'\x04' + bytes(64)
        with self.assertRaisesRegex(sealed.SealedError, 'point curve'):
            sealed.parse_envelope(bad)

    def test_authenticated_invalid_text_refuses_after_decryption(self):
        original = b64(self.fixture['inbound'])
        p = sealed.parse_envelope(original)
        suffix = original[len(p.prefix) + 16 + len(p.body):-64]
        for text in (b'\x00', b'\xef\xbb\xbftext', b'\xff', b'\xc0\xaf'):
            body = AESGCM(bytes([193]) * 32).encrypt(p.nonce, text, sealed.label('ZTSE/body/v2') + p.prefix)
            unsigned = p.prefix + p.nonce + len(body).to_bytes(4, 'big') + body + suffix
            with self.assertRaises(sealed.SealedError) as failure:
                self.open(signed(unsigned, 6, 'ZTSE/sign/v2'))
            self.assertIsNone(failure.exception.__context__)

    def test_root_and_manifest_chain_negatives(self):
        f = self.fixture
        with self.assertRaisesRegex(sealed.SealedError, 'root comparison'):
            sealed.enroll_root02(b64(f['rootPin']), bytes(32))
        raw = b64(f['manifest'])
        for candidate in (raw + b'\0', raw[:-1], raw[:-32] + (sealed.ORDER - int.from_bytes(raw[-32:], 'big')).to_bytes(32, 'big')):
            with self.assertRaises(sealed.SealedError):
                sealed.verify_manifest02(candidate, self.pin, 10000)
        gap = bytearray(raw[:-64]); gap[29:37] = (3).to_bytes(8, 'big')
        with self.assertRaisesRegex(sealed.SealedError, 'chain'):
            sealed.verify_manifest02(signed(gap, 7, 'ZTSE/manifest/v2'), self.pin, 10000)
        with self.assertRaises(sealed.SealedError):
            sealed.verify_manifest02(raw, self.pin, 100000)
        for bad in (True, -1, 1 << 1000, 10000.0):
            with self.assertRaises(sealed.SealedError):
                sealed.verify_manifest02(raw, self.pin, bad)

    def test_current_revocation_and_fork_do_not_inherit_historical_authority(self):
        raw = bytearray(b64(self.fixture['manifest'])[:-64])
        # Expire the archive record in a signed successor; active state remains
        # structurally valid, but opening must use current time, not capture time.
        raw[29:37] = (2).to_bytes(8, 'big')
        raw[53:85] = sealed.manifest_identity(self.manifest)['digest']
        archive_at = 151 + 149
        raw[archive_at + 140:archive_at + 148] = (10000).to_bytes(8, 'big')
        current = sealed.verify_manifest02(signed(raw, 7, 'ZTSE/manifest/v2'),
                     sealed.advance_trust02(self.pin, self.manifest), 15000)
        with self.assertRaisesRegex(sealed.SealedError, 'current reader revoked'):
            self.open(current=current, now_ms=15000)
        fork = bytearray(b64(self.fixture['manifest'])[:-64])
        fork[archive_at + 140:archive_at + 148] = (99999).to_bytes(8, 'big')
        other = sealed.verify_manifest02(signed(fork, 7, 'ZTSE/manifest/v2'), self.pin, 10000)
        with self.assertRaisesRegex(sealed.SealedError, 'not on current chain'):
            self.open(current=other)

    def test_evidence_copies_and_software_capabilities_do_not_mint_authority(self):
        for forged in (sealed.Evidence(), copy.copy(self.manifest), sealed.manifest_identity(self.manifest)):
            with self.assertRaises(sealed.SealedError):
                sealed.manifest_identity(forged)
        with self.assertRaisesRegex(sealed.SealedError, 'qualified hardware'):
            sealed.require_protected_custody(self.custody)
        class ForgedProvider:
            protected = True
        with self.assertRaisesRegex(sealed.SealedError, 'qualified hardware'):
            sealed.require_protected_custody(ForgedProvider())

    def test_original_buffer_mutation_cannot_change_accepted_manifest(self):
        raw = bytearray(b64(self.fixture['manifest']))
        accepted = sealed.verify_manifest02(raw, self.pin, 10000)
        before = sealed.manifest_identity(accepted)
        raw[:] = bytes(len(raw))
        self.assertEqual(sealed.manifest_identity(accepted), before)

    def test_existing_public_genesis_and_dual_root_rotation_vectors(self):
        path = ROOT / 'sdk/typescript/test/vectors'
        v = json.loads((path / 'draft02-genesis.json').read_text())
        pin = sealed.enroll_root02(b64(v['root_pin_b64']), b64(v['root_fingerprint_b64']))
        m = sealed.verify_manifest02(b64(v['manifest_b64']), pin, v['now_ms'])
        self.assertEqual(sealed.manifest_identity(m)['digest'], b64(v['semantic_manifest_digest_b64']))
        v = json.loads((path / 'draft02-rotation.json').read_text())
        pin = sealed.enroll_root02(b64(v['old_root_pin_b64']), b64(v['old_root_fingerprint_b64']))
        old = sealed.verify_manifest02(b64(v['old_manifest_b64']), pin, v['now_ms'])
        next_pin = sealed.verify_root_transition02(b64(v['transition_b64']),
            sealed.advance_trust02(pin, old), v['now_ms'], b64(v['new_root_point_b64']))
        new = sealed.verify_manifest02(b64(v['new_manifest_b64']), next_pin, v['now_ms'])
        self.assertEqual(sealed.manifest_identity(new)['digest'], b64(v['new_semantic_manifest_digest_b64']))
        with self.assertRaises(sealed.SealedError):
            sealed.verify_root_transition02(b64(v['transition_b64']), pin, v['now_ms'], b64(v['new_root_point_b64']))

    def test_profile03_existing_signed_vector_requires_original02_predecessor(self):
        v = json.loads((ROOT / 'protocol/v1/vectors/sealed-profile03-sdk-outbound-01.json').read_text())
        pin = sealed.enroll_root02(b64(v['root_pin_b64']), b64(v['root_fingerprint_b64']))
        old = sealed.verify_manifest02(b64(v['manifest02_b64']), pin, v['historical_comparison_ms'])
        accepted = sealed.verify_manifest03(b64(v['manifest03_b64']), old, v['now_ms'])
        self.assertEqual(sealed.manifest_identity(accepted)['digest'], b64(v['manifest03_digest_b64']))
        p = sealed.verify_envelope(b64(v['envelope_b64']), accepted,
            account=b64(v['account_id_b64']), device=b64(v['device_id_b64']), line=b64(v['line_id_b64']),
            peer=b64(v['peer_b64']).decode(), comparison_ms=v['now_ms'])
        self.assertEqual(sealed.sha(p.raw[:-64]), b64(v['unsigned_sha256_b64']))
        self.assertEqual(sealed.label('ZTSE/body/v3') + p.prefix, b64(v['body_aad_b64']))
        zero_message = bytearray(p.raw)
        zero_message[26:42] = bytes(16)
        with self.assertRaisesRegex(sealed.SealedError, 'zero message'):
            sealed.parse_envelope(zero_message)
        successor = sealed.verify_manifest03(b64(v['successor03_b64']), accepted, v['now_ms'])
        self.assertEqual(sealed.manifest_identity(successor)['digest'], b64(v['successor03_digest_b64']))
        for predecessor in (sealed.Evidence(), self.manifest, accepted):
            with self.assertRaises(sealed.SealedError):
                sealed.verify_manifest03(b64(v['manifest03_b64']), predecessor, v['now_ms'])
        with self.assertRaisesRegex(sealed.SealedError, 'profile02 inbound'):
            self.open(b64(v['envelope_b64']))


if __name__ == '__main__':
    unittest.main()
