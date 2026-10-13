"""Real TS election/composition to native Python proof and protected opening."""
import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from zrotext_native_candidate import election03 as election
from zrotext_native_candidate import sealed_candidate as s
from zrotext_native_candidate.checkpoint_store import CheckpointStore
from zrotext_native_candidate.cng_custody import HardwareRecipient, CngUnavailable, probe_platform
from test_sealed_candidate import signed

ROOT = Path(__file__).resolve().parents[4]


def decode(value):
    return base64.b64decode(value, validate=True)


def record(value):
    return {name: decode(item) if type(item) is str else item for name, item in value.items()}


def produce(public=None):
    args = ['node', str(Path(__file__).with_name('produce-election03.mjs'))]
    if public is not None:
        args += ['--recipient-point', public.hex()]
    return json.loads(subprocess.check_output(args, cwd=ROOT, encoding='utf-8'))


def prepare(fixture):
    pin = s.enroll_root02(decode(fixture['rootPin']), decode(fixture['fingerprint']))
    prior = s.verify_manifest02(decode(fixture['signed02']), pin, 10000)
    manifest = s.verify_manifest03(decode(fixture['signed03']), prior, 10000)
    args = dict(bundle=decode(fixture['bundle']), expected_core=decode(fixture['core']),
                accepted_record=record(fixture['accepted']), predecessor02=prior,
                prior_signed02=decode(fixture['signed02']), accepted_signed03=decode(fixture['signed03']),
                device_signing_point=decode(fixture['deviceSigningPoint']), owner_approval_point=decode(fixture['ownerApprovalPoint']))
    proof = election.verify_accepted_election03(**args)
    return manifest, proof, args


class ElectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = produce()

    def setUp(self):
        self.manifest, self.proof, self.proof_args = prepare(self.fixture)
        self.authority = record(self.fixture['authority'])
        self.custody = s.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(self.fixture['readerScalar']), 'big'), ec.SECP256R1()))

    def open(self, **overrides):
        args = dict(raw=decode(self.fixture['envelope']), manifest=self.manifest, proof=self.proof,
                    current_authority=self.authority, custody=self.custody,
                    expected_message_id=decode(self.fixture['message']), expected_peer='+12', now_ms=30000,
                    require_hardware=False)
        args.update(overrides)
        return election.open_elected_outbound03(**args)

    def test_actual_ts_election_and_ciphertext_open_with_exact_nonempty_aad(self):
        opened = self.open()
        self.assertEqual(opened.text, self.fixture['bodyText'])
        self.assertEqual(opened.envelope_digest, s.sha(decode(self.fixture['envelope'])))
        self.assertEqual(opened.unsigned_digest, s.sha(decode(self.fixture['envelope'])[:-64]))
        # Challenge expired at20000; historical proof remains valid, independent
        # current permission expires at60000. This does not renew a live grant.
        self.assertEqual(election.require_current_election03(self.proof, self.manifest, self.authority, 30000)['bindingGeneration'], 7)

    def test_software_never_qualifies_default_protected_path(self):
        with self.assertRaisesRegex(s.SealedError, 'qualified hardware'):
            self.open(require_hardware=True)
        with self.assertRaisesRegex(s.SealedError, 'hardware policy'):
            self.open(require_hardware='false')

    def test_current_authority_substitutions_refuse_before_unwrap(self):
        for name, value in self.authority.items():
            altered = dict(self.authority)
            if type(value) is bytes:
                altered[name] = bytes([value[0] ^ 1]) + value[1:]
            elif name == 'permissionExpiresAtMs':
                altered[name] = 30000
            elif name == 'comparedAtMs':
                altered[name] = 30001
            else:
                altered[name] = value + 1
            with self.subTest(field=name), patch.object(s, '_unwrap') as unwrap:
                with self.assertRaises(s.SealedError):
                    self.open(current_authority=altered)
                unwrap.assert_not_called()
        with self.assertRaises(s.SealedError):
            self.open(current_authority=dict(self.authority, extra='untrusted'))

    def test_caller_identity_and_expiry_are_independent(self):
        for changed in ({'expected_peer': '+13'}, {'expected_message_id': bytes([2]) * 16},
                        {'now_ms': 29999}, {'now_ms': 40000}, {'proof': s.Evidence()}):
            with self.subTest(change=changed), self.assertRaises(s.SealedError):
                self.open(**changed)

    def test_exact_original_signed_evidence_not_semantic_alias(self):
        for field, scalar, domain in (('prior_signed02', 7, 'ZTSE/manifest/v2'),
                                     ('accepted_signed03', 7, 'ZTSE/manifest/v3')):
            args = dict(self.proof_args)
            args[field] = signed(args[field][:-64], scalar, domain)
            self.assertNotEqual(args[field], self.proof_args[field])
            with self.assertRaises(s.SealedError):
                election.verify_accepted_election03(**args)
        args = dict(self.proof_args, predecessor02=self.manifest)
        with self.assertRaisesRegex(s.SealedError, 'original profile02'):
            election.verify_accepted_election03(**args)

    def test_independently_accepted_evidence_hashes_and_closed_records(self):
        for name in election._ACCEPTED_DIGESTS:
            a = dict(self.proof_args['accepted_record'])
            a[name] = bytes([a[name][0] ^ 1]) + a[name][1:]
            with self.subTest(field=name), self.assertRaises(s.SealedError):
                election.verify_accepted_election03(**dict(self.proof_args, accepted_record=a))
        for name in election._ACCEPTED_TIMES:
            a = dict(self.proof_args['accepted_record']); a[name] = True
            with self.assertRaises(s.SealedError):
                election.verify_accepted_election03(**dict(self.proof_args, accepted_record=a))
        with self.assertRaisesRegex(s.SealedError, 'closed'):
            election.verify_accepted_election03(**dict(self.proof_args, accepted_record=dict(self.proof_args['accepted_record'], current=True)))

    def test_both_low_s_signatures_and_owner_binding_to_device_signature(self):
        for offset in (500, 564):
            bundle = bytearray(self.proof_args['bundle'])
            scalar = int.from_bytes(bundle[offset + 32:offset + 64], 'big')
            bundle[offset + 32:offset + 64] = (s.ORDER - scalar).to_bytes(32, 'big')
            a = dict(self.proof_args['accepted_record'], electionBundleSha256=s.sha(bundle))
            with self.assertRaisesRegex(s.SealedError, 'low-S'):
                election.verify_accepted_election03(**dict(self.proof_args, bundle=bundle, accepted_record=a))
        bundle = self.proof_args['bundle']
        wrong_owner = signed(bundle[:500] + bytes(32), 9, 'ZTSE/line/payload-profile/owner/v1')[-64:]
        changed = bundle[:564] + wrong_owner
        a = dict(self.proof_args['accepted_record'], electionBundleSha256=s.sha(changed))
        with self.assertRaisesRegex(s.SealedError, 'signature verification'):
            election.verify_accepted_election03(**dict(self.proof_args, bundle=changed, accepted_record=a))

    def test_authenticated_wrap_tamper_and_wrong_aad_refuse(self):
        raw = decode(self.fixture['envelope'])
        p = s.parse_envelope(raw)
        offset = len(p.prefix) + 16 + len(p.body) + 1 + 145
        changed = bytearray(raw[:-64]); changed[offset] ^= 1
        with self.assertRaisesRegex(s.SealedError, 'recipient authentication'):
            self.open(raw=signed(changed, 5, 'ZTSE/sign/v3'))
        real_unwrap = s._unwrap
        with patch.object(s, '_unwrap', side_effect=lambda provider, public, enc, ct, info, aad:
                          real_unwrap(provider, public, enc, ct, info, b'')):
            with self.assertRaisesRegex(s.SealedError, 'recipient authentication'):
                self.open()

    def test_input_snapshots_and_forged_proof_refusal(self):
        args = dict(self.proof_args)
        a = dict(args['accepted_record'])
        original = bytearray(a['electionCommitment']); a['electionCommitment'] = original
        proof = election.verify_accepted_election03(**dict(args, accepted_record=a))
        original[:] = bytes(32)
        self.assertEqual(self.open(proof=proof).text, self.fixture['bodyText'])
        with self.assertRaises(s.SealedError):
            self.open(proof=copy.copy(proof))

    @unittest.skipUnless(os.name == 'nt', 'Windows TPM only; not protected acceptance')
    def test_actual_tpm_elected_reader_opens_ts_composed_profile03(self):
        try:
            probe_platform()
        except CngUnavailable as error:
            self.skipTest(f'No hardware provider: {error.operation}')
        fd, receipt_path = tempfile.mkstemp(prefix='zrotext-election-cng-', suffix='.json')
        os.close(fd)
        def record_alias(name):
            with open(receipt_path, 'w', encoding='utf-8') as receipt:
                json.dump({'pending_alias': name}, receipt); receipt.flush(); os.fsync(receipt.fileno())
        key = HardwareRecipient.create(record_alias)
        try:
            f = produce(key.public_point())
            manifest, proof, _ = prepare(f)
            self.assertNotIn('readerScalar', f)
            with tempfile.TemporaryDirectory(prefix='zrotext-election-checkpoint-') as folder:
                store = CheckpointStore(Path(folder) / 'checkpoint.sqlite', decode(f['rootPin']), decode(f['fingerprint']))
                store.accept_manifest(decode(f['signed02']), 0, 10000)
                store.accept_manifest(decode(f['signed03']), 1, 10000)
                _, manifest = store.snapshot(30000)
                with HardwareRecipient.open(key.name, key.public_point()) as reopened:
                    result = election.open_elected_outbound03(decode(f['envelope']), manifest, proof, record(f['authority']), reopened,
                        expected_message_id=decode(f['message']), expected_peer='+12', now_ms=30000)
                    self.assertEqual(result.text, f['bodyText'])
        finally:
            key.delete()
            with open(receipt_path, 'w', encoding='utf-8') as receipt:
                json.dump({'owned_test_key_deleted': True}, receipt); receipt.flush(); os.fsync(receipt.fileno())


if __name__ == '__main__':
    unittest.main()
