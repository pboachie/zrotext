# SPDX-License-Identifier: AGPL-3.0-only
"""Independent struct/schema checks; signatures run in the SDK test suite."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
UUIDS = "accountId deviceId lineId bindingId ownerUserId ownerSessionId intervalId messageId".split()
NUMBERS = "bindingGeneration vaultGeneration manifestVersion accountSelectionEpoch observedMs messageExpiresMs reviewIssuedMs reviewExpiresMs".split()
DIGESTS = "selectedReaderKeyId rootFingerprint manifestDigest electionCommitment electionBundleSha256 ownerSessionDigest originDigest signerKeyId envelopeDigest unsignedDigest".split()


def encode(fields):
    result = bytearray(b"ZTRI\x02\x03\x03\x00")
    for name in UUIDS:
        result += bytes.fromhex(fields[name])
    for name in NUMBERS:
        result += struct.pack(">Q", int(fields[name]))
    for name in DIGESTS:
        result += bytes.fromhex(fields[name])
    peer = bytes.fromhex(fields["peer"])
    result += bytes([len(peer)]) + peer + bytes([len(fields["recipients"])])
    for recipient in fields["recipients"]:
        result += bytes([recipient["role"]]) + bytes.fromhex(recipient["keyId"])
    return bytes(result) + bytes([fields["smsCeiling"]])


class ReviewedIntentV2Vectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((ROOT / "vectors/reviewed-intent03-v2.json").read_text())
        schema = json.loads((ROOT / "reviewed-intent03-v2.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema)

    def test_independent_bytes_offsets_and_signature_domain_hashes(self):
        lengths = []
        for case in self.vectors["cases"]:
            with self.subTest(case=case["name"]):
                fields = case["fields"]
                self.validator.validate(fields)
                self.assertNotIn("bodyDigest", fields)
                intent = encode(fields)
                self.assertEqual(intent.hex(), case["intent_hex"])
                peer = bytes.fromhex(fields["peer"])
                self.assertEqual(intent[520], len(peer))
                self.assertEqual(intent[521:521+len(peer)], peer)
                self.assertEqual(intent[521+len(peer)], len(fields["recipients"]))
                self.assertEqual(intent[456:488].hex(), fields["envelopeDigest"])
                self.assertEqual(intent[488:520].hex(), fields["unsignedDigest"])
                self.assertEqual(len(intent), 523 + len(peer) + 33 * len(fields["recipients"]))
                transcript = b"zrotext/conversation/reviewed-send03/v2\0" + struct.pack(">I", len(intent)) + intent
                self.assertEqual(hashlib.sha256(intent).hexdigest(), case["intent_sha256"])
                self.assertEqual(hashlib.sha256(transcript).hexdigest(), case["transcript_sha256"])
                lengths.append(len(intent))
        self.assertEqual(lengths, [592, 803, 592])

    def test_structural_schema_refuses_extra_body_fields_and_wrong_shape(self):
        fields = self.vectors["cases"][0]["fields"]
        for name, value in [("bodyDigest", "00"*32), ("body", "Synthetic"), ("smsCeiling", 0),
                            ("smsCeiling", 7), ("smsCeiling", "1"), ("smsCeiling", True),
                            ("accountSelectionEpoch", "2"), ("vaultGeneration", "2"),
                            ("accountId", "00"*16), ("originDigest", "00"*32),
                            ("peer", b"+01".hex()), ("peer", b"+1".hex())]:
            with self.subTest(name=name, value=value):
                self.assertFalse(self.validator.is_valid(dict(fields, **{name: value})))
        absent = dict(fields)
        del absent["smsCeiling"]
        self.assertFalse(self.validator.is_valid(absent))
        bad = copy.deepcopy(fields)
        bad["recipients"].reverse()
        self.assertFalse(self.validator.is_valid(bad))

    def test_decimal_strings_have_exact_positive_signed63_bounds(self):
        fields = self.vectors["cases"][0]["fields"]
        for value in [1, 9, 10, 10**18-1, 10**18, 9*10**18, 2**63-2, 2**63-1]:
            self.validator.validate(dict(fields, manifestVersion=str(value)))
        for value in ["0", "-1", "+1", "01", "1.0", str(2**63), str(10**19), 1, True]:
            self.assertFalse(self.validator.is_valid(dict(fields, manifestVersion=value)), value)
        # Each decimal prefix decision is checked around the exact upper bound.
        limit = str(2**63-1)
        for i in range(len(limit)):
            for digit in "0123456789":
                value = limit[:i] + digit + limit[i+1:]
                expected = value[0] != "0" and 1 <= int(value) <= 2**63-1
                self.assertEqual(self.validator.is_valid(dict(fields, manifestVersion=value)), expected, value)

    def test_historical_v1_fixture_keeps_its_separate_header_and_body_slot(self):
        historical = json.loads((ROOT / "vectors/reviewed-intent03.json").read_text())
        for case in historical["cases"]:
            intent = bytes.fromhex(case["intent_hex"])
            self.assertEqual(intent[:8], b"ZTRI\x01\x03\x03\x00")
            self.assertEqual(intent[520:552].hex(), case["fields"]["bodyDigest"])
            self.assertEqual(hashlib.sha256(intent).hexdigest(), case["intent_sha256"])


if __name__ == "__main__":
    unittest.main()
