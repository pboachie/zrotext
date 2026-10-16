# SPDX-License-Identifier: AGPL-3.0-only
"""Independent struct-based candidate ZTRI01 byte/timing vectors, no service."""
import hashlib
import json
from pathlib import Path
import struct
import unittest

UUIDS = "accountId deviceId lineId bindingId ownerUserId ownerSessionId intervalId messageId".split()
NUMBERS = "bindingGeneration vaultGeneration manifestVersion accountSelectionEpoch observedMs messageExpiresMs reviewIssuedMs reviewExpiresMs".split()
DIGESTS = "selectedReaderKeyId rootFingerprint manifestDigest electionCommitment electionBundleSha256 ownerSessionDigest originDigest signerKeyId envelopeDigest unsignedDigest bodyDigest".split()


def encode(fields):
    """Independent fixed ordering; deliberately imports no SDK implementation."""
    result = bytearray(b"ZTRI\x01\x03\x03\x00")
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
    result += bytes([fields["smsCeiling"]])
    return bytes(result)


def timing(observed, issued, now, review_expiry, message_expiry):
    return (1 <= observed <= issued <= now < review_expiry <= message_expiry < 2**63
            and 0 < review_expiry - issued <= 30_000
            and 0 < message_expiry - observed <= 900_000)


class ReviewedIntentVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((Path(__file__).resolve().parents[1] / "vectors" / "reviewed-intent03.json").read_text())

    def test_canonical_bytes_and_domain_commitments(self):
        for case in self.vectors["cases"]:
            with self.subTest(case=case["name"]):
                encoded = encode(case["fields"])
                transcript = b"zrotext/conversation/reviewed-send03/v1\x00" + struct.pack(">I", len(encoded)) + encoded
                self.assertEqual(encoded.hex(), case["intent_hex"])
                self.assertEqual(len(encoded), 555 + len(bytes.fromhex(case["fields"]["peer"])) + 33 * len(case["fields"]["recipients"]))
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), case["intent_sha256"])
                self.assertEqual(hashlib.sha256(transcript).hexdigest(), case["transcript_sha256"])

    def test_explicit_review_and_message_timing_policy(self):
        for case in self.vectors["timing_cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(timing(*(int(case[k]) for k in ["observed", "issued", "now", "review_expiry", "message_expiry"])), case["accept"])


if __name__ == "__main__":
    unittest.main()
