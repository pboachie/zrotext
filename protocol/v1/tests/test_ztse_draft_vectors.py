"""Independent Python byte-shape and transcript checks for the shared draft fixture."""

import hashlib
import json
import unittest
from pathlib import Path

from test_zt_sealed_draft_shape import check_envelope_shape


FIXTURE = json.loads(
    (Path(__file__).resolve().parents[1] / "vectors" / "ztse-draft-01.json").read_text()
)


class DraftVectorTests(unittest.TestCase):
    def test_exact_fixture_offsets_and_unsigned_digest(self):
        self.assertEqual(FIXTURE["status"], "UNAPPROVED_DRAFT_01")
        for name, kind in (("outbound", 1), ("inbound", 2)):
            vector = FIXTURE[name]
            envelope = bytes.fromhex(vector["envelopeHex"])
            unsigned = bytes.fromhex(vector["unsignedHex"])
            protected = bytes.fromhex(vector["protectedHex"])
            self.assertEqual(check_envelope_shape(envelope), kind)
            self.assertEqual(envelope, unsigned + bytes.fromhex(vector["signatureHex"]))
            self.assertEqual(envelope[10:10 + len(protected)], protected)
            self.assertEqual(hashlib.sha256(unsigned).hexdigest(), vector["unsignedSha256"])
            self.assertEqual(
                bytes.fromhex(vector["bodyAadHex"]),
                b"ZTSE/body/v1\0" + envelope[:10] + protected,
            )
            for transcript in vector["wrapTranscripts"]:
                role = bytes([transcript["role"]])
                key_id = bytes.fromhex(transcript["keyIdHex"])
                self.assertEqual(
                    bytes.fromhex(transcript["infoHex"]),
                    b"ZTSE/wrap/v1\0" + hashlib.sha256(protected).digest() + role + key_id,
                )
                self.assertEqual(
                    bytes.fromhex(transcript["aadHex"]),
                    b"ZTSE/wrap-aad/v1\0" + protected + role + key_id,
                )

    def test_shape_tamper_corpus(self):
        original = bytes.fromhex(FIXTURE["outbound"]["envelopeHex"])
        for changed in (original[:-1], original + b"\0", original[:4] + b"\2" + original[5:]):
            with self.subTest(length=len(changed)):
                with self.assertRaises(ValueError):
                    check_envelope_shape(changed)


if __name__ == "__main__":
    unittest.main()
