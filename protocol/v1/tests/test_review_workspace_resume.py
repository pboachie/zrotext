# SPDX-License-Identifier: AGPL-3.0-only
"""Independent stdlib framing/hash checks; ECDSA possession is covered by Rust."""
import hashlib
import json
from pathlib import Path
import unittest


class ReviewWorkspaceResumeVector(unittest.TestCase):
    def test_fixed_offsets_and_dedicated_length_framing(self):
        v = json.loads((Path(__file__).parents[1] / "vectors" / "review-workspace-resume-01.json").read_text())
        u = bytes.fromhex(v["unsignedHex"])
        self.assertEqual(u[:5], b"ZTRW\x01")
        for at, marker in [(5, 1), (21, 2), (37, 3), (53, 4), (77, 5), (93, 6), (109, 7)]:
            self.assertEqual(u[at:at + 16], bytes([marker]) * 16)
        self.assertEqual(int.from_bytes(u[69:77], "big"), v["credentialRevision"])
        self.assertEqual(u[125:157], bytes([8]) * 32)
        self.assertEqual(u[157:189], bytes([9]) * 32)
        self.assertEqual(int.from_bytes(u[189:197], "big"), v["issuedMs"])
        self.assertEqual(int.from_bytes(u[197:205], "big"), v["expiresMs"])
        pin = bytes.fromhex(v["rootPinHex"])
        fingerprint = hashlib.sha256(b"ZTSE/root-pin/v2\0" + pin).digest()
        self.assertEqual(u[205:299], pin)
        self.assertEqual(pin[:5], b"ZTRP\x02")
        self.assertEqual(pin[5:21], u[77:93])
        self.assertEqual(int.from_bytes(pin[21:29], "big"), 1)
        self.assertEqual(pin[29], 4)
        self.assertEqual(u[299:331], fingerprint)
        self.assertEqual(fingerprint.hex(), v["rootFingerprintHex"])
        origin = v["origin"].encode("ascii")
        self.assertEqual(int.from_bytes(u[331:333], "big"), len(origin))
        self.assertEqual(u[333:], origin)
        self.assertEqual(len(u), 333 + len(origin))
        transcript = b"ZTSE/review-workspace/resume/v1\0" + len(u).to_bytes(4, "big") + u
        self.assertEqual(transcript.hex(), v["transcriptHex"])
        self.assertEqual(hashlib.sha256(u).hexdigest(), v["unsignedSha256"])
        self.assertEqual(hashlib.sha256(transcript).hexdigest(), v["transcriptSha256"])
        signature = bytes.fromhex(v["signatureHex"])
        order = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
        self.assertEqual(len(signature), 64)
        self.assertTrue(0 < int.from_bytes(signature[:32], "big") < order)
        self.assertTrue(0 < int.from_bytes(signature[32:], "big") <= order // 2)


if __name__ == "__main__":
    unittest.main()
