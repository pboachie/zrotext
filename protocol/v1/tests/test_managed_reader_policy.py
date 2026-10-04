# SPDX-License-Identifier: AGPL-3.0-only
"""Shared framing/schema/digest checks; Rust verifies actual signatures/history."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


class ManagedReaderPolicyVectors(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((ROOT / "managed-reader-policy-vectors.json").read_text(encoding="utf-8"))
        self.schema = json.loads((ROOT / "managed-reader-policy.schema.json").read_text(encoding="utf-8"))

    def test_shared_exact_widths_and_signature_independent_semantic_digests(self):
        jsonschema.validate(self.vector, self.schema)
        p, e, i = (bytes.fromhex(self.vector[k + "_hex"]) for k in ("policy", "enrollment", "attestation"))
        n = int.from_bytes(p[22:24], "big")
        self.assertEqual(len(p), 228 + n + 49 * p[227 + n])
        n = int.from_bytes(e[86:88], "big")
        self.assertEqual(len(e), 596 + n)
        self.assertEqual(len(i), 442)
        self.assertEqual(p[:6], b"ZMPC\x01\x01")
        self.assertEqual(e[:6], b"ZMRE\x01\x01")
        self.assertEqual(i[:6], b"ZMCP\x01\x01")
        for name, domain, data in (("policy", b"operator-policy", p), ("enrollment", b"enrollment", e), ("attestation", b"custody-policy", i)):
            transcript = b"ZT/managed-reader/" + domain + b"/v1\0" + len(data).to_bytes(4, "big") + data
            self.assertEqual(hashlib.sha256(transcript).hexdigest(), self.vector[name + "_digest_hex"])
        self.assertNotEqual(i[375:407].hex(), self.vector["attestation_digest_hex"])

    def test_actual_maintained_pin_and_accepted_manifest_are_preserved(self):
        pin = bytes.fromhex(self.vector["root_pin_hex"])
        manifest = bytes.fromhex(self.vector["accepted_manifest_hex"])
        prior = json.loads((ROOT / "contact-reader-statement-vectors.json").read_text(encoding="utf-8"))
        for key in ("root_pin_hex", "accepted_manifest_hex", "expected_root_fingerprint_hex", "account_hex"):
            self.assertEqual(self.vector[key], prior[key])
        self.assertEqual(len(pin), 94)
        self.assertEqual(pin[:5], b"ZTRP\x02")
        self.assertEqual(pin[5:21].hex(), self.vector["account_hex"])
        self.assertEqual(pin[21:29], (1).to_bytes(8, "big"))
        self.assertEqual(pin[29:], manifest[85:150])
        self.assertEqual(hashlib.sha256(b"ZTSE/root-pin/v2\0" + pin).hexdigest(), self.vector["expected_root_fingerprint_hex"])

    def test_every_string_rejects_control_unicode_and_final_newline_aliases(self):
        for key, value in self.vector.items():
            if not isinstance(value, str):
                continue
            for suffix in ("\n", "\r", "\r\n", "\t", "\u2028", "\u2029"):
                candidate = copy.deepcopy(self.vector)
                candidate[key] = value + suffix
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(candidate, self.schema)
        candidate = copy.deepcopy(self.vector)
        candidate["unknown"] = "extra"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(candidate, self.schema)

    def test_variable_hex_requires_complete_bytes_inside_allowed_bounds(self):
        for key in ("policy_hex", "enrollment_hex", "accepted_manifest_hex"):
            for odd_value in (self.vector[key][:-1], self.vector[key] + "0"):
                limits = self.schema["properties"][key]
                self.assertGreaterEqual(len(odd_value), limits["minLength"])
                self.assertLessEqual(len(odd_value), limits["maxLength"])
                self.assertEqual(len(odd_value) % 2, 1)
                candidate = copy.deepcopy(self.vector)
                candidate[key] = odd_value
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(candidate, self.schema)

    def test_negative_corpus_is_bounded_distinct_and_mutates_real_exact_bytes(self):
        cases = self.vector["negative_mutations"]
        self.assertEqual(len(cases), 25)
        self.assertEqual(len({case["name"] for case in cases}), len(cases))
        for case in cases:
            data = bytes.fromhex(self.vector[case["target"] + "_hex"])
            self.assertLess(case["offset"], len(data))
            changed = bytearray(data)
            changed[case["offset"]] ^= case["xor"]
            self.assertNotEqual(changed, data)
            self.assertEqual(len(changed), len(data))


if __name__ == "__main__":
    unittest.main()
