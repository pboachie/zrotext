# SPDX-License-Identifier: AGPL-3.0-only
"""Closed wire-shape and exact-body HMAC vectors, not consent or crypto authority."""
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


class SealedEventDeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads((ROOT / "vectors/sealed-event-delivery-01.json").read_text())
        schema = json.loads((ROOT / "sealed-event-delivery.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema)

    def test_exact_nine_fields_and_opaque_bytes(self):
        body = self.vector["body"]
        self.validator.validate(body)
        self.assertEqual(len(body), 9)
        self.assertEqual(base64.b64decode(body["envelope_b64"], validate=True), bytes([13]) * 426)
        self.assertEqual(base64.b64decode(body["unsigned_digest_b64"], validate=True), bytes([7]) * 32)

    def test_plaintext_legacy_authority_and_unknown_fields_are_refused(self):
        for field in ["body", "peer", "recipient", "message_id", "attempt_id", "classification", "part_count", "content_ciphertext_b64", "token", "reader_key"]:
            candidate = copy.deepcopy(self.vector["body"])
            candidate[field] = "synthetic"
            self.assertFalse(self.validator.is_valid(candidate), field)
        for field in self.vector["body"]:
            candidate = copy.deepcopy(self.vector["body"])
            del candidate[field]
            self.assertFalse(self.validator.is_valid(candidate), field)

    def test_nil_identifiers_and_invalid_bounds_are_refused(self):
        for field in ["event_id", "delivery_id", "account_id", "device_id"]:
            body = copy.deepcopy(self.vector["body"])
            body[field] = "00000000-0000-0000-0000-000000000000"
            self.assertFalse(self.validator.is_valid(body))
        for field, values in {"v": [0, 2], "type": ["inbound.message"], "observed_at_ms": [0, -1, 2**63], "envelope_b64": ["", "_" * 568, "A" * 49156], "unsigned_digest_b64": ["A" * 44, "AA=="]}.items():
            for value in values:
                body = copy.deepcopy(self.vector["body"])
                body[field] = value
                self.assertFalse(self.validator.is_valid(body), (field, value))

    def test_hmac_signs_exact_raw_body_and_event_identity_is_stable_on_retry(self):
        raw = self.vector["raw_body"].encode("ascii")
        self.assertEqual(json.loads(raw), self.vector["body"])
        key = bytes(range(32))
        signing_input = str(self.vector["timestamp_seconds"]).encode("ascii") + b"." + raw
        signature = "v1=" + hmac.new(key, signing_input, hashlib.sha256).hexdigest()
        self.assertEqual(signature, self.vector["signature"])
        self.assertNotEqual(signature, "v1=" + hmac.new(key, signing_input + b" ", hashlib.sha256).hexdigest())
        self.assertEqual(self.vector["retry_seconds"], [60, 300, 900, 3600, 21600, 86400])
        # Schema does not establish reader/interval/root current authority;
        # those checks and receipt rollback are separate real PostgreSQL tests.
