"""Bounded optional negotiation and canonical signed fetch transcript."""
import base64
import copy
import json
from pathlib import Path
import unittest
import uuid

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1] / "vectors"


class SealedDispatchTest(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((ROOT / "sealed-dispatch-01.json").read_text())
        schema = json.loads((ROOT / "sealed-dispatch.schema.json").read_text())
        grant_schema = json.loads((ROOT / "sealed-execution-grant.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        registry = Registry().with_resource(
            "sealed-execution-grant.schema.json", Resource.from_contents(grant_schema)
        )
        self.validator = Draft202012Validator(schema, registry=registry)

    def test_ready_requires_the_exact_versioned_identity(self):
        ready = self.vector["ready"]
        self.validator.validate(ready)
        for name in ready:
            changed = dict(ready)
            del changed[name]
            self.assertFalse(self.validator.is_valid(changed))
        self.assertFalse(self.validator.is_valid({**ready, "fetch_token": "unexpected"}))

    def test_fetch_reuses_exact_grant_and_has_bounded_signature(self):
        request = {"grant": self.vector["grant"], "signature_der": "A" * 96}
        self.validator.validate(request)
        for size in (0, 10, 108):
            self.assertFalse(self.validator.is_valid({**request, "signature_der": "A" * size}))
        changed = copy.deepcopy(request)
        changed["grant"]["fetch_url"] = "unexpected"
        self.assertFalse(self.validator.is_valid(changed))

    def test_transcript_covers_every_exact_grant_field_in_order(self):
        grant = self.vector["grant"]
        transcript = b"ZT/sealed-envelope-fetch/v1\0" + bytes([
            grant["v"], grant["grant_version"], grant["reader_role"], grant["segment_count"]
        ])
        for field in ("account_id", "device_id", "line_id", "message_id", "attempt_id"):
            transcript += uuid.UUID(grant[field]).bytes
        for field in ("connection_epoch", "deployment_epoch", "binding_generation",
                      "attempt_generation", "expires_at_ms"):
            transcript += grant[field].to_bytes(8, "big", signed=True)
        for field in ("reader_key_id", "envelope_sha256", "unsigned_sha256"):
            transcript += base64.urlsafe_b64decode(grant[field] + "=")
        self.assertEqual(transcript.hex(), self.vector["transcriptHex"])


if __name__ == "__main__":
    unittest.main()
