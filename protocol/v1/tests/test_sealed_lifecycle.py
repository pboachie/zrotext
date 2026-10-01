"""Pin the metadata contract and conservative cancellation evidence vectors."""
import json
import unittest
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DOC = json.loads((ROOT / "openapi/sealed-v1.json").read_text(encoding="utf-8"))
VECTORS = json.loads((ROOT / "vectors/sealed-lifecycle.json").read_text(encoding="utf-8"))


class SealedLifecycleContractTests(unittest.TestCase):
    def test_metadata_schema_and_vectors_preserve_evidence_without_content(self):
        schema = DOC["components"]["schemas"]["SealedMessageMetadata"]
        self.assertEqual(set(schema["properties"]), set(VECTORS["metadata_fields"]))
        self.assertFalse(schema["additionalProperties"])
        validator = Draft202012Validator(schema)
        for case in VECTORS["cases"]:
            record = dict(message_id="00000000-0000-0000-0000-000000000001",
                          device_id="00000000-0000-0000-0000-000000000002",
                          state=case["state"], state_version=1,
                          created_at_ms=1, updated_at_ms=1, expires_at_ms=2)
            validator.validate(record)
            record["plaintext"] = "synthetic"
            self.assertTrue(list(validator.iter_errors(record)))

    def test_cancel_has_no_body_and_exposes_boundary_conflict(self):
        operation = DOC["paths"]["/v1/sealed/messages/{message_id}/cancel"]["post"]
        self.assertNotIn("requestBody", operation)
        self.assertIn("409", operation["responses"])
        self.assertIn("messages:send", operation["description"])
        for case in VECTORS["cases"]:
            if case["grant"]:
                self.assertEqual(case["cancel_status"], 409)
                self.assertEqual(case["result"], case["state"])
                self.assertEqual(case["refunds"], 0)

    def test_cursor_is_exclusive_bounded_and_tenant_safe(self):
        page = DOC["components"]["schemas"]["SealedMessagePage"]
        self.assertEqual(page["properties"]["messages"]["maxItems"], VECTORS["page_size"])
        operation = DOC["paths"]["/v1/sealed/messages"]["get"]
        self.assertEqual([(p["name"], p["required"]) for p in operation["parameters"]], [("cursor", False)])
        self.assertIn("404", operation["responses"])
        self.assertEqual(VECTORS["visibility"]["foreign_cursor"], 404)


if __name__ == "__main__":
    unittest.main()
