# SPDX-License-Identifier: AGPL-3.0-only
"""Wire-shape vectors, not grant authority, delivery or refund evidence."""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


class WorkflowCancellationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads((ROOT / "vectors/workflow-cancellation-01.json").read_text(encoding="utf-8"))
        schemas = json.loads((ROOT / "openapi/workflow-tools-v1.json").read_text(encoding="utf-8"))["components"]["schemas"]
        cls.requests = Draft202012Validator(schemas["WorkflowRequest"])
        cls.responses = Draft202012Validator(schemas["WorkflowResponse"])
        Draft202012Validator.check_schema(schemas["WorkflowRequest"])
        Draft202012Validator.check_schema(schemas["WorkflowResponse"])

    def test_exact_cancel_request_and_cancelled_response_match_generated_schema(self):
        self.requests.validate(self.vector["request"])
        self.responses.validate(self.vector["response"])
        params = self.vector["request"]["params"]
        self.assertEqual(set(params), {"request_id", "key"})
        self.assertEqual(set(params["key"]), {"account_id", "action_id", "revision", "binding_digest"})
        self.assertEqual(self.vector["response"]["result"]["key"], params["key"])

    def test_caller_queue_and_authority_fields_are_rejected(self):
        for field in self.vector["forbidden_params"]:
            with self.subTest(field=field):
                request = copy.deepcopy(self.vector["request"])
                request["params"][field] = self.vector["response"]["result"]["message_id"]
                self.assertFalse(self.requests.is_valid(request))
        for field in self.vector["forbidden_key_fields"]:
            request = copy.deepcopy(self.vector["request"])
            request["params"]["key"][field] = "synthetic"
            self.assertFalse(self.requests.is_valid(request))
        request = copy.deepcopy(self.vector["request"])
        request["actor"] = "synthetic"
        self.assertFalse(self.requests.is_valid(request))

    def test_missing_nil_or_malformed_key_identity_is_rejected(self):
        for field in ["account_id", "action_id", "revision", "binding_digest"]:
            request = copy.deepcopy(self.vector["request"])
            del request["params"]["key"][field]
            self.assertFalse(self.requests.is_valid(request))
        for field, value in [("account_id", "00000000-0000-0000-0000-000000000000"),
                             ("action_id", "not-a-uuid"), ("revision", 0),
                             ("binding_digest", "AB" * 32)]:
            request = copy.deepcopy(self.vector["request"])
            request["params"]["key"][field] = value
            self.assertFalse(self.requests.is_valid(request))

    def test_only_cancelled_response_state_is_supported(self):
        for state in self.vector["invalid_states"]:
            response = copy.deepcopy(self.vector["response"])
            response["result"]["state"] = state
            self.assertFalse(self.responses.is_valid(response))
        response = copy.deepcopy(self.vector["response"])
        response["result"]["refund"] = True
        self.assertFalse(self.responses.is_valid(response))
        for field in self.vector["request"]["params"]["key"]:
            response = copy.deepcopy(self.vector["response"])
            del response["result"]["key"][field]
            self.assertFalse(self.responses.is_valid(response))

    def test_shape_valid_foreign_key_requires_separate_request_binding(self):
        # JSON Schema cannot correlate two messages or establish authority.
        # Actual JS/Python client tests enforce this full-key comparison.
        expected = self.vector["request"]["params"]["key"]
        for field, value in self.vector["foreign_key_edits"].items():
            response = copy.deepcopy(self.vector["response"])
            response["result"]["key"][field] = value
            self.responses.validate(response)
            self.assertNotEqual(response["result"]["key"], expected)


if __name__ == "__main__":
    unittest.main()
