# SPDX-License-Identifier: AGPL-3.0-only
"""Closed waiting wire shapes; authority and runtime effects are tested in Rust."""
import copy
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


class SchedulingRuntimeContractTests(unittest.TestCase):
    def test_waiting_phone_and_existing_waits_never_claim_ready_or_delivery(self):
        vector = json.loads((ROOT / "vectors/workflow-scheduling-runtime-01.json").read_text())
        schemas = json.loads((ROOT / "openapi/workflow-tools-v1.json").read_text())["components"]["schemas"]
        validator = Draft202012Validator(schemas["WorkflowResponse"])
        validator.validate(vector["response"])
        for state in vector["other_waiting_states"]:
            response = copy.deepcopy(vector["response"])
            response["result"]["state"] = state
            validator.validate(response)
        for state in vector["invalid_states"]:
            response = copy.deepcopy(vector["response"])
            response["result"]["state"] = state
            self.assertFalse(validator.is_valid(response))
        for field in vector["forbidden_fields"]:
            response = copy.deepcopy(vector["response"])
            response["result"][field] = True
            self.assertFalse(validator.is_valid(response))


if __name__ == "__main__":
    unittest.main()
