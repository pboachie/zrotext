# SPDX-License-Identifier: AGPL-3.0-only
"""Closed original-input syntax; current execution authority is server-checked."""
import copy
import json
from pathlib import Path
import unittest

import jsonschema


class OriginalRoutineContract(unittest.TestCase):
    def setUp(self):
        directory = Path(__file__).resolve().parents[1] / "vectors"
        self.policy = json.loads((directory / "customer-routine-policy.schema.json").read_text())
        self.service = json.loads((directory / "customer-routine-service.schema.json").read_text())
        self.vector = json.loads((directory / "customer-routine-original-01.json").read_text())

    def refused(self, value, schema):
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(value, schema)

    def test_original_positive_vector_has_distinct_closed_admission_and_current(self):
        for schema in (self.policy, self.service):
            jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.vector["policy"], self.policy)
        for name in ("admit_original", "current_original"):
            jsonschema.validate(self.vector[name], self.service)
        params = self.vector["admit_original"]["params"]
        self.assertEqual(len(params), 8)
        self.assertEqual(self.vector["current_original"]["params"]["call_id"], params["request_id"])
        self.assertEqual(self.vector["call"]["assigned_output_context_id"], params["request_id"])

    def test_original_policy_requires_exact_grant_and_pinned_local_executor(self):
        for binding in ({}, {"grant_id": None}, {"grant_id": "00000000-0000-0000-0000-000000000000"},
                        {"grant_id": self.vector["policy"]["original_input"]["grant_id"], "verified": True}, [], True):
            policy = copy.deepcopy(self.vector["policy"])
            policy["original_input"] = binding
            self.refused(policy, self.policy)
        policy = copy.deepcopy(self.vector["policy"])
        policy.update(executor="deterministic_local", adapter_id=None, artifact_digest=None)
        self.refused(policy, self.policy)
        for absent in (False, True):
            legacy = copy.deepcopy(policy)
            if absent:
                del legacy["original_input"]
            else:
                legacy["original_input"] = None
            jsonschema.validate(legacy, self.policy)

    def test_original_admission_rejects_caller_authority_confirmation_and_credentials(self):
        for field, value in (("direction", "inbound"), ("active_request_id", self.vector["call"]["call_id"]),
                             ("verified", True), ("approved", True), ("original_credential", "example"),
                             ("reader_point", "example"), ("plaintext", "synthetic content")):
            request = copy.deepcopy(self.vector["admit_original"])
            request["params"][field] = value
            self.refused(request, self.service)
        request = copy.deepcopy(self.vector["admit_original"])
        request["x-zrotext-original-reader"] = "example"
        self.refused(request, self.service)

    def test_missing_and_malformed_event_correlation_refuses(self):
        for field in self.vector["admit_original"]["params"]:
            request = copy.deepcopy(self.vector["admit_original"])
            del request["params"][field]
            self.refused(request, self.service)
        for field, value in (("event_id", "00000000-0000-0000-0000-000000000000"),
                             ("accepted_manifest_version", True), ("accepted_manifest_version", 0),
                             ("accepted_manifest_version", 9007199254740992),
                             ("event_envelope_digest", "EF" * 32), ("event_envelope_digest", "ab" * 31),
                             ("input_revision", True), ("input_revision", 129)):
            request = copy.deepcopy(self.vector["admit_original"])
            request["params"][field] = value
            self.refused(request, self.service)

    def test_current_original_has_only_call_identity_and_no_executable_assertion(self):
        for field, value in (("execute_once", True), ("policy_id", self.vector["call"]["policy_id"]),
                             ("event_id", self.vector["admit_original"]["params"]["event_id"])):
            request = copy.deepcopy(self.vector["current_original"])
            request["params"][field] = value
            self.refused(request, self.service)
        # A syntactically valid foreign event/digest remains syntax-valid. Schema
        # cannot prove its provenance, scope, equality or current authority.
        foreign = copy.deepcopy(self.vector["admit_original"])
        foreign["params"]["event_id"] = "00000000-0000-4000-8000-00000000000b"
        foreign["params"]["event_envelope_digest"] = "aa" * 32
        jsonschema.validate(foreign, self.service)


if __name__ == "__main__":
    unittest.main()
