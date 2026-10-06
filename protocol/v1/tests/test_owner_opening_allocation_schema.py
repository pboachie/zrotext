# SPDX-License-Identifier: AGPL-3.0-only
"""Shape, semantic and Rust-parity controls for the offer/allocation wire proposal.

No server route exists; nothing here executes authentication or PostgreSQL."""
import json
from pathlib import Path
import re
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
SCHEMA = json.loads((ROOT / "owner-opening-allocation.schema.json").read_text(encoding="utf-8"))
VECTORS = json.loads((ROOT / "vectors/owner-opening-allocation.json").read_text(encoding="utf-8"))
CAPACITY = json.loads((ROOT / "owner-opening-capacity.schema.json").read_text(encoding="utf-8"))
OPENINGS = REPO / "crates/server/src/workflow_runtime/openings"


def validator(kind):
    return Draft202012Validator({
        "$schema": SCHEMA["$schema"],
        "$ref": "#/$defs/" + kind,
        "$defs": SCHEMA["$defs"],
    })


def semantics(kind, value):
    if kind != "MutationResponse":
        return True
    receipt = value["outcome"]["receipt"]
    if int(receipt["pending"]) + int(receipt["confirmed"]) > 100:
        return False
    # An allocation identity and its version travel together.
    return (receipt["allocation_id"] is None) == (receipt["allocation_version"] is None)


def accepted(kind, value):
    return validator(kind).is_valid(value) and semantics(kind, value)


def rust_fields(path, struct):
    text = (OPENINGS / path).read_text(encoding="utf-8")
    body = re.search(r"pub struct " + struct + r" \{(.*?)\n\}", text, re.S).group(1)
    return re.findall(r"pub (\w+):", body)


class OwnerOpeningAllocationSchemaTests(unittest.TestCase):
    def test_vectors_distinguish_shape_from_semantics(self):
        Draft202012Validator.check_schema(SCHEMA)
        self.assertGreaterEqual(len(VECTORS["cases"]), 30)
        for vector in VECTORS["cases"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(validator(vector["type"]).is_valid(vector["value"]),
                                 vector["schema_valid"])
                self.assertEqual(accepted(vector["type"], vector["value"]), vector["valid"])

    def test_every_request_and_response_shape_has_accepted_and_refused_vectors(self):
        for kind in ("OfferRequest", "ReserveRequest", "AllocationMutationRequest",
                     "OpeningMutationRequest", "MutationResponse"):
            outcomes = {v["valid"] for v in VECTORS["cases"] if v["type"] == kind}
            self.assertEqual(outcomes, {True, False}, kind)

    def test_request_fields_match_the_typed_library_contracts(self):
        pairs = {
            "OfferRequest": "Offer", "ReserveRequest": "Reserve",
            "AllocationMutationRequest": "AllocationMutation",
            "OpeningMutationRequest": "OpeningMutation",
        }
        for kind, struct in pairs.items():
            definition = SCHEMA["$defs"][kind]
            self.assertEqual(set(definition["required"]), set(definition["properties"]))
            self.assertEqual(set(definition["properties"]),
                             set(rust_fields("contracts.rs", struct)), kind)
        self.assertEqual(set(SCHEMA["$defs"]["OfferKey"]["properties"]),
                         set(rust_fields("contracts.rs", "OfferKey")))
        self.assertEqual(set(SCHEMA["$defs"]["Opening"]["properties"]),
                         set(rust_fields("contracts.rs", "OpeningKey")))
        self.assertEqual(set(SCHEMA["$defs"]["MutationReceipt"]["properties"]),
                         set(rust_fields("model.rs", "Receipt")))
        self.assertEqual(set(SCHEMA["$defs"]["MutationOutcome"]["properties"]),
                         set(rust_fields("model.rs", "Outcome")))

    def test_purpose_enum_matches_library_and_requests_carry_no_authority_fields(self):
        text = (OPENINGS / "contracts.rs").read_text(encoding="utf-8")
        body = re.search(r"pub enum Purpose \{(.*?)\}", text, re.S).group(1)
        variants = {name.lower() for name in re.findall(r"(\w+),", body)}
        self.assertEqual(set(SCHEMA["$defs"]["Purpose"]["enum"]), variants)
        forbidden = {"account_id", "owner_id", "action_key", "delivered", "accepted",
                     "model_approved", "phone", "body", "plaintext"}
        for kind in ("OfferRequest", "ReserveRequest", "AllocationMutationRequest",
                     "OpeningMutationRequest"):
            self.assertFalse(forbidden & set(SCHEMA["$defs"][kind]["properties"]), kind)

    def test_shared_primitives_are_identical_to_the_create_status_contract(self):
        for name in ("uuid", "positive_i64", "count", "digest", "Source", "Opening"):
            self.assertEqual(SCHEMA["$defs"][name], CAPACITY["$defs"][name], name)

    def test_every_object_is_closed(self):
        for name, definition in SCHEMA["$defs"].items():
            if definition.get("type") == "object":
                self.assertIs(definition["additionalProperties"], False, name)
                self.assertFalse(validator(name).is_valid([]), name)
                self.assertFalse(validator(name).is_valid(None), name)

    def test_response_recorded_is_not_forced_true_so_terminal_noops_stay_honest(self):
        noop = next(v for v in VECTORS["cases"] if v["name"] == "terminal_noop_response")
        self.assertIs(noop["value"]["outcome"]["recorded"], False)
        self.assertIs(noop["value"]["outcome"]["applied"], False)
        self.assertTrue(accepted("MutationResponse", noop["value"]))


if __name__ == "__main__":
    unittest.main()
