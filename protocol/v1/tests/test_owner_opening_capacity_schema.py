# SPDX-License-Identifier: AGPL-3.0-only
"""Wire shape and separate semantic controls; no server/authentication execution."""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "owner-opening-capacity.schema.json").read_text(encoding="utf-8"))
VECTORS = json.loads((ROOT / "vectors/owner-opening-capacity.json").read_text(encoding="utf-8"))
MAXIMUM = (1 << 63) - 1


def validator(kind):
    return Draft202012Validator({
        "$schema": SCHEMA["$schema"],
        "$ref": "#/$defs/" + kind,
        "$defs": SCHEMA["$defs"],
    })


def semantics(kind, value):
    """Apply constraints not expressed by JSON Schema; shape must pass first."""
    if kind == "CreateRequest":
        # JSON Schema integer accepts 1.0; serde's integer token visitor does not.
        return type(value["capacity"]) is int and type(value["description"]["revision"]) is int
    if kind in ("Created", "StatusResponse"):
        receipt = value["outcome"]["receipt"] if kind == "Created" else value["receipt"]
        return int(receipt["pending"]) + int(receipt["confirmed"]) <= 100
    return True


def accepted(kind, value):
    return validator(kind).is_valid(value) and semantics(kind, value)


class OwnerOpeningCapacitySchemaTests(unittest.TestCase):
    def test_schema_is_valid_and_vectors_distinguish_shape_from_semantics(self):
        Draft202012Validator.check_schema(SCHEMA)
        for vector in VECTORS["cases"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(validator(vector["type"]).is_valid(vector["value"]),
                                 vector["schema_valid"])
                self.assertEqual(accepted(vector["type"], vector["value"]), vector["valid"])

    def test_every_object_is_closed_and_rejects_sequences_missing_and_extra_fields(self):
        for kind in ("CreateRequest", "StatusRequest", "Created", "StatusResponse"):
            vector = next(v["value"] for v in VECTORS["cases"] if v["type"] == kind and v["valid"])
            self.assertFalse(validator(kind).is_valid([]), kind)
            self.assertFalse(validator(kind).is_valid(None), kind)
            changed = copy.deepcopy(vector)
            changed["permit"] = True
            self.assertFalse(validator(kind).is_valid(changed), kind)
            for field in vector:
                changed = copy.deepcopy(vector)
                del changed[field]
                self.assertFalse(validator(kind).is_valid(changed), (kind, field))
        for kind in ("Source", "Opening", "Receipt", "Outcome"):
            self.assertFalse(validator(kind).is_valid([]), kind)
            self.assertFalse(validator(kind).is_valid({"permit": True}), kind)

    def test_uuid_values_refuse_nil_case_format_and_nonstring_aliases(self):
        uuid = validator("uuid")
        original = "12345678-1234-1234-1234-123456789abc"
        self.assertTrue(uuid.is_valid(original))
        for bad in (original.upper(), original.replace("-", ""), "{" + original + "}",
                    "urn:uuid:" + original, " " + original, original + "\n",
                    "00000000-0000-0000-0000-000000000000", 1, None, []) + tuple(
                        original + end for end in ("\r", "\r\n", "\u2028", "\u2029", "\x00")):
            self.assertFalse(uuid.is_valid(bad), bad)

    def test_positive_decimal_pattern_enforces_exact_i64_bound_not_only_length(self):
        decimal = validator("positive_i64")
        samples = {0, 1, 9, 10, MAXIMUM - 1, MAXIMUM, MAXIMUM + 1, 10 ** 19 - 1, 10 ** 19}
        digits = str(MAXIMUM)
        # Exercise every maximum-prefix boundary against an independent integer oracle.
        for index, digit in enumerate(digits):
            for alternative in range(10):
                for suffix in ("0", "9"):
                    samples.add(int(digits[:index] + str(alternative)
                                    + suffix * (len(digits) - index - 1)))
        for value in samples:
            self.assertEqual(decimal.is_valid(str(value)), 1 <= value <= MAXIMUM, value)
        for bad in ("", "00", "01", "+1", "-1", "1.0", "1e0", "1\n", "1\r",
                    " 1", "1 ", "\u0661", 1, 1.0, True, None, [], {}) + tuple(
                        "1" + end for end in ("\r", "\r\n", "\u2028", "\u2029", "\x00")):
            self.assertFalse(decimal.is_valid(bad), bad)

    def test_digest_refuses_zero_uppercase_and_wrong_length(self):
        digest = validator("digest")
        self.assertTrue(digest.is_valid("ab" * 32))
        for bad in ("00" * 32, "AB" * 32, "ab" * 31, "ab" * 32 + "\n", 1, None) + tuple(
                        "ab" * 32 + end for end in ("\r", "\r\n", "\u2028", "\u2029", "\x00")):
            self.assertFalse(digest.is_valid(bad), bad)

    def test_fraction_and_exponent_tokens_need_semantic_integer_refusal(self):
        original = copy.deepcopy(VECTORS["cases"][0]["value"])
        for field in ("capacity", "revision"):
            for token in ("1.0", "1e0", "1E0"):
                changed = copy.deepcopy(original)
                target = changed if field == "capacity" else changed["description"]
                target[field] = json.loads(token)
                self.assertTrue(validator("CreateRequest").is_valid(changed))
                self.assertFalse(accepted("CreateRequest", changed))
            for bad in (0, -1, True, "1", None, 101 if field == "capacity" else 129):
                changed = copy.deepcopy(original)
                target = changed if field == "capacity" else changed["description"]
                target[field] = bad
                self.assertFalse(accepted("CreateRequest", changed))

    def test_count_sum_is_a_separate_required_semantic_control(self):
        original = next(v["value"] for v in VECTORS["cases"] if v["name"] == "status_metadata")
        for pending, confirmed in ((0, 0), (0, 100), (50, 50), (100, 0), (1, 100), (99, 2)):
            changed = copy.deepcopy(original)
            changed["receipt"].update(pending=str(pending), confirmed=str(confirmed))
            self.assertTrue(validator("StatusResponse").is_valid(changed))
            self.assertEqual(accepted("StatusResponse", changed), pending + confirmed <= 100)
        for bad in ("101", "-1", "01", "1e0", "0\n", 1, None) + tuple(
                "0" + end for end in ("\r", "\r\n", "\u2028", "\u2029", "\x00")):
            changed = copy.deepcopy(original)
            changed["receipt"]["pending"] = bad
            self.assertFalse(accepted("StatusResponse", changed), bad)

    def test_receipt_versions_null_fields_and_phases_match_closed_wire(self):
        original = next(v["value"] for v in VECTORS["cases"] if v["name"] == "status_metadata")
        for phase in ("open", "closed", "cancelled"):
            changed = copy.deepcopy(original)
            changed["receipt"]["phase"] = phase
            self.assertTrue(accepted("StatusResponse", changed))
        for field, bad in (("phase", "offered"), ("offer", {}), ("allocation_id", "unavailable"),
                           ("allocation_version", "1"), ("pending", "1000")):
            changed = copy.deepcopy(original)
            changed["receipt"][field] = bad
            self.assertFalse(accepted("StatusResponse", changed), field)
        for field in ("definition_version", "state_version"):
            for bad in ("0", "01", str(MAXIMUM + 1), MAXIMUM):
                changed = copy.deepcopy(original)
                changed["receipt"]["opening"][field] = bad
                self.assertFalse(accepted("StatusResponse", changed), (field, bad))

    def test_raw_duplicate_vectors_reference_streamed_server_controls_not_schema_proof(self):
        source = (ROOT.parents[1] / "crates/server/src/workflow_runtime/openings/http/wire/tests.rs")
        rust_tests = source.read_text(encoding="utf-8")
        for vector in VECTORS["raw_rejections"]:
            self.assertIn("fn " + vector["server_test"] + "(", rust_tests)
            if "raw_file" in vector:
                raw = (ROOT / "vectors" / vector["raw_file"]).read_text(encoding="utf-8")
            else:
                raw = vector["raw"]
            pairs = json.loads(raw, object_pairs_hook=lambda values: values)

            def duplicate(values):
                if not isinstance(values, list):
                    return False
                keys = [pair[0] for pair in values]
                return len(keys) != len(set(keys)) or any(duplicate(pair[1]) for pair in values)

            self.assertTrue(duplicate(pairs), vector["name"])
        # This verifies vector construction and the source reference, not execution
        # of Rust or a claim that a parsed JSON Schema value retains duplicates.


if __name__ == "__main__":
    unittest.main()
