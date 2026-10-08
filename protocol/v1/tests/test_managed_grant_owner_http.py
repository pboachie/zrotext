# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic wire-contract model; never target parsing or owner authorization."""

import copy
import json
from pathlib import Path
import unittest
import uuid

from jsonschema import Draft202012Validator, ValidationError


VECTORS = Path(__file__).resolve().parents[1] / "vectors"
SCHEMA = json.loads((VECTORS / "managed-grant-owner-http.schema.json").read_text(encoding="utf-8"))
FIELD_ORDER = {
    "create": ("password", "factor", "request"),
    "replace": ("expected_version", "password", "factor", "request"),
    "narrow": ("expected_version", "request"),
    "revoke": (),
    "grantRequestWire": ("policy", "contact", "purpose", "instruction_digest", "expires_ms", "max_calls", "max_input_bytes", "max_cost_microunits", "selections"),
    "policyWire": ("id", "version", "digest", "reader", "reader_generation"),
    "selectionWire": ("kind", "id", "version", "digest"),
}


def validator(kind):
    return Draft202012Validator({"$schema": SCHEMA["$schema"], "$ref": "#/$defs/" + kind, "$defs": SCHEMA["$defs"]})


def refuse(_value):
    raise ValueError("wire refusal")


def integer_token(value):
    # Pinned serde_json turns -0 into f64; typed i64/u8 visitors refuse it.
    if value == "-0":
        refuse(value)
    return int(value)


def unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            refuse(key)
        result[key] = value
    return result


def unicode_scalars(value):
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
    elif isinstance(value, list):
        for child in value:
            unicode_scalars(child)
    elif isinstance(value, dict):
        for key, child in value.items():
            unicode_scalars(key)
            unicode_scalars(child)


def named(value, kind):
    if isinstance(value, list):
        return dict(zip(FIELD_ORDER[kind], value))
    return dict(value)


def normalize(value, kind):
    result = named(value, kind)
    if kind in ("create", "replace", "narrow"):
        result["request"] = normalize(result["request"], "grantRequestWire")
    if kind == "grantRequestWire":
        result["policy"] = normalize(result["policy"], "policyWire")
        if isinstance(result["purpose"], dict):
            result["purpose"] = next(iter(result["purpose"]))
        result["selections"] = [normalize(item, "selectionWire") for item in result["selections"]]
    if kind == "selectionWire" and isinstance(result["kind"], dict):
        result["kind"] = next(iter(result["kind"]))
    return result


def decode_raw(raw, kind):
    """Independent supplemental model, not an invocation of serde/Axum."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="strict")
    if len(raw) > 16384:
        refuse(raw)
    value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_members,
                       parse_int=integer_token, parse_float=refuse, parse_constant=refuse)
    unicode_scalars(value)
    validator(kind).validate(value)
    result = normalize(value, kind) if kind in FIELD_ORDER else value
    for field, minimum, maximum in [("password", 12, 1024), ("factor", 1, 256)]:
        if field in result and not minimum <= len(result[field].encode("utf-8")) <= maximum:
            refuse(field)
    return result


def core_shape(scope):
    """Pure source-derived validate profile; no DB, freshness or narrow proof."""
    policy = scope["policy"]
    if any(uuid.UUID(value).int == 0 for value in [policy["id"], policy["reader"], scope["contact"]]):
        refuse(scope)
    if policy["version"] <= 0 or policy["reader_generation"] <= 0 or scope["expires_ms"] <= 0:
        refuse(scope)
    if not any(policy["digest"]) or not any(scope["instruction_digest"]):
        refuse(scope)
    if any(scope[field] < 0 for field in ["max_calls", "max_input_bytes", "max_cost_microunits"]):
        refuse(scope)
    selections = scope["selections"]
    if len(selections) > 32:
        refuse(scope)
    previous = None
    for selected in selections:
        identity = uuid.UUID(selected["id"]).int
        if not identity or not 1 <= selected["version"] <= 128 or not any(selected["digest"]):
            refuse(scope)
        key = (identity, selected["version"], tuple(selected["digest"]))
        if previous is not None and (previous >= key or previous[0] == identity):
            refuse(scope)
        previous = key
    return scope


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class ManagedGrantOwnerHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Draft202012Validator.check_schema(SCHEMA)
        cls.vector = json.loads((VECTORS / "managed-grant-owner-http-01.json").read_text(encoding="utf-8"))
        cls.create = copy.deepcopy(cls.vector["requests"][0]["expected"])
        cls.scope = copy.deepcopy(cls.create["request"])

    def assert_raw_refused(self, raw, kind):
        with self.assertRaises((ValueError, ValidationError)):
            decode_raw(raw, kind)

    def test_literal_requests_and_independent_expected_identities(self):
        self.assertEqual(len(self.vector["requests"]), 8)
        self.assertEqual(set(self.create), {"password", "factor", "request"})
        self.assertEqual(self.create["password"], "replace-with-a-secret")
        self.assertEqual(self.scope["contact"], "00000000-0000-0000-0000-000000000013")
        self.assertEqual(self.scope["policy"]["digest"], [1] * 32)
        self.assertEqual(self.scope["instruction_digest"], [2] * 32)
        self.assertEqual(self.scope["selections"][0]["digest"], [3] * 32)
        self.assertEqual(self.scope["selections"][0]["version"], 128)
        for record in self.vector["requests"]:
            expected = record.get("expected", record.get("expected_normalized"))
            self.assertEqual(decode_raw(record["raw"], record["operation"]), expected)
            if "request" in expected:
                core_shape(expected["request"])

    def test_required_unknown_and_duplicate_members_at_every_object(self):
        for path in [(), ("request",), ("request", "policy"), ("request", "selections", 0)]:
            target = self.create
            for key in path:
                target = target[key]
            for field in target:
                changed = copy.deepcopy(self.create)
                selected = changed
                for key in path:
                    selected = selected[key]
                del selected[field]
                self.assert_raw_refused(wire(changed), "create")
            changed = copy.deepcopy(self.create)
            selected = changed
            for key in path:
                selected = selected[key]
            selected["authority"] = True
            self.assert_raw_refused(wire(changed), "create")
        raw = self.vector["requests"][0]["raw"]
        for original, duplicate in [
            ('"password":"replace-with-a-secret"', '"password":"replace-with-a-secret","password":"other synthetic"'),
            ('"max_calls":8', '"max_calls":8,"max_calls":8'),
            ('"reader_generation":1', '"reader_generation":1,"reader_generation":2'),
            ('"version":128', '"version":128,"version":128'),
        ]:
            bad = raw.replace(original, duplicate)
            self.assertNotEqual(bad, raw)
            self.assert_raw_refused(bad, "create")
            # Generic JSON collapsed these names; schema is not duplicate proof.
            validator("create").validate(json.loads(bad))

    def test_all_wrapper_fields_and_positional_counts_order_types(self):
        for record in self.vector["requests"][:4]:
            kind, value = record["operation"], record["expected"]
            for field in value:
                for replacement in [None, True, "wrong", [], {}]:
                    changed = copy.deepcopy(value)
                    changed[field] = replacement
                    if field in ("password", "factor") and isinstance(replacement, str):
                        # Password too short; factor arbitrary nonempty text valid.
                        if field == "factor":
                            continue
                    self.assert_raw_refused(wire(changed), kind)
            changed = copy.deepcopy(value)
            changed["extra"] = 1
            self.assert_raw_refused(wire(changed), kind)
        for record in self.vector["requests"][4:]:
            value = json.loads(record["raw"])
            self.assert_raw_refused(wire(value + [None]), record["operation"])
            if value:
                self.assert_raw_refused(wire(value[:-1]), record["operation"])
                value[0] = {}
                self.assert_raw_refused(wire(value), record["operation"])
        self.assertEqual(decode_raw(b"{}", "revoke"), {})
        self.assertEqual(decode_raw(b"[]", "revoke"), {})
        for raw in [b"null", b"[1]", b"true", b'""']:
            self.assert_raw_refused(raw, "revoke")

    def test_nested_positional_and_unit_enum_compatibility_has_exact_counts(self):
        positional = json.loads(self.vector["requests"][4]["raw"])
        for location in [(2,), (2, 0), (2, 8, 0)]:
            for extra in [False, True]:
                changed = copy.deepcopy(positional)
                target = changed
                for field in location:
                    target = target[field]
                if extra:
                    target.append(None)
                else:
                    target.pop()
                self.assert_raw_refused(wire(changed), "create")
        for field, names in [("purpose", ["transactional", "operational", "marketing"])]:
            for name in names:
                scope = copy.deepcopy(self.scope)
                scope[field] = {name: None}
                self.assertEqual(decode_raw(wire(scope), "grantRequestWire")[field], name)
            for value in [{"operational": False}, {"operational": None, "marketing": None}, "unknown", []]:
                scope = copy.deepcopy(self.scope)
                scope[field] = value
                self.assert_raw_refused(wire(scope), "grantRequestWire")
        scope = copy.deepcopy(self.scope)
        scope["selections"][0]["kind"] = {"workflow_context_v1": None}
        self.assertEqual(decode_raw(wire(scope), "grantRequestWire")["selections"][0]["kind"], "workflow_context_v1")

    def test_typed_i64_byte_digest_and_lexical_integer_boundaries(self):
        raw = self.vector["requests"][2]["raw"]
        for token in ["1.0", "1e0", "true", '"1"', "0", "128", "-1", "9223372036854775808"]:
            bad = raw.replace('"expected_version":127', '"expected_version":' + token)
            self.assertNotEqual(bad, raw)
            self.assert_raw_refused(bad, "narrow")
        for token in ["1.0", "1e0"]:
            bad = json.loads(raw.replace('"expected_version":127', '"expected_version":' + token))
            validator("narrow").validate(bad)  # mathematical integer, wrong raw token
        for field in ["expires_ms", "max_calls", "max_input_bytes", "max_cost_microunits"]:
            for bound in [-9223372036854775808, 9223372036854775807]:
                scope = copy.deepcopy(self.scope)
                scope[field] = bound
                decode_raw(wire(scope), "grantRequestWire")
            for wrong in [-9223372036854775809, 9223372036854775808, True, "1"]:
                scope = copy.deepcopy(self.scope)
                scope[field] = wrong
                self.assert_raw_refused(wire(scope), "grantRequestWire")
        for digest in [[1] * 31, [1] * 33, [True] * 32, [-1] * 32, [256] * 32, "01"]:
            scope = copy.deepcopy(self.scope)
            scope["instruction_digest"] = digest
            self.assert_raw_refused(wire(scope), "grantRequestWire")
        for digest in [[0] * 32, [255] * 32]:
            scope = copy.deepcopy(self.scope)
            scope["instruction_digest"] = digest
            decode_raw(wire(scope), "grantRequestWire")
        self.assert_raw_refused(raw.replace('"max_calls":8', '"max_calls":-0'), "narrow")

    def test_decoded_secret_bytes_strict_utf8_and_raw_cap_are_separate(self):
        for field, cases in [
            ("password", [("x" * 11, False), ("x" * 12, True), ("x" * 1024, True), ("x" * 1025, False), ("é" * 6, True), ("é" * 513, False), ("🙂" * 3, True)]),
            ("factor", [("", False), ("x", True), ("x" * 256, True), ("x" * 257, False), ("雪" * 85, True), ("雪" * 86, False)]),
        ]:
            for value, accepted in cases:
                changed = copy.deepcopy(self.create)
                changed[field] = value
                if accepted:
                    decode_raw(wire(changed), "create")
                else:
                    self.assert_raw_refused(wire(changed), "create")
        too_many_bytes = copy.deepcopy(self.create)
        too_many_bytes["password"] = "é" * 513
        validator("create").validate(too_many_bytes)
        self.assert_raw_refused(wire(too_many_bytes), "create")
        raw = wire(self.create)
        exact = raw + b" " * (16384 - len(raw))
        self.assertEqual(decode_raw(exact, "create"), self.create)
        self.assert_raw_refused(exact + b" ", "create")
        unpaired = wire(self.create).replace(b'"replace-with-a-secret"', b'"' + bytes([92]) + b'ud800"')
        for raw in [bytes([255]), bytes([0xC0, 0xAF]), unpaired]:
            self.assert_raw_refused(raw, "create")
        escaped = json.dumps(self.create, ensure_ascii=True).encode()
        decode_raw(escaped, "create")
        large = copy.deepcopy(self.create)
        large["password"] = chr(1) * 1024
        large["factor"] = chr(2) * 256
        large["request"]["selections"] = [{"kind":"workflow_context_v1", "id":str(uuid.UUID(int=index)), "version":128, "digest":[255]*32} for index in range(1, 65)]
        validator("create").validate(large)
        # Typed wire accepts this count; core validation independently refuses it.
        # The raw reader cap acts before that core phase or dormant issuance gate.
        escaped = wire(large)
        self.assertGreater(len(escaped), 16384)
        self.assert_raw_refused(escaped, "create")
        self.assert_raw_refused(b"{} trailing", "revoke")

    def test_nested_uuid_aliases_are_not_canonical_path_or_authority(self):
        canonical = self.vector["path_grant_id"]
        for alias in [canonical, canonical.upper(), canonical.replace("-", ""), "{" + canonical + "}", "urn:uuid:" + canonical]:
            scope = copy.deepcopy(self.scope)
            scope["policy"]["id"] = alias
            core_shape(decode_raw(wire(scope), "grantRequestWire"))
            if alias == canonical:
                validator("pathGrantId").validate(alias)
            else:
                self.assertTrue(list(validator("pathGrantId").iter_errors(alias)))
        for bad in [canonical + "\n", canonical + "x", "URN:UUID:" + canonical, "synthetic", [0] * 16]:
            self.assertTrue(list(validator("uuidWire").iter_errors(bad)))
        nil = "00000000-0000-0000-0000-000000000000"
        scope = copy.deepcopy(self.scope)
        scope["contact"] = nil
        decoded = decode_raw(wire(scope), "grantRequestWire")
        with self.assertRaises(ValueError):
            core_shape(decoded)
        self.assertTrue(list(validator("pathGrantId").iter_errors(nil)))

    def test_core_profile_constraints_do_not_become_serde_or_freshness_claims(self):
        empty = copy.deepcopy(self.scope)
        empty["selections"] = []
        for field in ["max_calls", "max_input_bytes", "max_cost_microunits"]:
            empty[field] = 0
        core_shape(decode_raw(wire(empty), "grantRequestWire"))
        maximum = copy.deepcopy(self.scope)
        maximum["selections"] = [{"kind":"workflow_context_v1", "id":str(uuid.UUID(int=index)), "version":128, "digest":[3]*32} for index in range(1, 33)]
        core_shape(decode_raw(wire(maximum), "grantRequestWire"))
        mutants = []
        for path, replacement in [(("max_calls",), -1), (("expires_ms",), 0), (("policy", "version"), 0), (("policy", "reader_generation"), 0), (("policy", "digest"), [0]*32), (("instruction_digest",), [0]*32), (("selections", 0, "version"), 129), (("selections", 0, "digest"), [0]*32)]:
            bad = copy.deepcopy(maximum)
            target = bad
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = replacement
            mutants.append(bad)
        extra = copy.deepcopy(maximum)
        extra["selections"].append({"kind":"workflow_context_v1", "id":str(uuid.UUID(int=33)), "version":1, "digest":[3]*32})
        mutants.append(extra)
        for mode in ["reorder", "same_id", "same_record"]:
            bad = copy.deepcopy(maximum)
            if mode == "reorder":
                bad["selections"][0], bad["selections"][1] = bad["selections"][1], bad["selections"][0]
            elif mode == "same_id":
                bad["selections"][1]["id"] = bad["selections"][0]["id"]
            else:
                bad["selections"][1] = copy.deepcopy(bad["selections"][0])
            mutants.append(bad)
        for bad in mutants:
            decoded = decode_raw(wire(bad), "grantRequestWire")
            with self.assertRaises(ValueError):
                core_shape(decoded)
        self.assertIn("Structural wire data only", SCHEMA["$comment"])

    def test_named_success_error_envelopes_and_status_examples_are_closed(self):
        expected_codes = {"invalid_request":400, "unauthorized":401, "forbidden":403, "refused":403, "conflict":409, "revoke_sms_owner_key_first":409, "not_found":404, "method_not_allowed":405, "rate_limited":429, "internal_error":500, "unavailable":503}
        seen = set()
        for record in self.vector["responses"]:
            if record["kind"] == "empty":
                self.assertEqual((record["status"], record["raw"]), (204, ""))
                continue
            value = decode_raw(record["raw"], record["kind"])
            self.assertEqual(value, record["expected"])
            if record["kind"] == "error":
                self.assertEqual(record["status"], expected_codes[value["code"]])
                seen.add(value["code"])
            for field in value:
                changed = copy.deepcopy(value)
                del changed[field]
                self.assert_raw_refused(wire(changed), record["kind"])
            value["extra"] = "synthetic"
            self.assert_raw_refused(wire(value), record["kind"])
            self.assert_raw_refused(wire(list(record["expected"].values())), record["kind"])
        self.assertEqual(seen, set(expected_codes))
        for version in [0, 129, True, "1", None]:
            self.assert_raw_refused(wire({"grant_id":self.vector["path_grant_id"], "current_version":version}), "grantVersion")
        for wrong_id in [self.vector["path_grant_id"].upper(), "00000000-0000-0000-0000-000000000000", "synthetic", [0]*16]:
            self.assert_raw_refused(wire({"grant_id":wrong_id, "current_version":1}), "grantVersion")
        self.assertEqual(self.vector["responses"][0]["expected"]["current_version"], 1)
        self.assertEqual(self.vector["responses"][1]["expected"]["current_version"], 128)


if __name__ == "__main__":
    unittest.main()
