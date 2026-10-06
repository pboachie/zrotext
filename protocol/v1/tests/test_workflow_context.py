# SPDX-License-Identifier: AGPL-3.0-only
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import struct
import unittest
import uuid
import jsonschema

ROOT = Path(__file__).resolve().parents[1] / "vectors"


def aad(scope):
    return (b"ZTWC\x01" + bytes([scope["kind"]])
            + b"".join(uuid.UUID(scope[k]).bytes for k in
                       ("account_id", "device_id", "line_id", "interval_id", "context_id"))
            + b"".join(struct.pack(">q", scope[k]) for k in
                       ("binding_generation", "revision", "expires_ms", "trust_generation", "manifest_version"))
            + b"".join(bytes.fromhex(scope[k]) for k in
                       ("peer_digest", "reader_id", "manifest_digest")))


class WorkflowContextContractTest(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((ROOT / "workflow-context-01.json").read_text(encoding="utf-8"))
        self.schema = json.loads((ROOT / "workflow-context.schema.json").read_text(encoding="utf-8"))

    def test_vector_has_exact_nonempty_info_and_canonical_aad(self):
        jsonschema.validate(self.vector, self.schema, format_checker=jsonschema.FormatChecker())
        header = aad(self.vector["scope"])
        self.assertEqual(len(header), 222)
        self.assertEqual(header.hex(), self.vector["aad_hex"])
        self.assertEqual((b"ZT/workflow-context/hpke/v1\0" + header).hex(), self.vector["hpke_info_hex"])

    def test_every_scope_identity_changes_authenticated_bytes(self):
        for key in self.vector["scope"]:
            scope = copy.deepcopy(self.vector["scope"])
            if key.endswith("_id") and key != "reader_id":
                scope[key] = str(uuid.UUID(int=99))
            elif isinstance(scope[key], int):
                scope[key] += 1
            else:
                scope[key] = "09" * 32
            self.assertNotEqual(aad(scope), aad(self.vector["scope"]), key)

    def test_integration_representation_changes_only_the_selected_reader_aad(self):
        vector = json.loads((ROOT / "workflow-context-integration-01.json").read_text(encoding="utf-8"))
        jsonschema.validate(vector, self.schema, format_checker=jsonschema.FormatChecker())
        header = aad(vector["scope"])
        self.assertEqual(header.hex(), vector["aad_hex"])
        self.assertEqual((b"ZT/workflow-context/hpke/v1\0" + header).hex(), vector["hpke_info_hex"])
        archive = aad(self.vector["scope"])
        self.assertEqual(header[:158], archive[:158])
        self.assertNotEqual(header[158:190], archive[158:190])
        self.assertEqual(header[190:], archive[190:])

    def test_schema_refuses_plaintext_fields_nil_ids_and_unbounded_revisions(self):
        for change in ({"plaintext": "synthetic"}, {"revision": 0}, {"revision": 129},
                       {"context_id": str(uuid.UUID(int=0))}, {"kind": 4}):
            vector = copy.deepcopy(self.vector)
            vector["scope"].update(change)
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(vector, self.schema)


def response_contract(raw, schema, expected_account, expected_context, before=None):
    """Synthetic wire control, not proof of an authenticated Owner or SQL source.

    Expected selection/cursor are supplied independently by the caller, never
    derived from the response. The maintained server and browser enforce their
    own authority and transport rules; this helper imports neither implementation.
    """
    def canonical_uuid(value):
        if not isinstance(value, str) or len(value) != 36:
            raise ValueError("noncanonical expected UUID")
        parsed = uuid.UUID(value)
        if parsed.int == 0 or str(parsed) != value:
            raise ValueError("noncanonical expected UUID")

    for identity in (expected_account, expected_context):
        canonical_uuid(identity)
    if before is not None:
        canonical_uuid(before)
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536:
        raise ValueError("response byte budget")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("response BOM")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate response key")
            result[key] = value
        return result

    def refuse_number(value):
        raise ValueError("response numbers must be integer tokens")

    try:
        page = json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=unique_object,
                          parse_float=refuse_number, parse_constant=refuse_number)
    except RecursionError as error:
        raise ValueError("response nesting") from error
    checker = jsonschema.FormatChecker()
    jsonschema.Draft202012Validator(schema, format_checker=checker).validate(page)
    if (page["account_id"], page["context_id"]) != (expected_account, expected_context):
        raise ValueError("response scope")

    last = before
    for row in page["items"]:
        if (row["account_id"], row["context_id"]) != (expected_account, expected_context):
            raise ValueError("row scope")
        if last is not None and row["id"] <= last:
            raise ValueError("row order")
        last = row["id"]
        for field in ("created_at", "resolved_at"):
            value = row[field]
            if value is not None:
                # Mandatory Gregorian validation even if a format implementation
                # accepts more than this finite, fixed-width UTC representation.
                datetime(int(value[:4]), int(value[5:7]), int(value[8:10]),
                         int(value[11:13]), int(value[14:16]), int(value[17:19]),
                         int(value[20:26]), tzinfo=timezone.utc)
    if page["next_cursor"] is not None:
        if len(page["items"]) != 20 or page["next_cursor"] != last:
            raise ValueError("continuation must be the twentieth returned ID")
    return page


class WorkflowExceptionsResponseContractTest(unittest.TestCase):
    ACCOUNT = "a1000000-0000-0000-0000-000000000001"
    CONTEXT = "b2000000-0000-0000-0000-000000000002"
    BEFORE = "c3000000-0000-0000-0000-000000000000"
    LAST = "c3000000-0000-0000-0000-000000000014"
    OTHER = "f6000000-0000-0000-0000-000000000006"
    NIL = "00000000-0000-0000-0000-000000000000"

    def setUp(self):
        self.schema = json.loads((ROOT / "workflow-exceptions-response.schema.json").read_text(encoding="utf-8"))
        self.empty_raw = (ROOT / "workflow-exceptions-empty.json").read_bytes()
        self.page_raw = (ROOT / "workflow-exceptions-page.json").read_bytes()
        self.page = json.loads(self.page_raw)

    def check(self, raw, before=None, account=ACCOUNT, context=CONTEXT):
        return response_contract(raw, self.schema, account, context, before)

    def encoded(self, page):
        return json.dumps(page, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def refused(self, page, before=None):
        with self.assertRaises((ValueError, jsonschema.ValidationError)):
            self.check(self.encoded(page), before)

    def test_response_schema_and_independent_empty_and_twenty_row_vectors(self):
        jsonschema.Draft202012Validator.check_schema(self.schema)
        empty = self.check(self.empty_raw)
        self.assertEqual(empty, {"account_id": self.ACCOUNT, "context_id": self.CONTEXT,
                                 "items": [], "next_cursor": None})
        page = self.check(self.page_raw, self.BEFORE)
        expected_ids = [f"c3000000-0000-0000-0000-{number:012x}" for number in range(1, 21)]
        self.assertEqual([row["id"] for row in page["items"]], expected_ids)
        self.assertEqual(page["next_cursor"], self.LAST)
        self.assertEqual({(r["source_kind"], r["reason"]) for r in page["items"]},
                         {(1, 1), (1, 5), (2, 2), (2, 3), (2, 4)})
        self.assertEqual({r["context_revision"] for r in page["items"]}, {1, 128})
        self.assertEqual({(r["revision"], r["state"]) for r in page["items"]},
                         {(1, "pending"), (2, "resolved")})
        self.assertEqual(page["items"][0]["created_at"], "0001-01-01T00:00:00.000000Z")
        self.assertEqual(page["items"][1]["resolved_at"], "9999-12-31T23:59:59.999999Z")
        for raw in (self.empty_raw, self.page_raw, self.encoded(page)):
            self.assertLessEqual(len(raw), 65536)
        final = copy.deepcopy(page)
        final["next_cursor"] = None
        self.check(self.encoded(final), self.BEFORE)
        # Twenty rows alone cannot prove that a twenty-first row exists in SQL.

    def test_missing_extra_top_and_row_fields_and_legacy_empty_are_refused(self):
        for key in self.page:
            page = copy.deepcopy(self.page)
            del page[key]
            self.refused(page)
        for key in self.page["items"][0]:
            page = copy.deepcopy(self.page)
            del page["items"][0][key]
            self.refused(page)
        for extra in ("plaintext", "peer", "envelope", "audit", "future_column"):
            for row in (False, True):
                page = copy.deepcopy(self.page)
                (page["items"][0] if row else page)[extra] = "synthetic"
                self.refused(page)
        self.refused({"items": [], "next_cursor": None})
        for items in (None, {}, "synthetic"):
            page = copy.deepcopy(self.page)
            page["items"] = items
            self.refused(page)

    def test_canonical_nonzero_uuid_fields_and_expected_selection_are_required(self):
        paths = [(None, "account_id"), (None, "context_id"), (None, "next_cursor")]
        paths += [(1, field) for field in ("account_id", "context_id", "id", "source_id", "resolution_request_id")]
        for index, field in paths:
            for value in (self.NIL, self.OTHER.upper(), self.OTHER.replace("-", ""),
                          "{" + self.OTHER + "}", None, 1):
                page = copy.deepcopy(self.page)
                (page if index is None else page["items"][index])[field] = value
                # Null is legal only for the continuation, independent of row count.
                if field == "next_cursor" and value is None:
                    self.check(self.encoded(page))
                else:
                    self.refused(page)
        for kwargs in ({"account": self.OTHER}, {"context": self.OTHER},
                       {"account": self.NIL}, {"context": self.OTHER.upper()},
                       {"before": self.NIL}, {"before": self.OTHER.upper()}):
            for raw in (self.empty_raw, self.page_raw):
                with self.assertRaises((ValueError, jsonschema.ValidationError)):
                    self.check(raw, **kwargs)

    def test_schema_structure_does_not_attest_row_scope_order_or_cursor_identity(self):
        checker = jsonschema.FormatChecker()
        validator = jsonschema.Draft202012Validator(self.schema, format_checker=checker)
        mutations = []
        for field in ("account_id", "context_id"):
            page = copy.deepcopy(self.page)
            page["items"][0][field] = self.OTHER
            mutations.append(page)
        page = copy.deepcopy(self.page)
        page["items"][0], page["items"][1] = page["items"][1], page["items"][0]
        mutations.append(page)
        page = copy.deepcopy(self.page)
        page["items"][1]["id"] = page["items"][0]["id"]
        mutations.append(page)
        page = copy.deepcopy(self.page)
        page["next_cursor"] = self.OTHER
        mutations.append(page)
        for page in mutations:
            validator.validate(page)  # Standard schema cannot compare instance values.
            self.refused(page)
        self.refused(self.page, before=self.page["items"][0]["id"])
        with self.assertRaises(ValueError):
            self.check(self.page_raw, before=self.LAST)

    def test_item_budget_and_continuation_shape_are_refused(self):
        page = copy.deepcopy(self.page)
        page["items"].append(copy.deepcopy(page["items"][-1]))
        self.refused(page)
        for count in (0, 1, 19):
            page = copy.deepcopy(self.page)
            page["items"] = page["items"][:count]
            self.refused(page)
        for value in ([], {}, True, 1, "synthetic"):
            page = copy.deepcopy(self.page)
            page["next_cursor"] = value
            self.refused(page)

    def test_five_kind_reason_pairs_integer_ranges_and_digest_encoding(self):
        for kind in range(0, 4):
            for reason in range(0, 7):
                page = copy.deepcopy(self.page)
                page["items"][0].update(source_kind=kind, reason=reason)
                if (kind, reason) in {(1, 1), (1, 5), (2, 2), (2, 3), (2, 4)}:
                    self.check(self.encoded(page))
                else:
                    self.refused(page)
        for field in ("context_revision", "source_kind", "reason", "revision"):
            for value in (-1, 0, 129, True, "1", None, 1.0):
                page = copy.deepcopy(self.page)
                page["items"][0][field] = value
                self.refused(page)
        for value in ("", "00" * 32, "\\x" + "00" * 31, "\\x" + "00" * 33,
                      "\\x" + "AA" * 32, "\\X" + "00" * 32, "\\x" + "gg" * 32, None):
            page = copy.deepcopy(self.page)
            page["items"][0]["request_digest"] = value
            self.refused(page)

    def test_revision_state_resolution_nullability_is_exact(self):
        for index, change in (
            (0, {"revision": 2}), (0, {"state": "resolved"}),
            (0, {"resolution_request_id": self.OTHER}),
            (0, {"resolved_at": "2000-02-29T00:00:00.000000Z"}),
            (1, {"revision": 1}), (1, {"state": "pending"}),
            (1, {"resolution_request_id": None}), (1, {"resolved_at": None}),
            (1, {"resolution_request_id": self.NIL}), (0, {"state": "other"}),
        ):
            page = copy.deepcopy(self.page)
            page["items"][index].update(change)
            self.refused(page)

    def test_fixed_finite_utc_timestamps_assert_calendar_and_year_boundaries(self):
        for value in ("0001-01-01T00:00:00.000000Z", "2000-02-29T23:59:59.123456Z",
                      "9999-12-31T23:59:59.999999Z"):
            page = copy.deepcopy(self.page)
            page["items"][1].update(created_at=value, resolved_at=value)
            self.check(self.encoded(page))
        invalid = (
            "infinity", "-infinity", "0001-01-01 BC", "0000-01-01T00:00:00.000000Z",
            "10000-01-01T00:00:00.000000Z", "1900-02-29T00:00:00.000000Z",
            "2001-02-29T00:00:00.000000Z", "2000-04-31T00:00:00.000000Z",
            "2000-00-01T00:00:00.000000Z", "2000-13-01T00:00:00.000000Z",
            "2000-01-00T00:00:00.000000Z", "2000-01-01T24:00:00.000000Z",
            "2000-01-01T00:60:00.000000Z", "2000-01-01T00:00:60.000000Z",
            "2000-01-01T00:00:00.00000Z", "2000-01-01T00:00:00.0000000Z",
            "2000-01-01T00:00:00.000000+00:00", "2000-01-01 00:00:00.000000Z",
            "2000-01-01T00:00:00.000000z", "2000-01-01T00:00:00.00000é", None,
        )
        for field in ("created_at", "resolved_at"):
            for value in invalid:
                page = copy.deepcopy(self.page)
                page["items"][1][field] = value
                # Gregorian allOf patterns are normative without optional format
                # extras; FormatChecker and independent datetime checks also run.
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.Draft202012Validator(self.schema).validate(page)
                self.refused(page)

    def test_raw_utf8_duplicates_integer_tokens_and_exact_byte_cap(self):
        empty = self.encoded(json.loads(self.empty_raw))
        self.check(empty + b" " * (65536 - len(empty)))
        for raw in (b"", b"\xef\xbb\xbf" + empty, b"\xff" + empty,
                    empty + b" " * (65537 - len(empty)), empty + b"null",
                    empty.replace(b'"items":[]', b'"items":[],"items":[]'),
                    empty.replace(b'"items":[]', b'"items":[],"it\\u0065ms":[]')):
            with self.assertRaises((ValueError, jsonschema.ValidationError)):
                self.check(raw)
        compact = self.encoded(self.page)
        for raw in (
            compact.replace(b'"reason":1', b'"reason":1,"reason":1', 1),
            compact.replace(b'"reason":1', b'"reason":1,"r\\u0065ason":1', 1),
            compact.replace(b'"reason":1', b'"reason":1e0', 1),
            compact.replace(b'"reason":1', b'"reason":NaN', 1),
            compact.replace(b'"reason":1', b'"reason":Infinity', 1),
        ):
            with self.assertRaises((ValueError, jsonschema.ValidationError)):
                self.check(raw)
