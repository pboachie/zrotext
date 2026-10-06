# SPDX-License-Identifier: AGPL-3.0-only
"""Independent representation oracle. No provider, Rust, authority or disclosure call."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest
import uuid

import jsonschema

VECTORS = Path(__file__).resolve().parents[1] / "vectors"
FIELDS = ("from", "messaging_profile_id", "to", "text", "type", "encoding")
ROUTE_FIELDS = {"account_id", "organization_id", "profile_id", "revision", "sender"}


def e164(value):
    return isinstance(value, str) and re.fullmatch(r"\+[1-9][0-9]{1,14}", value) is not None


def identifier(value):
    if not isinstance(value, str):
        raise ValueError("identity")
    parsed = uuid.UUID(value)
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError("identity")
    return parsed.bytes


def text_bytes(value):
    if not isinstance(value, str):
        raise ValueError("text")
    raw = value.encode("utf-8", errors="strict")
    if not 1 <= len(raw) <= 4096 or len(value) > 4096:
        raise ValueError("text bound")
    if any(ord(character) > 0xffff for character in value):
        raise ValueError("ucs2 subset")
    return raw


def independent_digest(route, recipient, text):
    if set(route) != ROUTE_FIELDS or not e164(route["sender"]) or not e164(recipient):
        raise ValueError("route")
    revision = route["revision"]
    if type(revision) is not int or not 1 <= revision <= 2**64 - 1:
        raise ValueError("revision")
    sender = route["sender"].encode("utf-8")
    payload = (b"ZT/provider-request/v1\0telnyx-sms-v2\0"
               + b"".join(identifier(route[key]) for key in
                          ("account_id", "organization_id", "profile_id"))
               + struct.pack(">Q", revision) + struct.pack(">Q", len(sender))
               + sender + hashlib.sha256(recipient.encode("utf-8")).digest()
               + hashlib.sha256(text_bytes(text)).digest())
    return hashlib.sha256(payload).hexdigest()


def reject_duplicate(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def canonical_bytes(body):
    ordered = {key: body[key] for key in FIELDS}
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def bounded_body(raw, schema):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 32768:
        raise ValueError("body bound")
    body = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=reject_duplicate)
    jsonschema.validate(body, schema)
    if not e164(body["from"]) or not e164(body["to"]):
        raise ValueError("phone")
    identifier(body["messaging_profile_id"])
    text_bytes(body["text"])
    if raw != canonical_bytes(body):
        raise ValueError("noncanonical bytes")
    return body


def expected_body(case):
    return {"from": case["route"]["sender"],
            "messaging_profile_id": case["route"]["profile_id"],
            "to": case["recipient"], "text": case["text"],
            "type": "SMS", "encoding": "ucs2"}


def check_request_case(case):
    if case.get("content_kind", "provider-plaintext") != "provider-plaintext":
        raise ValueError("sealed content")
    if independent_digest(case["route"], case["recipient"], case["text"]) != case["request_digest_hex"]:
        raise ValueError("request conflict")


class ProviderSubmitBodyCodecContractTest(unittest.TestCase):
    def setUp(self):
        self.vectors = json.loads((VECTORS / "provider-submit-body-codec.json").read_text(encoding="utf-8"))
        self.schema = json.loads((VECTORS / "provider-submit-body-codec.schema.json").read_text(encoding="utf-8"))
        self.base = self.vectors["positive"][0]

    def test_positive_vectors_have_independent_digest_and_complete_literal_wire(self):
        self.assertEqual(self.vectors["format"], "provider-submit-body-codec-v1")
        self.assertEqual([case["name"] for case in self.vectors["positive"]],
                         ["ascii", "bmp-omega", "json-escapes", "bmp-upper-bound"])
        for case in self.vectors["positive"]:
            check_request_case(case)
            self.assertEqual(hashlib.sha256(case["recipient"].encode()).hexdigest(), case["recipient_hash_hex"])
            self.assertEqual(hashlib.sha256(case["text"].encode()).hexdigest(), case["body_hash_hex"])
            raw = bytes.fromhex(case["wire_utf8_hex"])
            self.assertEqual(bounded_body(raw, self.schema), expected_body(case))
            self.assertEqual(raw, canonical_bytes(expected_body(case)))

    def test_negative_vectors_refuse_without_replacing_retained_identity(self):
        positive = {case["name"]: case for case in self.vectors["positive"]}
        self.assertEqual(len(self.vectors["negative"]), 8)
        for changes in self.vectors["negative"]:
            case = copy.deepcopy(positive[changes["base"]])
            case.update({key: value for key, value in changes.items() if key not in ("name", "base")})
            with self.subTest(case=changes["name"]), self.assertRaises(ValueError):
                check_request_case(case)

    def test_every_route_field_and_content_is_bound_by_original_digest(self):
        original = self.base["request_digest_hex"]
        for field in ROUTE_FIELDS:
            route = copy.deepcopy(self.base["route"])
            route[field] = (2 if field == "revision" else
                            "+15550000102" if field == "sender" else str(uuid.UUID(int=99)))
            self.assertNotEqual(independent_digest(route, self.base["recipient"], self.base["text"]), original)
        self.assertNotEqual(independent_digest(self.base["route"], "+15550000102", self.base["text"]), original)
        self.assertNotEqual(independent_digest(self.base["route"], self.base["recipient"], "Synthetic other"), original)

    def test_duplicate_keys_are_refused_before_object_normalization(self):
        raw = bytes.fromhex(self.base["wire_utf8_hex"])
        for key, value in (("type", "SMS"), ("text", "Synthetic SMS"), ("to", "+15550000101")):
            duplicate = raw[:-1] + b"," + json.dumps(key).encode() + b":" + json.dumps(value).encode() + b"}"
            with self.assertRaises(ValueError):
                bounded_body(duplicate, self.schema)

    def test_extra_missing_wrong_type_and_optional_profile_fields_are_refused(self):
        body = expected_body(self.base)
        for key in FIELDS:
            changed = copy.deepcopy(body)
            del changed[key]
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(changed, self.schema)
        for patch in ({"send_at": None}, {"media_urls": []}, {"webhook_url": "synthetic"},
                      {"type": "MMS"}, {"encoding": "auto"}, {"encoding": "gsm7"},
                      {"text": True}, {"to": 12}, {"messaging_profile_id": None}):
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate({**body, **patch}, self.schema)

    def test_phone_lengths_ascii_and_complete_input_are_strict(self):
        for phone in ("+12", "+155500001001234"):
            self.assertTrue(e164(phone))
        for phone in ("+1", "+012", "+1555000010012345", "+１２", "+1 555", "+15550000101\n",
                      "+15550000101\r", "+15550000101\u2028", "+15550000101\u2029"):
            self.assertFalse(e164(phone))
            for key in ("from", "to"):
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate({**expected_body(self.base), key: phone}, self.schema)

    def test_canonical_nonnil_uuid_and_integer_revision_are_not_coerced(self):
        for identity in (str(uuid.UUID(int=0)), "{00000000-0000-0000-0000-000000000003}",
                         "00000000000000000000000000000003", "00000000-0000-0000-0000-00000000000A"):
            with self.assertRaises(ValueError):
                identifier(identity)
        for revision in (0, -1, True, 1.0, "1", 2**64):
            route = {**self.base["route"], "revision": revision}
            with self.assertRaises(ValueError):
                independent_digest(route, self.base["recipient"], self.base["text"])

    def test_utf8_byte_and_bmp_unit_caps_refuse_without_normalization(self):
        self.assertEqual(len(text_bytes("x" * 4096)), 4096)
        self.assertEqual(len(text_bytes("Ω" * 2048)), 4096)
        self.assertEqual(text_bytes("\uffff"), b"\xef\xbf\xbf")
        for text in ("", "x" * 4097, "Ω" * 2049, "\U00010000", "\ud800"):
            with self.assertRaises(ValueError):
                text_bytes(text)

    def test_invalid_utf8_bom_trailing_data_and_oversized_body_are_refused(self):
        raw = bytes.fromhex(self.base["wire_utf8_hex"])
        for bad in (b"\xff", b"\xef\xbb\xbf" + raw, raw + b"{}", raw + b"\n",
                    b"x" * 32769, b""):
            with self.assertRaises(ValueError):
                bounded_body(bad, self.schema)

    def test_maximum_escaped_representation_has_independent_finite_bound(self):
        body = {**expected_body(self.base), "text": "\0" * 4096}
        raw = canonical_bytes(body)
        self.assertEqual(bounded_body(raw, self.schema)["text"], "\0" * 4096)
        self.assertLessEqual(len(raw), 6 * 4096 + 256)
        self.assertLess(6 * 4096 + 256, 32768)

    def test_same_shape_does_not_substitute_a_different_retained_request(self):
        case = copy.deepcopy(self.base)
        case["route"]["account_id"] = str(uuid.UUID(int=99))
        with self.assertRaises(ValueError):
            check_request_case(case)
        # A matching newly chosen digest is still only identity, never a send grant.
        case["request_digest_hex"] = independent_digest(case["route"], case["recipient"], case["text"])
        check_request_case(case)
        self.assertEqual(set(expected_body(case)), set(FIELDS))


if __name__ == "__main__":
    unittest.main()
