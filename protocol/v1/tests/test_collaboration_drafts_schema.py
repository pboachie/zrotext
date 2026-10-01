# SPDX-License-Identifier: AGPL-3.0-only
"""Selected collaboration contracts cannot carry implicit broader grants."""
import base64
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "collaboration-drafts.schema.json").read_text(encoding="utf-8"))
IDENTITY = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def validator(name):
    return Draft202012Validator({"$ref": f"#/$defs/{name}", "$defs": SCHEMA["$defs"]}, format_checker=FormatChecker())


class CollaborationDraftContractTest(unittest.TestCase):
    def test_checked_in_synthetic_vectors_match_selected_shapes(self):
        vectors = json.loads((ROOT / "vectors" / "collaboration-drafts.json").read_text(encoding="utf-8"))
        for name, kind in [("valid_draft_create", "draft_create"), ("valid_grant_record", "grant"), ("valid_deleted_draft", "draft"), ("valid_export_cursor", "export_cursor")]:
            validator(kind).validate(vectors[name])

    def test_export_cursor_requires_both_canonical_identities(self):
        check = validator("export_cursor")
        value = f"{IDENTITY}:{IDENTITY}"
        check.validate(value)
        for malformed in [IDENTITY, value.upper(), value + ":extra", "invalid",
                          f"00000000-0000-0000-0000-000000000000:{IDENTITY}",
                          f"{IDENTITY}:00000000-0000-0000-0000-000000000000"]:
            self.assertFalse(check.is_valid(malformed))

    def test_only_selected_confirmed_drafting_grant_is_valid(self):
        grant = {"user_id": IDENTITY, "role": "encrypted_drafter", "confirm_widening": True,
                 "current_password": "synthetic proof only"}
        check = validator("grant_create")
        check.validate(grant)
        for field, value in [("role", "sender"), ("role", "owner"), ("confirm_widening", False),
                             ("read_content", True), ("send", True), ("root", True), ("approve", True)]:
            with self.subTest(field=field, value=value):
                candidate = dict(grant, **{field: value})
                self.assertFalse(check.is_valid(candidate))

    def test_opaque_draft_has_no_plaintext_recipient_or_key_fields(self):
        body = {"draft_id": IDENTITY, "ciphertext_base64": base64.b64encode(bytes(32)).decode("ascii")}
        check = validator("draft_create")
        check.validate(body)
        for field in ["body", "recipient", "private_key", "agent_grant", "author_user_id"]:
            with self.subTest(field=field):
                self.assertFalse(check.is_valid(dict(body, **{field: "synthetic"})))
        for size in [0, 27, 8193]:
            candidate = dict(body, ciphertext_base64=base64.b64encode(bytes(size)).decode("ascii"))
            # Exact byte lengths/canonical padding are additionally validated
            # by the server; schema enforces the encoded outer bound.
            self.assertFalse(check.is_valid(candidate))
        for size in [28, 8192]:
            check.validate(dict(body, ciphertext_base64=base64.b64encode(bytes(size)).decode("ascii")))

    def test_deleted_export_is_a_tombstone_without_ciphertext(self):
        record = {"draft_id": IDENTITY, "grant_id": IDENTITY, "author_user_id": IDENTITY,
                  "ciphertext_base64": base64.b64encode(bytes(32)).decode("ascii"),
                  "created_at_ms": 946684800000, "deleted_at_ms": None}
        check = validator("draft")
        check.validate(record)
        deleted = copy.deepcopy(record)
        deleted.update(ciphertext_base64=None, deleted_at_ms=946684800001)
        check.validate(deleted)
        self.assertFalse(check.is_valid(dict(deleted, ciphertext_base64=record["ciphertext_base64"])))


if __name__ == "__main__":
    unittest.main()
