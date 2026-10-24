# SPDX-License-Identifier: AGPL-3.0-only
"""Independent structural closure controls, without authentication or acceptance claims."""
import base64
import copy
import json
from pathlib import Path
import struct
import unittest
import uuid

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads((ROOT / "vectors/sealed-profile03-closed-unaccepted-01.json").read_text())
SCHEMA = json.loads((ROOT / "profile03-closed-unaccepted.schema.json").read_text())


def binary(text):
    value = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    assert len(value) == 500 and base64.urlsafe_b64encode(value).decode().rstrip("=") == text
    return value


def number(core, offset):
    return struct.unpack_from(">Q", core, offset)[0]


def identity(core, offset):
    return str(uuid.UUID(bytes=core[offset:offset + 16]))


def require_core(text):
    core = binary(text)
    assert core[:8] == b"ZTPE\x03\x01\x02\x03" and core[496:] == bytes(4)
    assert all(any(core[i:i + 16]) for i in (8, 24, 40, 56, 72))
    assert all(any(core[i:i + 32]) for i in (104, 136, 184, 224, 256, 288, 320, 352, 400, 432, 464))
    assert all(0 < number(core, i) <= 2**63 - 1 for i in (88, 96, 168, 176, 216, 384, 392))
    assert number(core, 168) == 1 and number(core, 96) > number(core, 88)
    assert number(core, 216) == number(core, 176) + 1
    assert 0 < number(core, 392) - number(core, 384) <= 300_000
    return core


def require_chain(vector):
    target = require_core(vector["target_core"])
    now = int(vector["authenticated_now_ms"])
    assert number(target, 384) <= now < number(target, 392)
    assert identity(target, 56) == vector["target_challenge_id"]
    rows = vector["closed_unaccepted"]
    Draft202012Validator(SCHEMA).validate({"closed_unaccepted": rows})
    for name, target_value in (("challenge_id", vector["target_challenge_id"]),
                               ("new_binding_id", vector["target_new_binding_id"]), ("opening_id", None)):
        values = [row[name] for row in rows]
        assert len(set(values)) == len(values) and target_value not in values
    for index, row in enumerate(rows):
        old = require_core(row["core"])
        successor = require_core(rows[index + 1]["core"]) if index + 1 < len(rows) else target
        assert identity(old, 56) == row["challenge_id"]
        assert all(old[start:end] == target[start:end] for start, end in
                   ((0, 56), (72, 96), (104, 224), (256, 352), (400, 432)))
        assert number(old, 96) < number(successor, 96)
        assert row["superseded_by_challenge_id"] == identity(successor, 56)
        assert int(row["closed_unaccepted_ms"]) == number(successor, 384)
        assert number(old, 392) <= int(row["closed_unaccepted_ms"]) <= now


class Profile03UnacceptedRecoveryTest(unittest.TestCase):
    def test_original_scope_order_links_and_explicit_burned_generation_gap(self):
        Draft202012Validator.check_schema(SCHEMA)
        require_chain(VECTOR)
        first, second = [binary(row["core"]) for row in VECTOR["closed_unaccepted"]]
        self.assertEqual(2, number(second, 96) - number(first, 96))
        self.assertNotEqual(first[432:496], second[432:496])
        self.assertIn("no signatures", VECTOR["status"])

    def test_closed_schema_requires_array_even_when_initially_empty(self):
        validator = Draft202012Validator(SCHEMA)
        self.assertTrue(validator.is_valid({"closed_unaccepted": []}))
        for value in ({}, {"closed_unaccepted": None}, {"closed_unaccepted": {}},
                      {"closed_unaccepted": ["not an object"]}, {"closed_unaccepted": [], "other": 1},
                      {"closed_unaccepted": VECTOR["closed_unaccepted"] * 9}):
            self.assertFalse(validator.is_valid(value))

    def test_exact_members_canonical_strings_and_bounded_e500(self):
        validator = Draft202012Validator(SCHEMA)
        row = VECTOR["closed_unaccepted"][0]
        for bad in ({k: v for k, v in row.items() if k != "opening_id"}, dict(row, accepted=True),
                    dict(row, opening_id=str(uuid.UUID(int=0))), dict(row, new_binding_id="1-1-1-1-1"),
                    dict(row, closed_unaccepted_ms=102000), dict(row, closed_unaccepted_ms="0102000"),
                    dict(row, core=row["core"] + "="), dict(row, core=row["core"][:-1])):
            self.assertFalse(validator.is_valid({"closed_unaccepted": [bad]}))

    def test_missing_intermediate_wrong_link_reorder_duplicate_and_wrong_time_refuse(self):
        rows = VECTOR["closed_unaccepted"]
        bad_rows = [rows[:1], list(reversed(rows)), rows + rows[:1],
                    [dict(rows[0], closed_unaccepted_ms="102001"), rows[1]],
                    [dict(rows[0], superseded_by_challenge_id=VECTOR["target_challenge_id"]), rows[1]],
                    [rows[0], dict(rows[1], opening_id=rows[0]["opening_id"])],
                    [rows[0], dict(rows[1], new_binding_id=rows[0]["new_binding_id"])]]
        for rows in bad_rows:
            changed = dict(VECTOR, closed_unaccepted=rows)
            with self.assertRaises((AssertionError, ValueError)):
                require_chain(changed)
        # An unseen first reservation is allowed structurally. Only the actual phone journal
        # can decide whether omitting that ancestor contradicts a locally retained signature.
        require_chain(dict(VECTOR, closed_unaccepted=VECTOR["closed_unaccepted"][1:]))

    def test_every_original_context_and_fresh_target_time_remain_independent_checks(self):
        for offset in (8, 24, 40, 72, 88, 104, 136, 168, 176, 184, 216, 256, 288, 320, 400):
            changed = copy.deepcopy(VECTOR)
            core = bytearray(binary(changed["closed_unaccepted"][0]["core"]))
            core[offset] ^= 1
            changed["closed_unaccepted"][0]["core"] = base64.urlsafe_b64encode(core).decode().rstrip("=")
            with self.assertRaises(AssertionError):
                require_chain(changed)
        for now in ("103999", "105000", "105001"):
            with self.assertRaises(AssertionError):
                require_chain(dict(VECTOR, authenticated_now_ms=now))


if __name__ == "__main__":
    unittest.main()
