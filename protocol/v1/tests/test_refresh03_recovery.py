# SPDX-License-Identifier: AGPL-3.0-only
"""Structural refresh closure controls; no OS, authentication or acceptance assertion."""
import base64
import copy
import json
from pathlib import Path
import struct
import unittest
import uuid

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads((ROOT / "vectors/sealed-profile03-refresh-closures-01.json").read_text())
SCHEMA = json.loads((ROOT / "profile03-selection-refresh.schema.json").read_text())


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def binary(text):
    data = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    assert len(data) == 496 and b64(data) == text and data[:8] == b"ZTSR\x01\x03\x03\0" and data[488:] == bytes(8)
    assert all(any(data[i:i + 16]) for i in (8, 24, 40, 56, 72))
    assert all(any(data[i:i + 32]) for i in range(120, 472, 32))
    assert all(0 < number(data, i) < 2**63 for i in (88, 96, 104, 112, 472, 480))
    assert 0 < number(data, 480) - number(data, 472) <= 300000
    return data


def number(data, at):
    return struct.unpack_from(">Q", data, at)[0]


def identity(data):
    return str(uuid.UUID(bytes=data[56:72]))


def require_chain(vector):
    target = binary(vector["target_core"])
    now = int(vector["authenticated_now_ms"])
    assert identity(target) == vector["target_refresh_id"]
    assert number(target, 472) <= now < number(target, 480)
    rows = vector["closed_unaccepted"]
    assert len(rows) <= 16
    for name in ("opening_id", "refresh_id"):
        ids = [row[name] for row in rows]
        assert len(set(ids)) == len(ids)
    assert all(row["refresh_id"] != identity(target) for row in rows)
    for index, row in enumerate(rows):
        Draft202012Validator(SCHEMA["$defs"]["refresh_closure"]).validate(row)
        old = binary(row["core"])
        next_core = binary(rows[index + 1]["core"]) if index + 1 < len(rows) else target
        assert identity(old) == row["refresh_id"]
        assert all(old[start:end] == target[start:end] for start, end in ((0, 56), (72, 376), (408, 440)))
        assert number(old, 472) < number(next_core, 472)
        assert row["superseded_by_refresh_id"] == identity(next_core)
        assert int(row["closed_unaccepted_ms"]) == number(next_core, 472)
        assert number(old, 480) <= int(row["closed_unaccepted_ms"]) <= now


class RefreshRecoveryTest(unittest.TestCase):
    def test_complete_chain_and_changed_owner_session_preserve_exact_full_device_scope(self):
        require_chain(VECTOR)
        first, second = [binary(row["core"]) for row in VECTOR["closed_unaccepted"]]
        self.assertNotEqual(first[376:408], second[376:408])
        self.assertEqual(first[344:376], second[344:376])
        self.assertIn("no signatures", VECTOR["status"])
        # Missing unseen ancestors are structurally possible; actual retained phone history
        # separately requires every known original row and saved closure.
        require_chain(dict(VECTOR, closed_unaccepted=VECTOR["closed_unaccepted"][1:]))

    def test_every_bound_scope_component_is_independent_of_owner_session_and_nonce(self):
        for offset in (8, 24, 40, 72, 88, 96, 104, 112, 120, 152, 184, 216, 248, 280, 312, 344, 408):
            changed = copy.deepcopy(VECTOR)
            data = bytearray(binary(changed["closed_unaccepted"][0]["core"]))
            data[offset] ^= 1
            changed["closed_unaccepted"][0]["core"] = b64(data)
            with self.assertRaises(AssertionError):
                require_chain(changed)

    def test_order_links_exact_closure_timestamp_and_actual_target_deadline(self):
        rows = VECTOR["closed_unaccepted"]
        for bad in (list(reversed(rows)), rows[:1], rows + rows[:1],
                    [dict(rows[0], closed_unaccepted_ms="102001"), rows[1]],
                    [dict(rows[0], superseded_by_refresh_id=VECTOR["target_refresh_id"]), rows[1]],
                    [rows[0], dict(rows[1], opening_id=rows[0]["opening_id"])], rows * 9):
            with self.assertRaises(AssertionError):
                require_chain(dict(VECTOR, closed_unaccepted=bad))
        for instant in ("103999", "105000", "105001"):
            with self.assertRaises(AssertionError):
                require_chain(dict(VECTOR, authenticated_now_ms=instant))

    def test_five_closed_members_cannot_be_coerced_or_replaced_by_election_history(self):
        validate = Draft202012Validator(SCHEMA["$defs"]["refresh_closure"])
        row = VECTOR["closed_unaccepted"][0]
        for invalid in (dict(row, new_binding_id=str(uuid.UUID(int=8))),
                        {k: v for k, v in row.items() if k != "opening_id"},
                        dict(row, refresh_id=str(uuid.UUID(int=0))), dict(row, closed_unaccepted_ms=102000),
                        dict(row, closed_unaccepted_ms="0102000"), dict(row, core=row["core"] + "=")):
            self.assertFalse(validate.is_valid(invalid))


if __name__ == "__main__":
    unittest.main()
