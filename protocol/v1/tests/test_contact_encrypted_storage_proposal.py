# SPDX-License-Identifier: AGPL-3.0-only
"""Checks the proposed opaque takeout record shape against the merged ZTCO01/ZTCM01 vectors.

The proposal vector must stay byte-identical to the merged contact content
vectors and internally consistent: slot tags, seal revisions, field digests,
account/contact scope and the tombstone digest are all re-derived here.
"""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

BASE = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((BASE / "contact-encrypted-storage-proposal.schema.json").read_text(encoding="utf-8"))
VECTOR = json.loads((BASE / "contact-encrypted-storage-proposal-vectors.json").read_text(encoding="utf-8"))
CONTRACT = json.loads((BASE / "contact-content-contract-vectors.json").read_text(encoding="utf-8"))


def slots(mutation: bytes):
    return {"name": mutation[222:263], "notes": mutation[263:304]}


class OpaqueTakeoutShape(unittest.TestCase):
    def test_vector_matches_schema_and_is_closed(self):
        validator = Draft202012Validator(SCHEMA)
        validator.validate(VECTOR)
        for key in VECTOR:
            changed = copy.deepcopy(VECTOR)
            del changed[key]
            self.assertFalse(validator.is_valid(changed), key)
        extra = copy.deepcopy(VECTOR)
        extra["records"][0]["plaintext_name"] = "x"
        self.assertFalse(validator.is_valid(extra))

    def test_tombstone_cannot_carry_content_or_a_mutation(self):
        validator = Draft202012Validator(SCHEMA)
        tomb = next(r for r in VECTOR["records"] if r["state"] == "deleted")
        for key in ["mutation_hex", "name_field_hex", "notes_field_hex"]:
            changed = copy.deepcopy(VECTOR)
            target = next(r for r in changed["records"] if r["state"] == "deleted")
            target[key] = tomb.get(key) or CONTRACT["clear_hex"]
            self.assertFalse(validator.is_valid(changed), key)

    def test_present_record_without_nullable_member_is_refused(self):
        validator = Draft202012Validator(SCHEMA)
        for key in ["name_field_hex", "notes_field_hex", "mutation_hex", "revision"]:
            changed = copy.deepcopy(VECTOR)
            del changed["records"][0][key]
            self.assertFalse(validator.is_valid(changed), key)

    def test_records_are_the_merged_contract_bytes(self):
        by_revision = {r.get("revision") or r.get("final_revision"): r for r in VECTOR["records"] if r["state"] == "present"}
        self.assertEqual(by_revision["2"]["mutation_hex"], CONTRACT["update_hex"])
        self.assertEqual(by_revision["3"]["mutation_hex"], CONTRACT["clear_hex"])
        self.assertEqual(VECTOR["contact_hex"], CONTRACT["contact_hex"])

    def test_present_records_are_internally_consistent(self):
        for record in VECTOR["records"]:
            if record["state"] != "present":
                continue
            mutation = bytes.fromhex(record["mutation_hex"])
            self.assertEqual(len(mutation), 368)
            self.assertEqual(mutation[6:22].hex(), VECTOR["account_hex"])
            self.assertEqual(mutation[22:38].hex(), record["contact_hex"])
            self.assertEqual(str(int.from_bytes(mutation[46:54], "big")), record["revision"])
            for kind, field_key in [("name", "name_field_hex"), ("notes", "notes_field_hex")]:
                slot = slots(mutation)[kind]
                field_hex = record[field_key]
                if slot[0] == 0:
                    self.assertIsNone(field_hex, (record["revision"], kind))
                    self.assertEqual(slot[1:], bytes(40))
                    continue
                self.assertIsNotNone(field_hex, (record["revision"], kind))
                field = bytes.fromhex(field_hex)
                self.assertEqual(field[4], 1)
                self.assertEqual(field[5], 1 if kind == "name" else 2)
                self.assertEqual(field[6:22].hex(), VECTOR["account_hex"])
                self.assertEqual(field[22:38].hex(), record["contact_hex"])
                self.assertEqual(field[38:46], slot[1:9])
                self.assertEqual(hashlib.sha256(field).digest(), slot[9:41])
                self.assertLessEqual(int.from_bytes(field[38:46], "big"), int(record["revision"]))

    def test_tombstone_binds_the_last_signed_mutation_only(self):
        latest = max((r for r in VECTOR["records"] if r["state"] == "present"), key=lambda r: int(r["revision"]))
        tomb = next(r for r in VECTOR["records"] if r["state"] == "deleted")
        self.assertEqual(tomb["final_revision"], latest["revision"])
        digest = hashlib.sha256(bytes.fromhex(latest["mutation_hex"])).hexdigest()
        self.assertEqual(tomb["last_mutation_digest_hex"], digest)
        self.assertEqual(digest, CONTRACT["clear_digest_hex"])


if __name__ == "__main__":
    unittest.main()
