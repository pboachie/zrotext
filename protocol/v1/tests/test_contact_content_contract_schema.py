# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

BASE = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((BASE / "contact-content-contract.schema.json").read_text(encoding="utf-8"))
VECTOR = json.loads((BASE / "contact-content-contract-vectors.json").read_text(encoding="utf-8"))


class ContactContentRepresentation(unittest.TestCase):
    def test_closed_shared_vector_and_exact_widths(self):
        validator = Draft202012Validator(SCHEMA)
        validator.validate(VECTOR)
        for key in VECTOR:
            missing = copy.deepcopy(VECTOR)
            del missing[key]
            self.assertFalse(validator.is_valid(missing), key)
        extra = copy.deepcopy(VECTOR)
        extra["current"] = True
        self.assertFalse(validator.is_valid(extra))
        for key, value in VECTOR.items():
            if key.endswith("_hex"):
                changed = copy.deepcopy(VECTOR)
                changed[key] = ""
                self.assertFalse(validator.is_valid(changed), key)
                changed[key] = value[:-1]
                self.assertFalse(validator.is_valid(changed), (key, "odd hex width"))
        for key in ["create_hex", "update_hex", "clear_hex", "contact_hex", "routing_digest_hex"]:
            changed = copy.deepcopy(VECTOR)
            changed[key] += "00"
            self.assertFalse(validator.is_valid(changed), key)

    def test_all_string_fields_reject_suffix_and_embedded_control_aliases(self):
        validator = Draft202012Validator(SCHEMA)
        for path, value in self.strings(VECTOR):
            for control in ["\n", "\r", "\r\n", "\u2028", "\u2029"]:
                for replacement in [value + control, value[:1] + control + value[1:]]:
                    changed = copy.deepcopy(VECTOR)
                    target = changed
                    for part in path[:-1]:
                        target = target[part]
                    target[path[-1]] = replacement
                    self.assertFalse(validator.is_valid(changed), (path, control))

    @staticmethod
    def strings(value, path=()):
        for key, item in value.items():
            if isinstance(item, str):
                yield path + (key,), item
            elif isinstance(item, dict):
                yield from ContactContentRepresentation.strings(item, path + (key,))


if __name__ == "__main__":
    unittest.main()
