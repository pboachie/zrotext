# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


class MessageSummaryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = Draft202012Validator(
            json.loads((ROOT / "message-summary.schema.json").read_text(encoding="utf-8")),
            format_checker=FormatChecker(),
        )
        cls.vectors = json.loads((ROOT / "vectors/message-summary.json").read_text(encoding="utf-8"))

    def test_zero_exact_and_capped_scoped_snapshots_are_valid(self):
        for vector in self.vectors:
            self.validator.validate(vector)
            self.assertEqual(vector["day_end_ms"] - vector["day_start_ms"], 86400000)
            self.assertLessEqual(vector["day_start_ms"], vector["observed_at_ms"])
            self.assertLess(vector["observed_at_ms"], vector["day_end_ms"])

    def test_scope_and_metadata_bounds_fail_closed(self):
        for field, value in [("device_id", "not-a-device"), ("timezone", "local"),
                             ("count_bound", 10000), ("max_age_ms", 60000),
                             ("recipient", "unavailable"), ("body", "unavailable")]:
            changed = copy.deepcopy(self.vectors[1])
            changed[field] = value
            self.assertFalse(self.validator.is_valid(changed), field)
        changed = copy.deepcopy(self.vectors[0])
        changed["device_id"] = self.vectors[1]["device_id"]
        self.assertFalse(self.validator.is_valid(changed))

    def test_capped_is_a_bound_and_never_a_boolean_zero_or_overflow(self):
        for count in [{"value": 0, "capped": True}, {"value": True, "capped": False},
                      {"value": 1001, "capped": False}, {"value": -1, "capped": False}]:
            changed = copy.deepcopy(self.vectors[0])
            changed["pending"] = count
            self.assertFalse(self.validator.is_valid(changed))


if __name__ == "__main__":
    unittest.main()
