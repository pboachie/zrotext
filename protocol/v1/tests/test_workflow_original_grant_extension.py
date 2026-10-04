# SPDX-License-Identifier: AGPL-3.0-only
"""Wire syntax only; current authority and immutable binding need server tests."""
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


class WorkflowOriginalGrantExtension(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.validator = Draft202012Validator(json.loads(
            (root / "workflow-original-grant-extension.schema.json").read_text()))
        self.vector = json.loads((root / "vectors" /
            "workflow-original-grant-extension-01.json").read_text())

    def test_legacy_absence_null_and_exact_selected_identity(self):
        for value in self.vector.values():
            self.validator.validate(value)
        # A different ID is valid syntax, never proof it can revive old authority.
        self.assertNotEqual(self.vector["selected"], self.vector["replacement"])

    def test_no_caller_authority_or_alternate_grant_identity(self):
        for extra in ("verified", "approved", "original_credential", "reader_key_id"):
            value = {**self.vector["selected"], extra: True}
            self.assertTrue(list(self.validator.iter_errors(value)))
        for malformed in (True, [], {}, "", "00000000-0000-0000-0000-000000000000"):
            self.assertTrue(list(self.validator.iter_errors({"original_grant_id": malformed})))


if __name__ == "__main__":
    unittest.main()
