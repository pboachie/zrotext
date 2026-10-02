"""Shape checks only; signature and operation correlation are enforced in Rust."""
import copy
import json
from pathlib import Path
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[1]


class ExternalAuthoritySchemaTests(unittest.TestCase):
    def setUp(self):
        self.validator = jsonschema.Draft202012Validator(
            json.loads((ROOT / "external-authority-v1.schema.json").read_text()),
            format_checker=jsonschema.FormatChecker(),
        )
        self.receipt = json.loads(
            (ROOT / "vectors/external-authority-v1.json").read_text()
        )["receipt"]

    def test_shape_fixture_and_closed_operation_variants(self):
        self.validator.validate(self.receipt)
        for operation in [
            {"kind": "status", "site": "site-a"},
            {"kind": "read_epoch"},
            {"kind": "record_epoch", "epoch": 5},
        ]:
            receipt = copy.deepcopy(self.receipt)
            receipt["request"]["operation"] = operation
            self.validator.validate(receipt)

    def test_unknown_authority_fields_and_invalid_epoch_or_namespace_refuse(self):
        for field, value in [("namespace", "../foreign"), ("nonce", "old-response"),
                             ("credential", "not-model-authority")]:
            receipt = copy.deepcopy(self.receipt)
            receipt["request"][field] = value
            self.assertFalse(self.validator.is_valid(receipt))
        for epoch in [0, -1, 9223372036854775808]:
            receipt = copy.deepcopy(self.receipt)
            receipt["reply"]["epoch"] = epoch
            self.assertFalse(self.validator.is_valid(receipt))
        receipt = copy.deepcopy(self.receipt)
        receipt["request"]["operation"] = {"kind": "unfence", "site": "site-a"}
        self.assertFalse(self.validator.is_valid(receipt))


if __name__ == "__main__":
    unittest.main()
