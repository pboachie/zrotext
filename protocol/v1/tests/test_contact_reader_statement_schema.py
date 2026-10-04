"""Closed synthetic vector representation, not binary or authority verification."""
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


class ContactReaderStatementSchemaTest(unittest.TestCase):
    def test_closed_historical_integrity_vector(self):
        schema = json.loads((ROOT / "contact-reader-statement.schema.json").read_text(encoding="utf-8"))
        vector = json.loads((ROOT / "contact-reader-statement-vectors.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(vector)
        for key, value in [("synthetic", False), ("comparison", "current"),
                           ("result_kind", "allowed"), ("profile", "ZTKA02"),
                           ("account_hex", "00" * 16), ("declared_issued_ms", "0"),
                           ("statement_hex", "aa" * 818), ("extra", True)]:
            self.assertFalse(validator.is_valid(dict(vector, **{key: value})))

    def test_every_string_rejects_noncanonical_controls(self):
        schema = json.loads((ROOT / "contact-reader-statement.schema.json").read_text(encoding="utf-8"))
        vector = json.loads((ROOT / "contact-reader-statement-vectors.json").read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for key, value in vector.items():
            if isinstance(value, str):
                for control in ["\n", "\r", "\u2028"]:
                    for changed in [value + control, value[:1] + control + value[1:]]:
                        with self.subTest(field=key, control=repr(control)):
                            self.assertFalse(validator.is_valid(dict(vector, **{key: changed})))


if __name__ == "__main__":
    unittest.main()
