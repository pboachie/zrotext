"""Validate every Rust-linked device-stream example against the public schema."""

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]


class DeviceStreamSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads((ROOT / "device-stream.schema.json").read_text())
        cls.frames = json.loads((ROOT / "device-stream.examples.json").read_text())
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema, format_checker=FormatChecker())

    def test_every_frame_variant_has_a_valid_example(self):
        names = [frame["type"] for frame in self.frames]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), set(self.schema["$defs"]) - {"uuid", "epoch", "ms", "digest"})
        self.assertEqual(len(self.schema["oneOf"]), len(names))
        for frame in self.frames:
            with self.subTest(frame=frame["type"]):
                self.validator.validate(frame)

    def test_unknown_and_missing_fields_are_rejected(self):
        for frame in self.frames:
            with self.subTest(frame=frame["type"]):
                self.assertFalse(self.validator.is_valid({**frame, "unexpected": True}))
                missing = dict(frame)
                key = next((key for key in frame if key not in ("type", "v")), "v")
                del missing[key]
                self.assertFalse(self.validator.is_valid(missing))

    def test_grant_discloses_number_and_radio_codes_are_wire_codes(self):
        grant = self.schema["$defs"]["synthetic_grant"]
        self.assertIn("recipient_e164", grant["required"])
        self.assertIn("body", grant["required"])
        radio = next(frame for frame in self.frames if frame["type"] == "radio_event")
        for evidence in self.schema["$defs"]["radio_event"]["properties"]["evidence"]["enum"]:
            self.assertTrue(self.validator.is_valid({**radio, "evidence": evidence}))
        self.assertFalse(self.validator.is_valid({**radio, "evidence": "grant_timeout"}))


if __name__ == "__main__":
    unittest.main()
