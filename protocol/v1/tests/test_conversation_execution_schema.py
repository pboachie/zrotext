"""The dormant conversation producer narrows the existing grant contract."""
import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


class ConversationExecutionSchemaTest(unittest.TestCase):
    def test_first_and_only_bounded_grant(self):
        schema = json.loads((ROOT / "conversation-execution.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        frame = json.loads((ROOT / "vectors/sealed-execution-grant-01.json").read_text())["frame"]
        validator.validate(frame)
        for field, value in [
            ("attempt_generation", 2), ("reader_role", 2),
            ("segment_count", 0), ("segment_count", 7),
            ("connection_epoch", 2**53), ("expires_at_ms", 2**53),
            ("deployment_epoch", 0), ("binding_generation", -1),
            ("envelope_sha256", "invalid"), ("attempt_id", "00000000-0000-0000-0000-000000000000"),
        ]:
            changed = copy.deepcopy(frame)
            changed[field] = value
            self.assertFalse(validator.is_valid(changed), (field, value))
        self.assertFalse(validator.is_valid(dict(frame, extra="refused")))


if __name__ == "__main__":
    unittest.main()
