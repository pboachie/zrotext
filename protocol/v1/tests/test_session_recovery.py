# SPDX-License-Identifier: AGPL-3.0-only
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator


class SessionRecoveryContract(unittest.TestCase):
    def test_closed_exact_target_vectors_do_not_claim_authority(self):
        root = Path(__file__).resolve().parents[1]
        schema = json.loads((root / 'session-recovery.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        vectors = json.loads((root / 'vectors/session-recovery-01.json').read_text())
        validator.validate(vectors['confirmed'])
        for value in vectors['invalid']:
            self.assertTrue(list(validator.iter_errors(value)))
        self.assertEqual(set(schema['properties']), {'method', 'session_id', 'status'})
