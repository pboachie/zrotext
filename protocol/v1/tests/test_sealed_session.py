# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import unittest

import jsonschema


class SealedSessionContractTest(unittest.TestCase):
    def setUp(self):
        vectors = Path(__file__).resolve().parents[1] / "vectors"
        self.schema = json.loads((vectors / "sealed-dispatch.schema.json").read_text())
        self.vector = json.loads((vectors / "sealed-session-02.json").read_text())

    def test_exact_challenge_session_frames_preserve_required_identity(self):
        for kind in ("request", "reply"):
            frame = self.vector[kind]
            jsonschema.validate(frame, self.schema)
            for field in frame:
                altered = copy.deepcopy(frame)
                del altered[field]
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(altered, self.schema)
            altered = dict(frame, authorized=True)
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(altered, self.schema)

    def test_nil_nonce_and_invalid_epochs_are_refused(self):
        for field, value in (("challenge", "00000000-0000-0000-0000-000000000000"), ("connection_epoch", 0)):
            for kind in ("request", "reply"):
                frame = dict(self.vector[kind])
                frame[field] = value
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(frame, self.schema)
