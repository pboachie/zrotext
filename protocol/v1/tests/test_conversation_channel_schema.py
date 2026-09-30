# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
import pathlib
import unittest
import jsonschema


class ConversationChannelSchemaTest(unittest.TestCase):
    def test_exact_session_and_rejected_ambiguities(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        schema = json.loads((root / "conversation-channel.schema.json").read_text())
        ready = {"v": 1, "type": "conversation_ready", "connection_epoch": 7,
                 "challenge": "11111111-1111-4111-8111-111111111111"}
        reply = dict(ready, type="conversation_session", deployment_epoch=3,
                     account_id="22222222-2222-4222-8222-222222222222",
                     device_id="33333333-3333-4333-8333-333333333333",
                     phone_session="44444444-4444-4444-8444-444444444444",
                     origin_hash="ab" * 32)
        for valid in (ready, reply):
            jsonschema.validate(valid, schema)
        for field, value in (("connection_epoch", 7.5), ("deployment_epoch", 0),
                             ("origin_hash", "AB" * 32), ("phone_session", "00000000-0000-0000-0000-000000000000"),
                             ("unexpected", True)):
            bad = copy.deepcopy(reply)
            bad[field] = value
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(bad, schema)


if __name__ == "__main__":
    unittest.main()
