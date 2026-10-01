# SPDX-License-Identifier: AGPL-3.0-only
import base64
import copy
import json
import pathlib
import unittest

import jsonschema


class OwnerHostSchemaTest(unittest.TestCase):
    def test_bounded_requests_reject_claimed_authority(self):
        schema = json.loads((pathlib.Path(__file__).resolve().parents[1] /
                             "conversation-owner-host.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        selected = {"device_id": "11111111-1111-4111-8111-111111111111",
                    "line_id": "22222222-2222-4222-8222-222222222222",
                    "binding_generation": 1, "peer": "+12025550199"}
        # Serialization shapes only; these opaque bytes are not authority proofs.
        manifest = base64.b64encode(bytes(364)).decode()
        key_id = base64.b64encode(bytes(32)).decode()
        activation = {"consent": dict(selected, disclosure_version="conversation-content-v1",
                                      content_transfer_confirmed=True), "next_manifest": manifest}
        enrollment = dict(selected, phone_reader=key_id, archive_reader=key_id,
                          signer=key_id, predecessor=key_id,
                          public_point=base64.b64encode(bytes(65)).decode(),
                          signed_successor=manifest)
        for valid in (selected, activation, enrollment):
            jsonschema.validate(valid, schema)
            for field in ("account_id", "session_id", "site_id", "server_now_ms", "root_pin"):
                changed = copy.deepcopy(valid)
                changed[field] = "claimed"
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(changed, schema)
        for field, value in (("binding_generation", 0), ("binding_generation", "1"),
                             ("device_id", "00000000-0000-0000-0000-000000000000")):
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(dict(selected, **{field: value}), schema)
        for value in (manifest[:-1], "A" * 13008):
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(dict(activation, next_manifest=value), schema)


if __name__ == "__main__":
    unittest.main()
