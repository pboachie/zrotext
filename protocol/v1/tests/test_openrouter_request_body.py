# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic structural controls; no provider, grant or task authority."""

import copy
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


VECTORS = Path(__file__).resolve().parents[1] / "vectors"


class OpenRouterRequestBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads(
            (VECTORS / "openrouter-request-body.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)
        cls.vector = json.loads(
            (VECTORS / "openrouter-request-body-01.json").read_text(encoding="utf-8")
        )

    def assert_refused(self, body):
        self.assertTrue(list(self.validator.iter_errors(body)), "expected structural refusal")

    def changed(self, path, replacement):
        body = copy.deepcopy(self.vector)
        parent = body
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = replacement
        return body

    def test_independent_expected_fixture_and_closed_shape(self):
        expected = {
            "model": "synthetic/model-alpha",
            "messages": [
                {"role": "system", "content": 'Summarize synthetic text.\nPreserve "quotes" and a final slash: \\'},
                {"role": "user", "content": "Aster blooms. λ雪\x01"},
            ],
            "max_completion_tokens": 17,
            "stream": False,
            "provider": {
                "only": ["synthetic-provider"],
                "allow_fallbacks": False,
                "require_parameters": True,
                "data_collection": "deny",
                "zdr": True,
            },
        }
        self.assertEqual(self.vector, expected)
        self.validator.validate(expected)
        self.assertEqual(len(expected), 5)
        self.assertEqual(len(expected["provider"]), 5)
        self.assertEqual([len(message) for message in expected["messages"]], [2, 2])

    def test_unknown_fields_refuse_at_every_object(self):
        for path in [(), ("provider",), ("messages", 0), ("messages", 1)]:
            for field in ["extensions", "task_id", "account_id", "region", "credential", "tools"]:
                with self.subTest(path=path, field=field):
                    body = copy.deepcopy(self.vector)
                    target = body
                    for key in path:
                        target = target[key]
                    target[field] = "synthetic"
                    self.assert_refused(body)

    def test_each_required_field_refuses_when_missing(self):
        for path in [(), ("provider",), ("messages", 0), ("messages", 1)]:
            target = self.vector
            for key in path:
                target = target[key]
            for field in target:
                with self.subTest(path=path, field=field):
                    body = copy.deepcopy(self.vector)
                    parent = body
                    for key in path:
                        parent = parent[key]
                    del parent[field]
                    self.assert_refused(body)

    def test_privacy_fallback_and_stream_requests_are_fixed(self):
        changes = [
            (("stream",), True),
            (("provider", "allow_fallbacks"), True),
            (("provider", "require_parameters"), False),
            (("provider", "data_collection"), "allow"),
            (("provider", "zdr"), False),
            (("provider", "only"), []),
            (("provider", "only"), ["synthetic-provider", "synthetic-other"]),
        ]
        for path, replacement in changes:
            with self.subTest(path=path, replacement=replacement):
                self.assert_refused(self.changed(path, replacement))

    def test_message_roles_order_counts_and_text_types_refuse(self):
        messages = self.vector["messages"]
        for replacement in [[], messages[:1], messages + [messages[1]], list(reversed(messages)), {}]:
            with self.subTest(replacement=replacement):
                self.assert_refused(self.changed(("messages",), replacement))
        for index in [0, 1]:
            for role in ["assistant", "tool", "developer", None, 1, ""]:
                self.assert_refused(self.changed(("messages", index, "role"), role))
            for text in ["", "x" * 8193, None, 1, True, [], {"text": "synthetic"}]:
                self.assert_refused(self.changed(("messages", index, "content"), text))

    def test_profile_lexical_and_length_refusals(self):
        invalid = ["", "x" * 129, "/model", "model/", "model//part", "model name", "model\n", "model\x00", 'model"name', "model\\name", "model:*", "model@hint", "mødel", None, 1, True, []]
        for path in [("model",), ("provider", "only", 0)]:
            for slug in invalid:
                with self.subTest(path=path, slug=slug):
                    self.assert_refused(self.changed(path, slug))
            for slug in ["x", "x" * 128, "synthetic/model_alias-1.2"]:
                self.validator.validate(self.changed(path, slug))

    def test_token_ceiling_and_scalar_type_confusion(self):
        for tokens in [0, 65537, -1, 1.5, "17", True, None, []]:
            self.assert_refused(self.changed(("max_completion_tokens",), tokens))
        for tokens in [1, 65536]:
            self.validator.validate(self.changed(("max_completion_tokens",), tokens))
        for path in [("stream",), ("provider", "allow_fallbacks"), ("provider", "require_parameters"), ("provider", "zdr")]:
            for wrong in [0, 1, "false", None, []]:
                self.assert_refused(self.changed(path, wrong))
        for wrong in [None, True, 1, [], {}]:
            self.assert_refused(self.changed(("provider", "data_collection"), wrong))
        for wrong in ["synthetic-provider", None, True, 1, {}]:
            self.assert_refused(self.changed(("provider", "only"), wrong))

    def test_schema_character_limit_is_not_combined_utf8_byte_authority(self):
        # Intentionally structural-valid but above the encoder's combined byte
        # cap. A schema cannot replace the independent Rust byte controls.
        body = copy.deepcopy(self.vector)
        body["messages"][0]["content"] = "雪" * 4096
        body["messages"][1]["content"] = "λ" * 4096
        self.validator.validate(body)
        self.assertGreater(sum(len(message["content"].encode("utf-8")) for message in body["messages"]), 8192)
        self.assertIn("Structural output shape only", self.schema["$comment"])


if __name__ == "__main__":
    unittest.main()
