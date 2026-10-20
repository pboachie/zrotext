# SPDX-License-Identifier: AGPL-3.0-only
"""DTO shape controls, deliberately not cryptography or current permission."""
import copy
import json
from pathlib import Path
import unittest

import jsonschema
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads((ROOT / "profile03-manifest-transport.schema.json").read_text())
SCHEMA = json.loads((ROOT / "profile03-fetch-permission.schema.json").read_text())
REGISTRY = Registry().with_resource(BASE["$id"], Resource.from_contents(BASE))


def sample(rule):
    """Only a shape placeholder. These strings intentionally prove no signature."""
    if "$ref" in rule:
        name = rule["$ref"].split("/")[-1]
        return sample(SCHEMA["$defs"].get(name, BASE["$defs"].get(name)))
    if "allOf" in rule:
        value = {}
        for part in rule["allOf"]:
            value.update(sample(part))
        return value
    if "const" in rule:
        return rule["const"]
    if "oneOf" in rule:
        return sample(rule["oneOf"][0])
    if rule.get("type") == "object" or "properties" in rule:
        return {key: sample(rule["properties"][key]) for key in rule["required"]}
    if rule.get("type") == "array":
        return []
    if rule.get("type") == "string":
        pattern = rule.get("pattern", "")
        if pattern.startswith("^[1-9]"):
            return "1"
        if pattern.startswith("^[0-9a-f]"):
            return "11111111-1111-4111-8111-111111111111"
        return "A" * rule.get("minLength", 1)
    raise AssertionError(rule)


class FetchPermissionTests(unittest.TestCase):
    def packet(self):
        packet = sample(SCHEMA["allOf"][0])
        current = sample(BASE["$defs"]["selection_common"])
        extra = SCHEMA["$defs"]["current"]["allOf"][1]
        current.update({key: sample(extra["properties"][key]) for key in extra["required"]})
        packet["current"] = current
        packet["interval_permission"] = sample(SCHEMA["$defs"]["interval_permission"])
        return packet

    def test_exact_current_kind_and_correlation_fields_are_required(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        check = jsonschema.Draft202012Validator(SCHEMA, registry=REGISTRY)
        packet = self.packet()
        check.validate(packet)
        self.assertEqual(len(packet), 10)
        self.assertEqual(len(packet["current"]), 40)
        for field in ["request_id", "fetch_transcript_sha256", "physical_selection", "current_manifest03", "manifest_ancestry_sha256"]:
            changed = copy.deepcopy(packet)
            del changed["current"][field]
            self.assertFalse(check.is_valid(changed))
        for kind in ["message_permission03", "device_selection03", "capture_permission03"]:
            changed = copy.deepcopy(packet)
            changed["current"]["kind"] = kind
            self.assertFalse(check.is_valid(changed))
        changed = copy.deepcopy(packet)
        changed["current"]["selection_expires_ms"] = "1"
        self.assertFalse(check.is_valid(changed))
        self.assertFalse(check.is_valid([packet]))

    def test_full_active_interval_and_exact_mapping_direction_are_required(self):
        check = jsonschema.Draft202012Validator(SCHEMA, registry=REGISTRY)
        packet = self.packet()
        permission = packet["interval_permission"]
        permission["readers"] = [sample(SCHEMA["$defs"]["reader"])]
        check.validate(packet)
        for field in ["owner_signature", "phone_signature", "installed_signature", "requested_ms", "approved_ms", "installed_ms"]:
            changed = copy.deepcopy(packet)
            changed["interval_permission"][field] = None
            self.assertFalse(check.is_valid(changed))
        for direction in [4, 8]:
            changed = copy.deepcopy(packet)
            changed["interval_permission"]["readers"][0]["read_directions"] = direction
            self.assertFalse(check.is_valid(changed))
        for field, value in [("phase", "requested"), ("request_kind", "capture")]:
            changed = copy.deepcopy(packet)
            changed["interval_permission"][field] = value
            self.assertFalse(check.is_valid(changed))
        changed = copy.deepcopy(packet)
        changed["interval_permission"]["readers"] *= 7
        self.assertFalse(check.is_valid(changed))


if __name__ == "__main__":
    unittest.main()
