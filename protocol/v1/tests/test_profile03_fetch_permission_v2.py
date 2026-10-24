# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit V2 packet shape, not accepted crypto, storage or permission."""
import base64
import copy
import json
from pathlib import Path
import unittest

import jsonschema
from referencing import Registry, Resource
import test_profile03_fetch_permission as historical

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "profile03-fetch-permission-v2.schema.json").read_text())
VECTORS = json.loads((ROOT / "vectors/reviewed-intent03-v2.json").read_text())
V1 = json.loads((ROOT / "vectors/reviewed-intent03.json").read_text())
REGISTRY = Registry().with_resources([
    (source["$id"], Resource.from_contents(source))
    for source in [historical.BASE, historical.SCHEMA]
])


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class FetchPermissionV2Tests(unittest.TestCase):
    def packet(self, case=None):
        # Other fields are the explicit old shape placeholders; these confer
        # no crypto/currentness. The sole producer's V2 bytes stay unchanged.
        case = case or VECTORS["cases"][0]
        value = historical.FetchPermissionTests().packet()
        value["reviewed_intent"] = encoded(bytes.fromhex(case["intent_hex"]))
        value["reviewed_signature"] = encoded(bytes.fromhex(case["signature_hex"]))
        return value

    def test_same_closed_packet_accepts_only_explicit_v2_header_and_bounds(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        check = jsonschema.Draft202012Validator(SCHEMA, registry=REGISTRY)
        for case in VECTORS["cases"]:
            packet = self.packet(case)
            check.validate(packet)
            self.assertEqual(len(packet), 10)
            self.assertEqual(len(packet["current"]), 40)
        for case in V1["cases"]:
            packet = self.packet()
            packet["reviewed_intent"] = encoded(bytes.fromhex(case["intent_hex"]))
            self.assertFalse(check.is_valid(packet))

    def test_short_long_padded_or_changed_header_is_not_a_v2_packet(self):
        check = jsonschema.Draft202012Validator(SCHEMA, registry=REGISTRY)
        packet = self.packet()
        raw = bytes.fromhex(VECTORS["cases"][0]["intent_hex"])
        maximum = bytes.fromhex(VECTORS["cases"][1]["intent_hex"])
        for wrong in [raw[:-1], maximum + b"x", b"ZTRI\x01\x03\x03\x00" + raw[8:], raw[:5] + b"\x02" + raw[6:]]:
            packet["reviewed_intent"] = encoded(wrong)
            self.assertFalse(check.is_valid(packet))
        packet["reviewed_intent"] = encoded(raw) + "="
        self.assertFalse(check.is_valid(packet))

    def test_new_body_field_other_current_kinds_and_missing_proofs_stay_closed(self):
        check = jsonschema.Draft202012Validator(SCHEMA, registry=REGISTRY)
        packet = self.packet()
        for kind in ["message_permission03", "device_selection03", "capture_permission03"]:
            wrong = copy.deepcopy(packet)
            wrong["current"]["kind"] = kind
            self.assertFalse(check.is_valid(wrong))
        wrong = copy.deepcopy(packet)
        wrong["body_digest"] = "A" * 43
        self.assertFalse(check.is_valid(wrong))
        for field in ["owner_signature", "phone_signature", "installed_signature"]:
            wrong = copy.deepcopy(packet)
            wrong["interval_permission"][field] = None
            self.assertFalse(check.is_valid(wrong))


if __name__ == "__main__":
    unittest.main()
