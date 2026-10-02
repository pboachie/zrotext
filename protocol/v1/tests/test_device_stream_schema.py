"""Validate every Rust-linked device-stream example against the public schema."""

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]


class DeviceStreamSchemaTest(unittest.TestCase):
    def test_sealed_line_setup_frames_preserve_epoch_and_exact_receipt_bounds(self):
        names = {"sealed_line_challenge", "sealed_line_proof", "sealed_line_proof_ack",
                 "sealed_line_activated", "sealed_line_installed", "sealed_line_install_ack"}
        frames = {frame["type"]: frame for frame in self.frames if frame["type"] in names}
        self.assertEqual(set(frames), names)
        for frame in frames.values():
            self.validator.validate(frame)
            self.assertFalse(self.validator.is_valid({**frame, "connection_epoch": 0}))
            self.assertFalse(self.validator.is_valid({**frame, "body": "synthetic"}))
        proof = frames["sealed_line_proof"]
        self.assertFalse(self.validator.is_valid({**frames["sealed_line_challenge"], "nonce": "A" * 43}))
        self.assertFalse(self.validator.is_valid({**proof, "android_api_level": 30}))
        self.assertFalse(self.validator.is_valid({**proof, "active_subscription_count": 2}))
        for name in ("sealed_line_activated", "sealed_line_installed"):
            receipt = frames[name]
            for value in ("A" * 42, "A" * 44, "A" * 42 + "B", "A" * 43 + "="):
                self.assertFalse(self.validator.is_valid({**receipt, "device_statement_sha256": value}))

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

    def test_line_opt_out_has_only_stop_actions_and_no_body_or_clear_ack(self):
        frame = next(frame for frame in self.frames if frame["type"] == "line_opt_out")
        ack = next(frame for frame in self.frames if frame["type"] == "line_opt_out_ack")
        for action in ("opt_out", "opt_out_review"):
            self.assertTrue(self.validator.is_valid({**frame, "action": action}))
        for action in ("opt_in", "start", "captured_local"):
            self.assertFalse(self.validator.is_valid({**frame, "action": action}))
        self.assertFalse(self.validator.is_valid({**frame, "body": "synthetic"}))
        self.assertFalse(self.validator.is_valid({**frame, "attempt_id": frame["event_id"]}))
        self.assertFalse(self.validator.is_valid({**ack, "suppression_cleared": True}))

    def test_network_service_is_v2_only_and_never_a_readiness_flag(self):
        frame = next(frame for frame in self.frames if frame["type"] == "device_status_v2")
        for state in ("in_service", "out_of_service", "emergency_only", "power_off", "unavailable"):
            self.assertTrue(self.validator.is_valid({**frame, "network_service": state}))
        for invalid in (None, True, "ready", "", "x" * 5000):
            self.assertFalse(self.validator.is_valid({**frame, "network_service": invalid}))
        self.assertFalse(self.validator.is_valid({**frame, "type": "device_status"}))
        self.assertFalse(self.validator.is_valid({**frame, "subscription_id": 7}))

    def test_device_status_accepts_only_fixed_preconditions_without_identity_or_clock(self):
        frame = next(frame for frame in self.frames if frame["type"] == "device_status")
        for key, valid in (("selected_sim", "unavailable"), ("sms_permission", "denied"), ("airplane_mode", "enabled")):
            self.assertTrue(self.validator.is_valid({**frame, key: valid}))
            for invalid in ("x" * 5000, "", None, True, 1, [valid]):
                self.assertFalse(self.validator.is_valid({**frame, key: invalid}))
        for key in ("account_id", "device_id", "subscription_id", "card_id", "phone_number", "observed_at_ms", "ready"):
            self.assertFalse(self.validator.is_valid({**frame, key: 1}))

    def test_radio_timestamp_requires_a_positive_observation(self):
        frame = next(frame for frame in self.frames if frame["type"] == "radio_event")
        for observed_at_ms in (-1, 0):
            self.assertFalse(self.validator.is_valid({**frame, "observed_at_ms": observed_at_ms}))
        # Dynamic attempt/database clock bounds are exercised by delivery-store.
        self.assertTrue(self.validator.is_valid({**frame, "observed_at_ms": 1}))


if __name__ == "__main__":
    unittest.main()
