"""Additive v2 frame shape and cross-language encoding conformance, not authority."""
import hashlib
import json
from pathlib import Path
import re
import unittest
import uuid

from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[3]
V2 = ROOT / "protocol/v2"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def reject_number(_):
    raise ValueError("non-integer numeric token")


def raw_frame(text, validator):
    """Test contract reader only; deployed consumers must enforce these checks."""
    if len(text.encode("utf-8")) > 4096:
        raise ValueError("frame bound")
    frame = json.loads(text, object_pairs_hook=unique_object,
                       parse_float=reject_number, parse_constant=reject_number)
    validator.validate(frame)
    return frame


class LineActivationV2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = json.loads((V2 / "line-activation.schema.json").read_text())
        cls.vector = json.loads((V2 / "vectors/line-activation.json").read_text())
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)
        cls.frames = {frame["type"]: frame for frame in cls.vector["frames"]}

    def test_every_closed_variant_has_exactly_one_shape_vector(self):
        self.assertEqual(len(self.frames), 10)
        self.assertEqual(len(self.vector["frames"]), len(self.frames))
        self.assertEqual({r["$ref"].split("/")[-1] for r in self.schema["oneOf"]},
                         set(self.frames))
        for name, frame in self.frames.items():
            with self.subTest(name=name):
                self.assertEqual(raw_frame(json.dumps(frame), self.validator), frame)
                self.assertFalse(self.validator.is_valid({**frame, "unexpected": True}))
                for key in frame:
                    changed = dict(frame)
                    del changed[key]
                    self.assertFalse(self.validator.is_valid(changed), (name, key))
                    self.assertFalse(self.validator.is_valid({**frame, key: None}), (name, key))

    def test_direction_specific_epochs_and_no_sms_installation(self):
        for name, frame in self.frames.items():
            needs_epoch = name.startswith("sealed_") or name == "sms_line_proof_v2"
            self.assertEqual("connection_epoch" in frame, needs_epoch)
            if not needs_epoch:
                self.assertFalse(self.validator.is_valid({**frame, "connection_epoch": "1"}))
        installed = self.frames["sealed_line_installed_v2"]
        for suffix in ("installed_v2", "install_ack_v2"):
            self.assertFalse(self.validator.is_valid({**installed, "type": "sms_line_" + suffix}))

    def test_raw_duplicate_numeric_and_nonobject_inputs_refuse(self):
        frame = self.frames["sealed_line_challenge_v2"]
        text = json.dumps(frame, separators=(",", ":"))
        cases = [text.replace('"v":2', '"v":2,"v":2'),
                 text.replace('"v":2', '"v":2.0'),
                 text.replace('"v":2', '"v":2e0'),
                 text.replace('"expires_at_ms":1700000000000', '"expires_at_ms":1.0'),
                 text.replace('"expires_at_ms":1700000000000', '"expires_at_ms":NaN'),
                 "[]", "null", '"object"', "true", " " * 4097 + text]
        for raw in cases:
            with self.subTest(raw=raw[:70]):
                with self.assertRaises((ValueError, ValidationError)):
                    raw_frame(raw, self.validator)

    def test_positive_i64_strings_preserve_large_values_and_exact_bounds(self):
        frame = self.frames["sealed_line_activated_v2"]
        for key in ("generation", "connection_epoch"):
            for value in ("1", "9007199254740993", "9223372036854775807"):
                self.assertTrue(self.validator.is_valid({**frame, key: value}))
            for value in (0, 1, True, "0", "01", "+1", "-1", "1.0", "1e0", " 1",
                          "1\n", "9223372036854775808", "9999999999999999999", "1" * 20):
                self.assertFalse(self.validator.is_valid({**frame, key: value}), value)
        # Exercise every equal-length prefix boundary rather than only the maximum.
        maximum = 9223372036854775807
        for offset in (-1000000000000000000, -1, 0, 1, 1000000000000000000):
            value = maximum + offset
            self.assertEqual(self.validator.is_valid({**frame, "generation": str(value)}),
                             0 < value <= maximum)

    def test_uuid_base64_and_boolean_bounds(self):
        frame = self.frames["sealed_line_activated_v2"]
        for key in ("account_id", "line_id", "device_id", "challenge_id"):
            for invalid in ("00000000-0000-0000-0000-000000000000", "ABCDEF00-0000-4000-8000-000000000001",
                            frame[key].replace("-", ""), frame[key] + "\n"):
                self.assertFalse(self.validator.is_valid({**frame, key: invalid}))
        for key in ("device_statement_sha256", "device_signature_sha256"):
            for invalid in ("A" * 42, "A" * 44, "A" * 42 + "B", frame[key] + "=", frame[key] + "\n"):
                self.assertFalse(self.validator.is_valid({**frame, key: invalid}))
        proof = self.frames["sms_line_proof_v2"]
        for invalid in ("A" * 161, "A" * 163, "A" * 161 + "B", proof["observation_b64url"] + "="):
            self.assertFalse(self.validator.is_valid({**proof, "observation_b64url": invalid}))
        ack = self.frames["sealed_line_install_ack_v2"]
        self.assertTrue(self.validator.is_valid({**ack, "accepted": False}))
        for invalid in (0, 1, "true", None):
            self.assertFalse(self.validator.is_valid({**ack, "accepted": invalid}))

    def test_numeric_expiry_is_not_an_epoch_string_or_floating_token(self):
        frame = self.frames["sms_line_challenge_v2"]
        for valid in (1, 9007199254740993, 9223372036854775807):
            self.assertTrue(self.validator.is_valid({**frame, "expires_at_ms": valid}))
        for invalid in (0, -1, True, "1", 9223372036854775808):
            self.assertFalse(self.validator.is_valid({**frame, "expires_at_ms": invalid}))

    def test_encoding_answers_reconstruct_exact_purpose_transcripts(self):
        challenge = self.vector["challenge"]
        der = bytes.fromhex(self.vector["encoding_der_hex"])
        self.assertEqual(der, bytes.fromhex("3006020101020101"))
        self.assertEqual(len(self.vector["encodings"]), 11)
        for answer in self.vector["encodings"]:
            with self.subTest(name=answer["name"]):
                observation = bytes.fromhex(answer["observation_hex"])
                self.assertEqual(len(observation), 121)
                self.assertGreaterEqual(int.from_bytes(observation[:2], "big"), 33)
                self.assertIn(int.from_bytes(observation[2:4], "big"), range(1, 257))
                self.assertIn(observation[8], (1, 2))
                self.assertGreater(int.from_bytes(observation[65:73], "big", signed=True), 0)
                prefix, code = (b"ZTSMS", 1) if answer["purpose"] == "sms" else (b"ZTSE", 2)
                device = prefix + b"/line/device-confirm/v2\0" + bytes((2, code))
                device += b"".join(uuid.UUID(challenge[k]).bytes for k in ("account_id", "line_id", "device_id"))
                device += int(answer["generation"]).to_bytes(8, "big", signed=True)
                device += uuid.UUID(challenge["challenge_id"]).bytes + bytes.fromhex(challenge["nonce_hex"])
                device += observation
                owner = prefix + b"/line/owner-approve/v2\0" + device + hashlib.sha256(der).digest()
                self.assertEqual(device.hex(), answer["device_hex"])
                self.assertEqual(owner.hex(), answer["owner_hex"])
                self.assertEqual(hashlib.sha256(device).hexdigest(), answer["device_digest_hex"])
                self.assertEqual(hashlib.sha256(owner).hexdigest(), answer["owner_digest_hex"])

    def test_answers_match_independent_rust_codec_literals(self):
        source = (ROOT / "crates/server/src/sealed_inbound/line_activation/v2/tests.rs").read_text()
        for answer in self.vector["encodings"]:
            block = re.search(r'name: "' + re.escape(answer["name"]) + r'",(.*?)\n    \}', source, re.S).group(1)
            for key in ("observation_hex", "device_hex", "owner_hex", "device_digest_hex", "owner_digest_hex"):
                self.assertIn(f'{key}: "{answer[key]}"', block)


if __name__ == "__main__":
    unittest.main()
