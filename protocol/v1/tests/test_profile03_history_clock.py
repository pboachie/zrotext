"""Independent passive DTO/session bytes; no authenticated clock or permission."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest
import uuid

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


class HistoryClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads((ROOT / "vectors/profile03-history-clock-01.json").read_text())
        schema = json.loads((ROOT / "profile03-history-clock.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema)

    def test_closed_requests_replies_and_independent_full_session_bytes(self):
        versions = set()
        digests = set()
        for case in self.vector["cases"]:
            request, reply = case["request"], case["reply"]
            self.validator.validate(request)
            self.validator.validate(reply)
            for field in ("connection_epoch", "request_id", "message_id", "attempt_id"):
                self.assertEqual(request[field], reply[field])
            lease = reply["lease"]
            versions.add(lease["line_activation_version"])
            data = uuid.UUID(reply["account_id"]).bytes + uuid.UUID(reply["device_id"]).bytes
            for field in ("site_id", "instance_id"):
                text = lease[field].encode()
                data += struct.pack(">I", len(text)) + text
            data += struct.pack(">QQH", reply["connection_epoch"],
                                int(lease["deployment_epoch"]), lease["line_activation_version"])
            data += base64.urlsafe_b64decode(lease["enrolled_signing_key_id"] + "=")
            digest = hashlib.sha256(b"ZTSE/line/payload-profile/device-session/v1\0"
                                    + struct.pack(">I", len(data)) + data).digest()
            encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            self.assertEqual(encoded, lease["device_session_digest"])
            digests.add(encoded)
            sampled = int(reply["server_time_ms"])
            self.assertEqual(int(reply["sample_expires_ms"]),
                             min(sampled + 30000, int(lease["expires_ms"])))
        self.assertEqual(versions, {1, 2})
        self.assertEqual(len(digests), 2)

    def test_permission_status_and_noncanonical_shape_are_not_clocks(self):
        for case in self.vector["cases"]:
            for original in (case["request"], case["reply"]):
                for field in original:
                    changed = copy.deepcopy(original)
                    del changed[field]
                    self.assertFalse(self.validator.is_valid(changed), field)
                for extra in ("current", "submit_once", "accepted_ms", "physical_selection"):
                    changed = copy.deepcopy(original)
                    changed[extra] = True
                    self.assertFalse(self.validator.is_valid(changed), extra)
                for epoch in ("7", 0, -1, None):
                    changed = copy.deepcopy(original)
                    changed["connection_epoch"] = epoch
                    self.assertFalse(self.validator.is_valid(changed))
            changed = copy.deepcopy(case["reply"])
            changed["type"] = "payload_profile_submit_status03"
            self.assertFalse(self.validator.is_valid(changed))
            changed = copy.deepcopy(case["reply"])
            changed["lease"]["line_activation_version"] = 3
            self.assertFalse(self.validator.is_valid(changed))

    def test_worst_escaped_configured_identifiers_fit_the_unchanged_frame_bound(self):
        for case in self.vector["cases"]:
            reply = copy.deepcopy(case["reply"])
            reply["lease"]["site_id"] = '"' * 256
            reply["lease"]["instance_id"] = "\\" * 256
            self.validator.validate(reply)
            encoded = json.dumps(reply, ensure_ascii=False, separators=(",", ":")).encode()
            self.assertLess(len(encoded), 4096)
            self.assertLess(len(json.dumps(case["request"]).encode()), 4096)


if __name__ == "__main__":
    unittest.main()
