"""Independent exact webhook HMAC and fail-closed local response schema checks."""
import copy
import hashlib
import hmac
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads((ROOT / "protocol/v1/vectors/agent-reply-events-01.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((ROOT / "protocol/drafts/agent-reply-events-01.schema.json").read_text(encoding="utf-8"))


class ReplyEventContractTests(unittest.TestCase):
    def test_exact_webhook_bytes_match_independent_hmac_and_mutations_do_not(self):
        self.assertEqual(VECTOR["status"], "UNAPPROVED_TEST_ONLY")
        transcript = VECTOR["timestamp"].encode("ascii") + b"." + VECTOR["rawBody"].encode("utf-8")
        key = bytes.fromhex(VECTOR["syntheticWebhookBytesHex"])
        signature = hmac.new(key, transcript, hashlib.sha256).hexdigest()
        self.assertEqual("v1=" + signature, VECTOR["signature"])
        self.assertNotEqual(signature, hmac.new(key, transcript + b" ", hashlib.sha256).hexdigest())
        self.assertNotEqual(signature, hmac.new(bytes(32), transcript, hashlib.sha256).hexdigest())

    def test_shared_response_shapes_validate_and_never_grant_approval(self):
        validator = Draft202012Validator(SCHEMA)
        Draft202012Validator.check_schema(SCHEMA)
        for response in VECTOR["responses"]:
            validator.validate(response)
            if "approval" in response:
                changed = copy.deepcopy(response)
                changed["approval"] = True
                self.assertFalse(validator.is_valid(changed))
                if response["state"] == "unknown":
                    changed = copy.deepcopy(response)
                    changed["execute"] = True
                    self.assertFalse(validator.is_valid(changed))
            for event in response.get("events", []):
                changed = copy.deepcopy(response)
                changed["events"][0]["approval"] = True
                self.assertFalse(validator.is_valid(changed))
                self.assertFalse(event["approval"])

    def test_stop_never_becomes_decrypted_and_pages_and_unknown_fields_are_bounded(self):
        validator = Draft202012Validator(SCHEMA)
        page = next(response for response in VECTOR["responses"] if "events" in response)
        changed = copy.deepcopy(page)
        changed["events"][0]["content"] = {"kind": "decrypted", "text": "Synthetic reply", "readerId": VECTOR["readerId"]}
        self.assertFalse(validator.is_valid(changed))
        changed = copy.deepcopy(page)
        changed["events"] *= 21
        self.assertFalse(validator.is_valid(changed))
        changed = copy.deepcopy(page)
        changed["plaintext_fallback"] = "Synthetic reply"
        self.assertFalse(validator.is_valid(changed))


if __name__ == "__main__":
    unittest.main()
