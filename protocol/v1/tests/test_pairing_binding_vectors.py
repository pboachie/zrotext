"""Keep the phone recovery transcript independent of implementation layout."""
import json
from pathlib import Path
import unittest
import uuid
import jsonschema


class PairingBindingVectors(unittest.TestCase):
    def test_network_order_and_domain_are_exact(self):
        vector = json.loads((Path(__file__).parents[1] / "vectors" / "pairing-binding-01.json").read_text())
        transcript = b"ZROTEXT-PAIRING-BINDING-V1\0"
        transcript += b"".join(uuid.UUID(vector[key]).bytes for key in ("account_id", "pairing_id", "challenge_id"))
        transcript += bytes.fromhex(vector["key_fingerprint"]) + bytes.fromhex(vector["nonce_hex"])
        self.assertEqual(transcript.hex(), vector["transcript_hex"])
        self.assertEqual(len(transcript), 139)

    def test_binding_status_does_not_imply_unapproved_device(self):
        root = Path(__file__).parents[1]
        schema = json.loads((root / "pairing-binding.schema.json").read_text())
        fixture = json.loads((root / "vectors" / "pairing-binding-01.json").read_text())
        response = {"schema_version": 1, "status": "pending", "account_id": fixture["account_id"],
                    "pairing_id": fixture["pairing_id"], "device_id": None,
                    "comparison_code": "12345678", "key_fingerprint": fixture["key_fingerprint"]}
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(response)
        response["comparison_code"] = None
        self.assertFalse(validator.is_valid(response))
        response["comparison_code"] = "12345678"
        response["device_id"] = fixture["challenge_id"]
        self.assertFalse(validator.is_valid(response))
        response["status"] = "approved"
        validator.validate(response)
        response["comparison_code"] = None
        validator.validate(response)
        response["comparison_code"] = "12345678"
        response["extra"] = True
        self.assertFalse(validator.is_valid(response))
        response.pop("extra")
        response["status"] = "expired"
        response["device_id"] = None
        self.assertFalse(validator.is_valid(response))
        response["comparison_code"] = None
        validator.validate(response)


if __name__ == "__main__":
    unittest.main()
