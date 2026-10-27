# SPDX-License-Identifier: AGPL-3.0-only
"""Public DTO shape controls only, never auth, crypto or accepted custody."""
import base64
import copy
import json
from pathlib import Path
import unittest

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "profile03-manifest-transport.schema.json").read_text())
VECTOR = json.loads((ROOT / "vectors/sealed-profile03-manifest-install-01.json").read_text())


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def binary(name, row):
    return encoded(bytes.fromhex(row[name]))


def validator(name):
    return jsonschema.Draft202012Validator(
        {"$ref": "#/$defs/" + name, "$defs": SCHEMA["$defs"]}
    )


class ManifestTransportTests(unittest.TestCase):
    def test_closed_receipt_consumes_exact_public_vector_without_authority_claim(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        row = VECTOR["successors"][0]
        prior = VECTOR["first03"]
        receipt = {
            "v": 1, "opening_id": row["opening_id"], "line_id": VECTOR["line_id"],
            "binding_id": VECTOR["binding_id"],
            "election_digest": binary("election_commitment_hex", VECTOR),
            "statement": binary("statement_hex", row),
            "signature": binary("signature_hex", row),
            "successor_manifest03": binary("successor_signed_hex", row),
            "accepted_ms": row["accepted_ms"], "predecessor_version": "2",
            "predecessor_digest": binary("semantic_sha256", prior),
            "successor_version": "3",
            "successor_digest": binary("successor_semantic_sha256", row),
            "operation": "enroll",
            "predecessor_ancestry_sha256": binary("predecessor_ancestry_sha256_hex", row),
            "ancestry_sha256": binary("ancestry_sha256_hex", row),
        }
        check = validator("receipt")
        check.validate(receipt)
        for field, value in [("fresh_mfa", True), ("password", "synthetic"), ("permission", True)]:
            changed = copy.deepcopy(receipt)
            changed[field] = value
            self.assertFalse(check.is_valid(changed))
        changed = copy.deepcopy(receipt)
        changed["operation"] = "reactivate"
        self.assertFalse(check.is_valid(changed))
        changed["operation"] = "enroll"
        changed["signature"] += "="
        self.assertFalse(check.is_valid(changed))

    def test_history_requires_entire_tip_triple_and_rejects_partial_snapshot(self):
        digest = encoded(bytes([1]) * 32)
        request = {"v": 1, "line_id": VECTOR["line_id"], "after_version": "2",
                   "after_digest": digest, "after_ancestry_sha256": digest,
                   "tip_version": None, "tip_digest": None, "tip_ancestry_sha256": None}
        check = validator("history_request")
        check.validate(request)
        for field in ["tip_version", "tip_digest", "tip_ancestry_sha256"]:
            missing = copy.deepcopy(request)
            del missing[field]
            self.assertFalse(check.is_valid(missing))
            mixed = copy.deepcopy(request)
            mixed[field] = "3" if field == "tip_version" else digest
            self.assertFalse(check.is_valid(mixed))
        request.update(tip_version="3", tip_digest=digest, tip_ancestry_sha256=digest)
        check.validate(request)
        self.assertFalse(check.is_valid([request]))
        request["after_version"] = "02"
        self.assertFalse(check.is_valid(request))

    def test_original_bootstrap_requires_binding_and_has_no_current_permission(self):
        # Shape-only synthetic strings deliberately confer no signature proof.
        evidence = {name: "1" if "pattern" in rule and rule["pattern"].startswith("^[1-9]")
                    else "A" * rule["minLength"]
                    for name, rule in SCHEMA["$defs"]["evidence"]["properties"].items()}
        owner = {"v": 1, "kind": "manifest_original03", "line_id": VECTOR["line_id"],
                 "binding_id": VECTOR["binding_id"], "evidence": evidence}
        check = validator("owner_original")
        check.validate(owner)
        for field in ["binding_id", "evidence"]:
            changed = copy.deepcopy(owner)
            del changed[field]
            self.assertFalse(check.is_valid(changed))
        for field in ["permission_expires_ms", "physical_selection", "manifest_version"]:
            changed = copy.deepcopy(owner)
            changed[field] = "3"
            self.assertFalse(check.is_valid(changed))
        device = dict(owner)
        del device["kind"]
        device.update(type="payload_profile_manifest_original03", connection_epoch=1,
                      challenge=VECTOR["election_challenge_id"])
        validator("device_original").validate(device)
        device["evidence"]["current_manifest03"] = "AA"
        self.assertFalse(validator("device_original").is_valid(device))

    def test_readback_is_exact_tip_and_different_from_current_or_effect_permission(self):
        digest = encoded(bytes([1]) * 32)
        frame = {"v": 1, "type": "payload_profile_manifest03_installed",
                 "connection_epoch": 1, "challenge": VECTOR["opening_id"] if "opening_id" in VECTOR else VECTOR["election_challenge_id"],
                 "line_id": VECTOR["line_id"], "tip_version": "3", "tip_digest": digest,
                 "tip_ancestry_sha256": digest, "election_digest": digest}
        check = validator("device_installed")
        check.validate(frame)
        for field in ["tip_ancestry_sha256", "challenge"]:
            missing = copy.deepcopy(frame)
            del missing[field]
            self.assertFalse(check.is_valid(missing))
        frame["permission_expires_ms"] = "3"
        self.assertFalse(check.is_valid(frame))
        del frame["permission_expires_ms"]
        frame["type"] = "payload_profile_current03_request"
        self.assertFalse(check.is_valid(frame))


if __name__ == "__main__":
    unittest.main()
