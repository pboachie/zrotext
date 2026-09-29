"""Check the PROPOSED sealed execution grant vectors (#539) against their schema,
the synthetic envelope they bind, and an independent reference of the refusal table.
The Android JVM suite consumes the same file (SealedExecutionGrantVectorTest)."""

import base64
import hashlib
import json
from pathlib import Path
import unittest
import uuid

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
MAX_FUTURE_MS = 35_000


def b64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def envelope_named(source, name):
    cases = json.loads((REPO / "android/app/src/sharedTest/resources" / source["file"]).read_text())["cases"]
    normal = bytes.fromhex(cases[source["case"]])
    return normal[:-1] if name == "truncated" else bytes.fromhex(cases[name]) if name else normal


def routing_claims(envelope):
    """Mirror only the bounds needed here; the Android parser is the full implementation."""
    if not 557 <= len(envelope) <= 34_213 or envelope[:8] != bytes([0x5A, 0x54, 0x53, 0x45, 2, 1, 0, 0]):
        return None
    length = int.from_bytes(envelope[8:10], "big")
    end = 10 + length
    body_len = int.from_bytes(envelope[end + 12:end + 16], "big")
    body_end = end + 16 + body_len
    count = envelope[body_end]
    if body_end + 1 + count * 146 + 64 != len(envelope):
        return None
    wraps = [envelope[body_end + 1 + i * 146:body_end + 1 + (i + 1) * 146] for i in range(count)]
    device = [w[1:33] for w in wraps if w[0] == 1]
    p = envelope[10:end]
    return {"account": str(uuid.UUID(bytes=p[0:16])), "message": str(uuid.UUID(bytes=p[16:32])),
            "device": str(uuid.UUID(bytes=p[32:48])), "line": str(uuid.UUID(bytes=p[48:64])),
            "reader": device[0]}


def reference_verdict(frame, context, envelope):
    """Independent restatement of SealedExecutionGrantValidator's order of fences."""
    claims = routing_claims(envelope)
    if claims is None:
        return "envelope_malformed"
    if frame["account_id"] != context["authenticatedAccountId"] or claims["account"] != frame["account_id"]:
        return "account_mismatch"
    if frame["device_id"] != context["authenticatedDeviceId"] or claims["device"] != frame["device_id"]:
        return "device_mismatch"
    if frame["line_id"] != context["activeLineId"] or claims["line"] != frame["line_id"]:
        return "line_mismatch"
    zero = "00000000-0000-0000-0000-000000000000"
    if zero in (frame["message_id"], frame["attempt_id"]):
        return "message_or_attempt_mismatch"
    if claims["message"] != frame["message_id"]:
        return "message_mismatch"
    if frame["reader_role"] != 1:
        return "reader_role_mismatch"
    reader = b64(frame["reader_key_id"])
    if reader != b64(context["pinnedReaderKeyId"]) or claims["reader"] != reader:
        return "reader_key_mismatch"
    if frame["connection_epoch"] != context["connectionEpoch"]:
        return "session_mismatch"
    if frame["deployment_epoch"] != context["deploymentEpoch"]:
        return "deployment_mismatch"
    if frame["binding_generation"] != context["activeBindingGeneration"]:
        return "binding_generation_mismatch"
    if b64(frame["envelope_sha256"]) != hashlib.sha256(envelope).digest():
        return "envelope_digest_mismatch"
    now = context["trustedNowMs"]
    if now >= frame["expires_at_ms"]:
        return "expired"
    if frame["expires_at_ms"] - now > MAX_FUTURE_MS:
        return "implausible_expiry"
    if not 1 <= frame["segment_count"] <= 6:
        return "segment_count_out_of_range"
    return None


class SealedExecutionGrantVectorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((ROOT / "vectors/sealed-execution-grant-01.json").read_text())
        cls.schema = json.loads((ROOT / "vectors/sealed-execution-grant.schema.json").read_text())
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def case_inputs(self, case):
        frame = {**self.vectors["frame"], **case.get("framePatch", {})}
        for key in case.get("frameRemove", []):
            del frame[key]
        context = {**self.vectors["context"], **case.get("contextPatch", {})}
        return frame, context, envelope_named(self.vectors["envelopeSource"], case.get("envelope"))

    def test_proposed_status_and_base_frame_binds_the_synthetic_envelope(self):
        self.assertTrue(self.vectors["status"].startswith("PROPOSED"))
        frame = self.vectors["frame"]
        envelope = envelope_named(self.vectors["envelopeSource"], None)
        self.assertEqual(b64(frame["envelope_sha256"]), hashlib.sha256(envelope).digest())
        self.assertEqual(b64(frame["unsigned_sha256"]), hashlib.sha256(envelope[:-64]).digest())
        fixture = json.loads((REPO / "android/app/src/sharedTest/resources/candidate02-preparation.json").read_text())
        self.assertEqual(b64(frame["reader_key_id"]), bytes.fromhex(fixture["deviceKeyId"]))

    def test_every_case_matches_schema_and_reference_verdict(self):
        names = [case["name"] for case in self.vectors["cases"]]
        self.assertEqual(len(names), len(set(names)))
        for case in self.vectors["cases"]:
            with self.subTest(case=case["name"]):
                frame, context, envelope = self.case_inputs(case)
                if case["verdict"] == "malformed":
                    self.assertFalse(self.validator.is_valid(frame))
                    continue
                self.assertTrue(self.validator.is_valid(frame))
                expected = None if case["verdict"] == "accept" else case["reason"]
                self.assertEqual(reference_verdict(frame, context, envelope), expected)

    def test_every_binding_field_has_a_refusal_vector(self):
        reasons = {case.get("reason") for case in self.vectors["cases"] if case["verdict"] == "refuse"}
        enum = set(self.schema["$defs"]["sealed_execution_refusal"]["properties"]["reason"]["enum"])
        # The one executor-only refusal needs a decrypted segment count; the Android suite covers it.
        self.assertEqual(reasons, enum - {"segment_count_exceeds_grant"})
        for binding in ("account_mismatch", "device_mismatch", "line_mismatch", "message_mismatch",
                        "reader_role_mismatch", "reader_key_mismatch"):
            self.assertIn(binding, reasons)

    def test_refusal_report_carries_no_content_or_digest(self):
        for frame in self.vectors["refusalFrames"]:
            self.assertTrue(self.validator.is_valid(frame))
            for leaked in ("envelope_sha256", "reader_key_id", "body", "message_id", "recipient_e164"):
                self.assertFalse(self.validator.is_valid({**frame, leaked: "AQ"}))

    def test_grant_never_carries_content_or_recipient(self):
        frame = self.vectors["frame"]
        for leaked in ("body", "recipient_e164", "envelope", "plaintext", "cek"):
            self.assertFalse(self.validator.is_valid({**frame, leaked: "AQ"}))


if __name__ == "__main__":
    unittest.main()
