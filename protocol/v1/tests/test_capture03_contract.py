# SPDX-License-Identifier: AGPL-3.0-only
"""Closed transport/byte/hash controls only, not server or hardware permission.

Actual signatures and selected role authorities run in Kotlin/Rust consumers.
The independent producer verifies HPKE recipient round trips before discarding keys.
"""
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
SCHEMA = json.loads((ROOT / "profile03-capture.schema.json").read_text())
VECTOR = json.loads((ROOT / "vectors/sealed-profile03-capture-01.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
raw = lambda v, k: bytes.fromhex(v[k])
sha = lambda b: hashlib.sha256(b).digest()
identity = lambda b: str(uuid.UUID(bytes=b))


def packets(name="minimum"):
    """Synthetic source-shaped JSON, explicitly not an authenticated projection."""
    v, c = VECTOR, VECTOR[name]
    intent = raw(c, "intent")
    ids = [identity(intent[8 + 16*i:24 + 16*i]) for i in range(13)]
    digests = [intent[328 + 32*i:360 + 32*i] for i in range(18)]
    core = raw(v, "core500")
    evidence = {"root_pin": b64(raw(v, "root_pin")), "prior_manifest02": b64(raw(v, "manifest02")),
        "prior_accepted_ms": v["prior_accepted_ms"], "accepted_manifest03": b64(raw(v, "manifest03")),
        "accepted_ms": v["election_accepted_ms"], "bundle": b64(raw(v, "bundle628")),
        "device_signing_point": b64(raw(v, "device_enrollment_point")), "owner_approval_point": b64(raw(v, "original_approval_point")),
        "registration_evidence": b64(raw(v, "registration_evidence")), "activation_evidence": b64(raw(v, "activation_evidence"))}
    current = {"v": 1, "kind": "capture_permission03", "request_kind": "capture", "request_id": ids[2], "capture_id": ids[1], "interval_id": ids[3],
        "observed_ms": c["observed_ms"], "observed_upper_ms": c["observed_upper_ms"], "envelope_profile": 3, "manifest_profile": 3,
        "account_id": ids[0], "user_id": ids[7], "owner_session_id": ids[8], "device_id": ids[5], "line_id": ids[6], "selection_epoch": "1",
        "origin_digest": b64(digests[8]), "owner_session_digest": b64(digests[9]), "device_session_digest": b64(digests[10]),
        "site_id": v["site_id"], "instance_id": v["instance_id"], "connection_epoch": "1", "deployment_epoch": "1",
        "old_binding_id": ids[11], "old_binding_generation": "1", "old_binding_proof_digest": b64(core[104:136]), "binding_id": ids[9], "binding_generation": "2",
        "reader_key_id": b64(digests[0]), "archive_reader_key_id": b64(digests[1]), "phone_signer_key_id": b64(digests[2]),
        "device_signing_key_id": b64(core[288:320]), "approval_key_id": b64(core[320:352]), "root_fingerprint": b64(digests[3]), "trust_generation": "1",
        "manifest_version": "2", "manifest_digest": b64(digests[4]), "election_digest": b64(digests[6]), "election_bundle_sha256": b64(digests[7]),
        "compared_ms": c["compared_ms"], "permission_expires_ms": c["permission_expires_ms"], "evidence": evidence,
        "current_manifest03": b64(raw(v, "manifest03")), "manifest_ancestry_sha256": b64(digests[5]), "physical_selection": {"kind": "original_v2"}}
    original = c["interval"]
    statement = raw(original, "statement")
    at = 632 + 1 + statement[632] + 32
    at += 1 + statement[at]
    count = statement[at]
    mappings = []
    for i in range(count):
        mapping = statement[at + 1 + i*64:at + 1 + (i+1)*64]
        mappings.append({"connector_id": identity(mapping[:16]), "read_grant_id": identity(mapping[16:32]), "key_id": b64(mapping[32:]),
            "key_point": b64(bytes.fromhex(v["integration_points"][i])), "manifest_generation": "1", "read_directions": 12,
            "registration_expires_ms": "900000", "grant_expires_ms": "900000", "key_valid_from_ms": "1", "key_valid_until_ms": "900000"})
    permission = {"v": 1, "kind": "interval_permission03", "request_kind": "capture", "request_id": ids[2], "interval_id": ids[3],
        "statement_sha256": b64(sha(statement)), "statement": b64(statement),
        **{key: b64(raw(original, key)) for key in ["owner_signature", "phone_signature", "installed_signature"]},
        **{key: original[key] for key in ["requested_ms", "approved_ms", "installed_ms"]}, "phase": "active",
        "device_session_digest": b64(digests[10]), "physical_selection_digest": b64(digests[11]), "owner_session_digest": b64(digests[9]),
        "compared_ms": c["compared_ms"], "permission_expires_ms": c["permission_expires_ms"], "readers": mappings}
    request = {"v": 1, "type": "conversation_capture_permission03_request", "connection_epoch": 1, "request_id": ids[2], "capture_id": ids[1],
        "interval_id": ids[3], "statement_sha256": b64(digests[12]), "observed_ms": c["observed_ms"], "observed_upper_ms": c["observed_upper_ms"]}
    reply = {"v": 1, "type": "conversation_capture_permission03", "connection_epoch": 1, "request_id": ids[2], "capture_id": ids[1], "interval_id": ids[3],
        "current": current, "interval_permission": permission}
    upload = {"v": 1, "type": "conversation_capture03", "connection_epoch": 1, "request_id": ids[2], "capture_id": ids[1], "interval_id": ids[3],
        "device_sequence": c["sequence"], "envelope": b64(raw(c, "envelope")), "intent": b64(intent), "signature": b64(raw(c, "intent_signature"))}
    receipt = {"receipt_id": str(uuid.UUID(int=900)), "request_id": ids[2], "capture_id": ids[1], "interval_id": ids[3], "device_sequence": c["sequence"],
        "envelope_sha256": b64(digests[16]), "intent_sha256": b64(sha(intent)), "signature_sha256": b64(sha(raw(c, "intent_signature"))),
        "device_session_digest": b64(digests[10]), "accepted_ms": "11250"}
    status_id = str(uuid.UUID(int=901))
    status_request = {"v": 1, "type": "conversation_capture_status03_request", "connection_epoch": 2, "status_request_id": status_id, "capture_id": ids[1],
        **{key: receipt[key] for key in ["envelope_sha256", "intent_sha256", "signature_sha256"]}}
    status = {"v": 1, "type": "conversation_capture_status03", "connection_epoch": 2, "status_request_id": status_id, "capture_id": ids[1], "status": "accepted", "receipt": receipt}
    return [request, reply, upload, {"v": 1, "type": "conversation_capture03_ack", "connection_epoch": 1, "receipt": receipt}, status_request, status]


class Capture03ContractTest(unittest.TestCase):
    def test_schema_and_both_exact_extrema_frames_are_closed_and_bounded(self):
        Draft202012Validator.check_schema(SCHEMA)
        for name in ["minimum", "maximum"]:
            frames = packets(name)
            for frame, bound in zip(frames, [4096, 192*1024, 48000, 192*1024, 4096, 192*1024]):
                VALIDATOR.validate(frame)
                self.assertLessEqual(len(json.dumps(frame, separators=(",", ":")).encode()), bound)
                changed = {**frame, "unexpected": 1}
                self.assertFalse(VALIDATOR.is_valid(changed))

    def test_intent_offsets_lengths_hashes_and_domains_match_independent_bytes(self):
        for name, length, envelope_size in [("minimum", 942, 426), ("maximum", 1153, 34082)]:
            c = VECTOR[name]; intent = raw(c, "intent"); envelope = raw(c, "envelope")
            self.assertEqual(intent[:8], b"ZTCI\x01\x03\x03\x02")
            self.assertEqual(len(intent), length); self.assertEqual(len(envelope), envelope_size)
            self.assertEqual(len(intent[8:216]), 13*16); self.assertEqual(len(intent[216:328]), 14*8)
            self.assertEqual(len(intent[328:904]), 18*32)
            self.assertEqual(intent[8+16:8+32], uuid.UUID(c["capture_id"]).bytes)
            self.assertEqual(struct.unpack(">14Q", intent[216:328])[3], 1)
            self.assertEqual(intent[328+16*32:328+17*32], sha(envelope))
            self.assertEqual(intent[328+17*32:904], sha(envelope[:-64]))
            self.assertEqual(raw(c, "intent_transcript"), b"ZTSE/conversation/capture-intent03/v1\0" + struct.pack(">I", length) + intent)
            self.assertEqual(raw(c, "intent_sha256"), sha(intent))
            self.assertNotEqual(raw(c, "intent_signature"), raw(c, "envelope_signature"))
            self.assertEqual(envelope[-64:], raw(c, "envelope_signature"))

    def test_capture_current_keeps_strict_new_kind_and_nonnull_original_proofs(self):
        frame = packets()[1]
        for change in [lambda x: x["current"].update(kind="message_manifest_permission03"), lambda x: x["current"].pop("observed_upper_ms"),
            lambda x: x["interval_permission"].update(request_kind="fetch"), lambda x: x["interval_permission"].update(phone_signature=None),
            lambda x: x["interval_permission"].update(phase="requested"), lambda x: x["current"].update(connection_epoch=1)]:
            invalid = copy.deepcopy(frame); change(invalid); self.assertFalse(VALIDATOR.is_valid(invalid))
        self.assertNotIn("body_digest", json.dumps(SCHEMA))
        self.assertNotIn("body_digest", json.dumps(VECTOR))

    def test_socket_epoch_and_projection_time_types_are_deliberately_distinct(self):
        for frame in packets():
            changed = copy.deepcopy(frame); changed["connection_epoch"] = "1"; self.assertFalse(VALIDATOR.is_valid(changed))
            changed["connection_epoch"] = 0; self.assertFalse(VALIDATOR.is_valid(changed))
        upload = packets()[2]; upload["device_sequence"] = 1; self.assertFalse(VALIDATOR.is_valid(upload))
        request = packets()[0]; request["observed_upper_ms"] = "01"; self.assertFalse(VALIDATOR.is_valid(request))

    def test_socket_identity_text_rejects_controls_without_restricting_public_text(self):
        frame = packets()[1]
        for field in ["site_id", "instance_id"]:
            for value in ["", "x" * 257, "synthetic\x00site", "synthetic\x1fsite", "synthetic\x7fsite"]:
                changed = copy.deepcopy(frame); changed["current"][field] = value
                self.assertFalse(VALIDATOR.is_valid(changed))
            for value in ["synthetic-site", "synthetic instance", "synthetic-\u00e9"]:
                changed = copy.deepcopy(frame); changed["current"][field] = value
                VALIDATOR.validate(changed)

    def test_passive_status_has_exact_conditional_receipt_without_new_permission(self):
        frame = packets()[-1]
        VALIDATOR.validate(frame)
        not_found = {**frame, "status": "not_found", "receipt": None}; VALIDATOR.validate(not_found)
        self.assertFalse(VALIDATOR.is_valid({**frame, "receipt": None}))
        self.assertFalse(VALIDATOR.is_valid({**not_found, "receipt": frame["receipt"]}))
        self.assertFalse(VALIDATOR.is_valid({**frame, "current": packets()[1]["current"]}))


if __name__ == "__main__":
    unittest.main()
