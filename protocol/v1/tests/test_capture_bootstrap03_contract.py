# SPDX-License-Identifier: AGPL-3.0-only
"""Closed syntax/hash checks only; Kotlin verifies the actual two P256 signatures.

No shape, public vector or hash is original-history/current-actor/hardware/allocator evidence.
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
SCHEMA = json.loads((ROOT / "profile03-capture-bootstrap.schema.json").read_text())
VECTOR = json.loads((ROOT / "vectors/sealed-capture-bootstrap03-01.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA)
raw = lambda name: bytes.fromhex(VECTOR[name])
b64 = lambda data: base64.urlsafe_b64encode(data).decode().rstrip("=")
sha = lambda data: hashlib.sha256(data).digest()


class CaptureBootstrapContract(unittest.TestCase):
    def frames(self):
        bid, oid, request, attempt = (VECTOR[k + "_id"] for k in ("bootstrap", "opening", "proof_request", "attempt"))
        base = {"v": 1, "connection_epoch": 7}
        make = lambda kind, **kw: dict(base, type=kind, **kw)
        digest = b64(raw("core_sha256"))
        evidence = {name: "A" * spec.get("minLength", 43) if spec.get("type") == "string" else None
                    for name, spec in SCHEMA["$defs"]["evidence"]["properties"].items()}
        evidence["prior_accepted_ms"] = "11"; evidence["accepted_ms"] = "12"
        opening = dict(bootstrap_id=bid, opening_id=oid, nonce=b64(raw("bootstrap_nonce")), line_id=VECTOR["line_id"],
                       binding_id=VECTOR["binding_id"], evidence=evidence, created_ms="13")
        record = dict(proof_request_id=request, attempt_id=attempt, attempt_nonce=b64(raw("attempt_nonce")),
                      association_sha256=b64(raw("association_sha256")), core=b64(raw("core521")), created_ms="14")
        receipt = dict(receipt_id=str(uuid.UUID(int=20)), bootstrap_id=bid, opening_id=oid,
                       proof_request_id=request, attempt_id=attempt, association_sha256=b64(raw("association_sha256")),
                       core_sha256=digest, bundle_sha256=b64(raw("bundle_sha256")), device_id=VECTOR["device_id"],
                       enrolled_signing_key_id=b64(sha(b"ZTSE/key/v1\0\1\1" + raw("enrolled_point"))),
                       canary_signing_key_id=b64(sha(b"ZTSE/key/v1\0\1\1" + raw("canary_point"))), accepted_ms="15")
        status_request = str(uuid.UUID(int=21))
        return {
            "open": make("conversation_capture_bootstrap_open03", bootstrap_id=bid, nonce=b64(raw("bootstrap_nonce")), line_id=VECTOR["line_id"]),
            "opened": make("conversation_capture_bootstrap_opened03", bootstrap_id=bid, opening=opening),
            "attempt_request": make("conversation_capture_bootstrap_attempt03_request", bootstrap_id=bid, opening_id=oid, proof_request_id=request, association=b64(raw("association473")), predecessor=None),
            "attempt": make("conversation_capture_bootstrap_attempt03", bootstrap_id=bid, opening_id=oid, proof_request_id=request, attempt=record, closed_predecessor=None, receipt=None),
            "submit": make("conversation_capture_bootstrap03", bootstrap_id=bid, opening_id=oid, proof_request_id=request, attempt_id=attempt, attempt_nonce=b64(raw("attempt_nonce")), bundle=b64(raw("bundle649"))),
            "ack": make("conversation_capture_bootstrap_ack03", receipt=receipt),
            "opening_status_request": make("conversation_capture_bootstrap_status03_request", status_request_id=status_request, bootstrap_id=bid, nonce=b64(raw("bootstrap_nonce"))),
            "opening_status": make("conversation_capture_bootstrap_status03", status_request_id=status_request, bootstrap_id=bid, status="accepted", opening=opening, receipt=receipt),
            "attempt_status_request": make("conversation_capture_bootstrap_attempt_status03_request", status_request_id=status_request, bootstrap_id=bid, opening_id=oid, proof_request_id=request),
            "attempt_status": make("conversation_capture_bootstrap_attempt_status03", status_request_id=status_request, bootstrap_id=bid, opening_id=oid, proof_request_id=request, status="accepted", attempt=record, closed_predecessor=None, receipt=receipt),
        }

    def valid(self, value):
        self.assertEqual([], list(VALIDATOR.iter_errors(value)))

    def denied(self, value):
        self.assertTrue(list(VALIDATOR.iter_errors(value)))

    def test_exact_independent_bytes_commit_both_nonces_and_distinct_known_keys(self):
        association, core, bundle = (raw(k) for k in ("association473", "core521", "bundle649"))
        self.assertEqual((473, 521, 649), tuple(map(len, (association, core, bundle))))
        self.assertEqual(b"ZTCB\x01\x03\x03\x00", core[:8])
        self.assertEqual(association, core[:72] + core[88:424] + core[456:])
        self.assertEqual(core, bundle[:521])
        self.assertEqual(uuid.UUID(VECTOR["attempt_id"]).bytes, core[72:88])
        self.assertEqual((1, 3, 1, 1), struct.unpack(">QQQQ", core[168:200]))
        self.assertEqual(sha(raw("bootstrap_nonce")), association[184:216])
        self.assertEqual(sha(raw("attempt_nonce")), core[424:456])
        for name, value in (("association", association), ("core", core), ("bundle", bundle)):
            self.assertEqual(sha(value), raw(name + "_sha256"))
        points = [raw(name + "_point") for name in ("root", "enrolled", "approval", "role04", "role05", "canary")]
        self.assertEqual(6, len(set(points)))
        self.assertEqual(sha(b"ZTSE/key/v1\0\1\1" + points[1]), core[232:264])
        self.assertEqual(sha(b"ZTSE/key/v1\0\1\1" + points[-1]), core[264:296])
        self.assertEqual(points[-1], core[456:])
        for domain, payload, name in ((b"device-attempt", core, "device"), (b"canary-attempt", core + sha(bundle[521:585]), "canary")):
            framed = b"ZTSE/conversation/capture-bootstrap/" + domain + b"/v1\0" + struct.pack(">I", len(payload)) + payload
            self.assertEqual(framed, raw(name + "_transcript"))
        self.assertNotIn("private", VECTOR)

    def test_all_ten_closed_frames_and_nested_extra_fields(self):
        frames = self.frames()
        self.assertEqual(10, len(frames))
        Draft202012Validator.check_schema(SCHEMA)
        for frame in frames.values():
            self.valid(frame)
            self.denied(dict(frame, reset_counter=True))
            for key, value in frame.items():
                if isinstance(value, dict):
                    wrong = copy.deepcopy(frame); wrong[key]["connection_epoch"] = 99
                    self.denied(wrong)

    def test_socket_integer_and_historical_decimal_values_stay_distinct(self):
        frame = self.frames()["ack"]
        self.valid(dict(frame, connection_epoch=9223372036854775807))
        for bad in (0, -1, True, "7", 9223372036854775808):
            self.denied(dict(frame, connection_epoch=bad))
        for bad in (15, "0", "015", "+15", "1e3"):
            wrong = copy.deepcopy(frame); wrong["receipt"]["accepted_ms"] = bad
            self.denied(wrong)

    def test_canonical_binary_lengths_reject_padding_and_old_601_packet(self):
        frame = self.frames()["submit"]
        for field in ("attempt_nonce", "bundle"):
            self.denied(dict(frame, **{field: frame[field] + "="}))
            self.denied(dict(frame, **{field: frame[field][:-1]}))
        self.denied(dict(frame, bundle=b64(raw("association473") + raw("device_signature") + raw("canary_signature"))))
        # The final unused base64 bits must be zero, not merely accepted alphabet/length.
        self.denied(dict(frame, bundle=frame["bundle"][:-1] + "B"))

    def test_nullable_lost_result_is_not_a_fabricated_bundle_or_acceptance(self):
        f = self.frames(); request = f["attempt_request"]
        predecessor = dict(attempt_id=VECTOR["attempt_id"], core_sha256=b64(raw("core_sha256")), bundle_sha256=None)
        self.valid(dict(request, predecessor=predecessor))
        self.valid(dict(request, predecessor=dict(predecessor, bundle_sha256=b64(raw("bundle_sha256")))))
        self.denied(dict(request, predecessor={k: v for k, v in predecessor.items() if k != "bundle_sha256"}))
        self.denied(dict(request, predecessor=dict(predecessor, accepted=True)))
        empty = dict(f["attempt_status"], status="not_found", attempt=None, closed_predecessor=None, receipt=None)
        self.valid(empty)
        self.denied(dict(empty, status="accepted"))
        self.denied(dict(empty, status="opened"))
        # Opening may have accepted a DIFFERENT successor. Syntax never equates that receipt
        # with a missing queried command; actual source must compare exact immutable IDs/hashes.
        self.valid(dict(empty, receipt=f["ack"]["receipt"]))

    def test_reconnect_changes_only_outer_epoch_not_the_original_opening(self):
        frame = self.frames()["opening_status"]
        original = copy.deepcopy(frame["opening"])
        reconnected = dict(frame, connection_epoch=8)
        self.valid(reconnected); self.assertEqual(original, reconnected["opening"])
        wrong = copy.deepcopy(reconnected); wrong["opening"]["connection_epoch"] = 7
        self.denied(wrong)
        not_found = dict(frame, status="not_found", opening=None, receipt=None)
        self.valid(not_found)
        self.denied(dict(not_found, receipt=frame["receipt"]))
        self.denied(dict(frame, status="opened"))

    def test_real_encoded_component_fixtures_fit_the_distinct_limits(self):
        for name, frame in self.frames().items():
            limit = 192 * 1024 if name in ("opened", "opening_status") else 4096
            self.assertLessEqual(len(json.dumps(frame, separators=(",", ":")).encode()), limit)
        self.assertFalse(any(k in SCHEMA["$defs"] for k in ("counter", "reset", "body_digest", "bundle601")))


if __name__ == "__main__":
    unittest.main()
