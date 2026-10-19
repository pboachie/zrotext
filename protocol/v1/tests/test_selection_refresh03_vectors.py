# SPDX-License-Identifier: AGPL-3.0-only
"""Independent stdlib P-256 verification and closed-schema controls; no private keys.

Public proof parity is not OS truth, hardware custody, owner authentication or acceptance.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "vectors/sealed-profile03-selection-refresh-01.json").read_text())
SCHEMA = json.loads((ROOT / "profile03-selection-refresh.schema.json").read_text())
P = int("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
B = int("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
G = (int("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
     int("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16))


def raw(name):
    return bytes.fromhex(V[name])


def sha(value):
    return hashlib.sha256(value).digest()


def frame(domain, value):
    return domain.encode("ascii") + b"\0" + struct.pack(">I", len(value)) + value


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x - 3) * pow(2 * y, -1, P) if left == right
             else (v - y) * pow(u - x, -1, P)) % P
    result = (slope * slope - x - u) % P
    return result, (slope * (x - result) - y) % P


def multiply(n, point):
    result = None
    while n:
        if n & 1:
            result = add(result, point)
        point = add(point, point)
        n >>= 1
    return result


def verifies(point, signature, transcript):
    if len(point) != 65 or point[0] != 4 or len(signature) != 64:
        return False
    x, y = int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big")
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not (0 <= x < P and 0 <= y < P and (y * y - x**3 + 3 * x - B) % P == 0 and 0 < r < N and 0 < s <= N // 2):
        return False
    inverse = pow(s, -1, N)
    candidate = add(multiply(int.from_bytes(sha(transcript), "big") * inverse % N, G), multiply(r * inverse % N, (x, y)))
    return candidate is not None and candidate[0] % N == r


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class SelectionRefreshVectorTest(unittest.TestCase):
    def test_fixed_core_offsets_domains_and_exact_bundle(self):
        core, observation = raw("core"), raw("observation")
        self.assertEqual(496, len(core))
        self.assertEqual(b"ZTSR\x01\x03\x03\0", core[:8])
        self.assertEqual(bytes(8), core[488:])
        self.assertEqual((2, 1, 2, 7), struct.unpack(">QQQQ", core[88:120]))
        self.assertTrue(all(any(core[i:i+32]) for i in range(120, 472, 32)))
        self.assertEqual((100000, 220000), struct.unpack(">QQ", core[472:488]))
        self.assertEqual(sha(V["origin"].encode()), core[408:440])
        self.assertEqual(sha(b"ZTSE/key/v1\0\x01\x01" + raw("device_signing_point")), core[216:248])
        self.assertEqual(sha(b"ZTSE/key/v1\0\x01\x01" + raw("owner_approval_point")), core[248:280])
        self.assertEqual(121, len(observation))
        self.assertEqual((34, 1, 8, 2), struct.unpack(">HHiB", observation[:9]))
        self.assertEqual(sha(raw("complete_set_preimage")), observation[-32:])
        self.assertEqual(frame("ZTSE/line/payload-profile/selection-refresh/device/v1", core + observation), raw("device_transcript"))
        self.assertEqual(frame("ZTSE/line/payload-profile/selection-refresh/owner/v1", core + observation + sha(raw("device_signature"))), raw("owner_transcript"))
        self.assertEqual(core + observation + raw("device_signature") + raw("owner_signature"), raw("bundle"))
        self.assertEqual(745, len(raw("bundle")))
        self.assertEqual(sha(raw("bundle")), raw("bundle_sha256"))
        self.assertEqual(frame("ZTSE/line/payload-profile/selection-refresh/installed/v1", core[56:72] + sha(raw("bundle")) + core[344:376]), raw("installed_transcript"))

    def test_three_real_signatures_verify_independently_without_private_material(self):
        for point, signature, body in (("device_signing_point", "device_signature", "device_transcript"),
                                       ("owner_approval_point", "owner_signature", "owner_transcript"),
                                       ("device_signing_point", "installed_signature", "installed_transcript")):
            self.assertTrue(verifies(raw(point), raw(signature), raw(body)))
            changed = bytearray(raw(body)); changed[-1] ^= 1
            self.assertFalse(verifies(raw(point), raw(signature), changed))

    def test_high_s_cross_operation_and_wrong_owner_signatures_refuse(self):
        device = raw("device_signature")
        high = device[:32] + (N - int.from_bytes(device[32:], "big")).to_bytes(32, "big")
        self.assertFalse(verifies(raw("device_signing_point"), high, raw("device_transcript")))
        self.assertFalse(verifies(raw("device_signing_point"), device, raw("owner_transcript")))
        self.assertFalse(verifies(raw("device_signing_point"), raw("owner_signature"), raw("owner_transcript")))
        self.assertFalse(verifies(raw("device_signing_point"), raw("installed_signature"), raw("device_transcript")))


class SelectionRefreshSchemaTest(unittest.TestCase):
    def setUp(self):
        Draft202012Validator.check_schema(SCHEMA)
        self.validator = Draft202012Validator(SCHEMA)
        self.refresh = "00000000-0000-0000-0000-000000000004"

    def frames(self):
        return [
            {"v": 1, "type": "payload_profile_selection_proof03", "connection_epoch": 7, "refresh_id": self.refresh,
             "observation": b64(raw("observation")), "device_signature": b64(raw("device_signature"))},
            {"v": 1, "type": "payload_profile_selection_approved03", "refresh_id": self.refresh, "bundle": b64(raw("bundle")), "accepted_ms": "100001"},
            {"v": 1, "type": "payload_profile_selection_installed03", "connection_epoch": 7, "refresh_id": self.refresh,
             "bundle_sha256": b64(raw("bundle_sha256")), "device_signature": b64(raw("installed_signature"))},
            {"v": 1, "type": "payload_profile_selection_install_ack03", "connection_epoch": 7, "refresh_id": self.refresh,
             "bundle_sha256": b64(raw("bundle_sha256")), "installed_ms": "100002"},
        ]

    def test_closed_frames_preserve_direction_widths_and_counter_types(self):
        for value in self.frames():
            self.validator.validate(value)
            self.assertFalse(self.validator.is_valid(value | {"approved": True}))
            for field in value:
                missing = copy.deepcopy(value); missing.pop(field)
                self.assertFalse(self.validator.is_valid(missing))
            if "connection_epoch" in value:
                self.assertFalse(self.validator.is_valid(value | {"connection_epoch": "7"}))
            for field in ("accepted_ms", "installed_ms"):
                if field in value:
                    self.assertFalse(self.validator.is_valid(value | {field: "0100001"}))

    def test_refresh_physical_selection_cannot_coerce_to_original_or_message_permission(self):
        validator = Draft202012Validator(SCHEMA["$defs"]["physical_selection"])
        original = {"kind": "original_v2"}
        refreshed = {"kind": "owner_refresh03", "refresh_id": self.refresh, "bundle": b64(raw("bundle")), "accepted_ms": "100001", "installed_ms": "100002"}
        validator.validate(original); validator.validate(refreshed)
        self.assertFalse(validator.is_valid(refreshed | {"kind": "original_v2"}))
        self.assertFalse(validator.is_valid(original | {"permission_expires_ms": "200000"}))
        for key in refreshed:
            missing = dict(refreshed); missing.pop(key)
            self.assertFalse(validator.is_valid(missing))

    def test_challenge_requires_all_original_evidence_before_physical_availability(self):
        # Width-only schema controls. These zero public placeholders are not verified proofs.
        evidence = {name: b64(bytes(width)) for name, width in (("root_pin", 94), ("prior_manifest02", 364),
                    ("accepted_manifest03", 366), ("bundle", 628), ("device_signing_point", 65),
                    ("owner_approval_point", 65), ("registration_evidence", 1), ("activation_evidence", 1))}
        evidence.update(prior_accepted_ms="99000", accepted_ms="99900")
        challenge = {"v": 1, "type": "payload_profile_selection_challenge03", "refresh_id": self.refresh,
                     "core": b64(raw("core")), "evidence": evidence}
        self.validator.validate(challenge)
        for name in evidence:
            missing = copy.deepcopy(challenge); missing["evidence"].pop(name)
            self.assertFalse(self.validator.is_valid(missing))
        self.assertFalse(self.validator.is_valid(challenge | {"physical_selection": {"kind": "original_v2"}}))
        self.assertFalse(self.validator.is_valid(challenge | {"core": b64(raw("core") + b"\0")}))


if __name__ == "__main__":
    unittest.main()
