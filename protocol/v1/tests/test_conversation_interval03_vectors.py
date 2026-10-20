# SPDX-License-Identifier: AGPL-3.0-only
"""Independent public proof/physical-byte verification; no current-server or hardware claim."""
import hashlib
import json
from pathlib import Path
import struct
import unittest
import uuid
import base64
import copy
import jsonschema

from test_selection_refresh03_vectors import verifies, add, multiply, P, N, G

ROOT = Path(__file__).resolve().parents[1]
V = json.loads((ROOT / "vectors/sealed-profile03-conversation-interval-01.json").read_text())
SCHEMA = json.loads((ROOT / "conversation-interval03.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def raw(name):
    return bytes.fromhex(V[name])


def sha(value):
    return hashlib.sha256(value).digest()


def frame(label, value):
    return label.encode() + b"\0" + struct.pack(">I", len(value)) + value


def unframe(label, value):
    prefix = label.encode() + b"\0"
    assert value.startswith(prefix)
    size = struct.unpack(">I", value[len(prefix):len(prefix) + 4])[0]
    result = value[len(prefix) + 4:]
    assert len(result) == size
    return result


def der_pair(value):
    assert 8 <= len(value) <= 72 and value[:1] == b"\x30" and value[1] == len(value) - 2
    at = 2
    result = []
    for _ in range(2):
        assert value[at] == 2
        size = value[at + 1]
        integer = value[at + 2:at + 2 + size]
        assert 1 <= size <= 33 and len(integer) == size and integer[0] < 128
        assert size == 1 or integer[0] != 0 or integer[1] >= 128
        number = int.from_bytes(integer, "big")
        assert 0 < number < N
        result.append(number)
        at += 2 + size
    assert at == len(value)
    return result


def original_der_verifies(point, der, statement):
    # Original exact received DER/high-S is kept and used directly; no normalization.
    r, s = der_pair(der)
    x, y = int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:], "big")
    inverse = pow(s, -1, N)
    result = add(multiply(int.from_bytes(sha(statement), "big") * inverse % N, G), multiply(r * inverse % N, (x, y)))
    return result is not None and result[0] % N == r


class ConversationInterval03VectorTest(unittest.TestCase):
    def test_both_statements_exact_offsets_disclosure_peer_and_mapping(self):
        for name, size, count in (("without_integrations", 695, 0), ("with_integration", 759, 1)):
            b = bytes.fromhex(V[name]["statement"])
            self.assertEqual(size, len(b))
            self.assertEqual(b"ZTCA\x03\x03\x03\0", b[:8])
            self.assertTrue(all(any(b[i:i+16]) for i in range(8,152,16)))
            self.assertEqual((2,1,2,7,10000,100000,10000,200000), struct.unpack(">8Q", b[152:216]))
            self.assertTrue(all(any(b[i:i+32]) for i in range(216,632,32)))
            self.assertEqual(b"\x19conversation-content03-v1", b[632:658])
            self.assertEqual(sha(V["disclosure"].encode()), b[658:690])
            self.assertEqual(b"\x03+12", b[690:694])
            self.assertEqual(count, b[694])
            self.assertEqual(sha(b).hex(), V[name]["statement_sha256"])
            self.assertEqual(raw("device_session_digest"), b[536:568])
            self.assertEqual(raw("physical_digest"), b[568:600])
            if count:
                self.assertEqual(uuid.UUID(V["integration_connector_id"]).bytes, b[695:711])
                self.assertEqual(uuid.UUID(V["integration_read_grant_id"]).bytes, b[711:727])
                self.assertEqual(raw("integration_key_id"), b[727:759])

    def test_three_domains_and_six_actual_low_s_signatures_are_distinct(self):
        for name in ("without_integrations", "with_integration"):
            v = {k: bytes.fromhex(value) for k,value in V[name].items() if k.endswith("signature") or k.endswith("transcript") or k == "statement"}
            self.assertEqual(frame("zrotext/conversation/request03/v1", v["statement"]), v["request_transcript"])
            self.assertEqual(frame("zrotext/conversation/approve03/v1", v["statement"] + sha(v["owner_signature"])), v["approval_transcript"])
            self.assertEqual(frame("zrotext/conversation/install03/v1", v["statement"] + sha(v["owner_signature"]) + sha(v["phone_signature"])), v["installed_transcript"])
            for point,sig,body in ((raw("browser_role5_point"),v["owner_signature"],v["request_transcript"]),
                                   (raw("phone_role4_point"),v["phone_signature"],v["approval_transcript"]),
                                   (raw("phone_role4_point"),v["installed_signature"],v["installed_transcript"])):
                self.assertTrue(verifies(point,sig,body))
                self.assertFalse(verifies(point,sig,body+b"\0"))
            self.assertFalse(verifies(raw("device_enrollment_point"),v["phone_signature"],v["approval_transcript"]))
            self.assertFalse(verifies(raw("original_approval_point"),v["owner_signature"],v["request_transcript"]))
            self.assertFalse(verifies(raw("phone_role4_point"),v["phone_signature"],v["installed_transcript"]))

    def test_original_physical_commitment_uses_exact_activation_bytes_and_full_context(self):
        b = bytes.fromhex(V["without_integrations"]["statement"])
        payload = b"\x01"+b[8:72]+raw("election_commitment")+raw("device_session_digest")+uuid.UUID(V["old_binding_id"]).bytes+sha(raw("activation_evidence"))
        self.assertEqual(frame("ZTSE/line/payload-profile/physical-selection/v1",payload),raw("physical_transcript"))
        self.assertEqual(sha(raw("physical_transcript")),raw("physical_digest"))
        self.assertEqual(sha(frame("ZTSE/line/payload-profile/owner-session/v1",b[8:24]+b[104:136])),b[472:504])
        self.assertEqual(sha(V["origin"].encode()),b[504:536])

    def test_root_manifests_and_original_election_signatures_verify_with_independent_roles(self):
        root = raw("root_pin")[29:94]
        self.assertEqual(sha(b"ZTSE/root-pin/v2\0"+raw("root_pin")),raw("root_fingerprint"))
        for profile in (2,3):
            manifest = raw("manifest"+str(profile).zfill(2))
            self.assertTrue(verifies(root,manifest[-64:],frame("ZTSE/manifest/v"+str(profile),manifest[:-64])))
        old,new = raw("manifest02"),raw("manifest03")
        self.assertEqual(sha(old[:-64]),new[55:87])
        b = raw("bundle628")
        self.assertEqual(628,len(b)); self.assertEqual(raw("core500"),b[:500])
        self.assertTrue(verifies(raw("device_enrollment_point"),b[500:564],frame("ZTSE/line/payload-profile/device/v1",b[:500])))
        self.assertTrue(verifies(raw("original_approval_point"),b[564:],frame("ZTSE/line/payload-profile/owner/v1",b[:500]+sha(b[500:564]))))
        self.assertEqual(sha(frame("ZTSE/line/payload-profile/commitment/v1",b[:500])),raw("election_commitment"))
        self.assertNotEqual(raw("device_enrollment_point"),raw("phone_role4_point"))
        self.assertNotEqual(raw("original_approval_point"),raw("browser_role5_point"))
        self.assertEqual(sha(old[:-64]),b[184:216]); self.assertEqual(sha(new[:-64]),b[224:256])

    def test_original_der_high_s_is_preserved_and_both_signatures_verify_without_rewriting(self):
        b = unframe("ZTSE/line/payload-profile/activation-evidence/v1",raw("activation_evidence"))
        at = 32
        device_point, owner_point = b[at:at+65], b[at+65:at+130]
        at += 130
        device_statement = b[at:at+255]; at += 255
        size = struct.unpack_from(">H",b,at)[0]; at += 2
        device_signature = b[at:at+size]; at += size
        owner_statement = b[at:at+314]; at += 314
        size = struct.unpack_from(">H",b,at)[0]; at += 2
        owner_signature = b[at:at+size]; at += size
        self.assertEqual(8,len(b)-at)
        self.assertGreater(der_pair(device_signature)[1],N//2)
        self.assertTrue(original_der_verifies(device_point,device_signature,device_statement))
        self.assertTrue(original_der_verifies(owner_point,owner_signature,owner_statement))
        self.assertTrue(owner_statement.endswith(device_statement+sha(device_signature)))


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def permission(mapped=False, phase="active", kind="fetch"):
    v = V["with_integration" if mapped else "without_integrations"]
    s = bytes.fromhex(v["statement"])
    result = {"v": 1, "kind": "interval_permission03", "request_kind": kind,
        "request_id": str(uuid.UUID(bytes=s[88:104])) if kind == "interval_challenge" else str(uuid.UUID(int=55)),
        "interval_id": str(uuid.UUID(bytes=s[72:88])), "statement_sha256": b64(sha(s)), "statement": b64(s), "phase": phase,
        "device_session_digest": b64(s[536:568]), "physical_selection_digest": b64(s[568:600]), "owner_session_digest": b64(s[472:504]),
        "compared_ms": "11000", "permission_expires_ms": "12000", "readers": []}
    count = {"reserved": 0, "requested": 1, "install_pending": 2, "active": 3}.get(phase, 3)
    for i, (signature, time) in enumerate(zip(["owner_signature", "phone_signature", "installed_signature"], ["requested_ms", "approved_ms", "installed_ms"])):
        result[signature] = b64(bytes.fromhex(v[signature])) if i < count else None
        result[time] = v[time] if i < count else None
    if mapped:
        result["readers"] = [{"connector_id": V["integration_connector_id"], "read_grant_id": V["integration_read_grant_id"],
            "key_id": b64(raw("integration_key_id")), "key_point": b64(raw("integration_point")), "manifest_generation": "1", "read_directions": 12,
            "registration_expires_ms": "250000", "grant_expires_ms": "250000", "key_valid_from_ms": "1", "key_valid_until_ms": "900000"}]
    return result


class ConversationInterval03SchemaTest(unittest.TestCase):
    def valid(self, value):
        self.assertEqual([], list(VALIDATOR.iter_errors(value)))

    def invalid(self, value):
        self.assertTrue(list(VALIDATOR.iter_errors(value)))

    def test_schema_and_both_exact_mapping_sets(self):
        jsonschema.Draft202012Validator.check_schema(SCHEMA)
        self.valid(permission())
        self.valid(permission(True))
        for kind in ["interval_challenge", "interval_status"]:
            for phase in ["reserved", "requested", "install_pending", "active"]:
                self.valid(permission(phase=phase, kind=kind))

    def test_nulls_describe_only_original_pending_fields_and_never_fetch_permission(self):
        for phase in ["reserved", "requested", "install_pending"]:
            self.invalid(permission(phase=phase))
        for field in ["owner_signature", "phone_signature", "installed_signature", "requested_ms", "approved_ms", "installed_ms", "readers"]:
            value = permission(); value[field] = None; self.invalid(value)
        for phase in ["reserved", "requested", "install_pending"]:
            value = permission(phase=phase, kind="interval_challenge")
            field = ["owner_signature", "phone_signature", "installed_signature"][["reserved", "requested", "install_pending"].index(phase)]
            value[field] = b64(bytes.fromhex(V["without_integrations"][field])); self.invalid(value)

    def test_current_mapping_direction_width_and_closed_fields_refuse(self):
        for change in [8, 4, "12", 0]:
            value = permission(True); value["readers"][0]["read_directions"] = change; self.invalid(value)
        value = permission(True); value["readers"][0]["permission"] = "caller"; self.invalid(value)
        value = permission(True); value["readers"] *= 7; self.invalid(value)
        for name in ["v", "request_id", "permission_expires_ms", "statement"]:
            value = permission(); del value[name]; self.invalid(value)
        value = permission(); value["extra"] = "unsupported"; self.invalid(value)
        for value in ["012000", 12000, "0", "-1"]:
            p = permission(); p["permission_expires_ms"] = value; self.invalid(p)

    def test_device_mutations_acknowledgements_and_status_remain_closed_and_distinct(self):
        p = permission(); base = {"v": 1, "interval_id": p["interval_id"], "statement_sha256": p["statement_sha256"]}
        frames = [
            {**base, "type": "conversation_interval_approve03", "signature": p["phone_signature"]},
            {**base, "type": "conversation_interval_install03", "signature": p["installed_signature"]},
            {**base, "type": "conversation_interval_approved03", "approved_ms": p["approved_ms"]},
            {**base, "type": "conversation_interval_installed03", "installed_ms": p["installed_ms"], "device_session_digest": p["device_session_digest"]},
            {**base, "type": "conversation_interval_stop03"},
            {**base, "type": "conversation_interval_stopped03", "stopped_ms": "12000", "device_session_digest": p["device_session_digest"]}]
        for frame in frames:
            self.valid(frame)
            changed = copy.deepcopy(frame); changed["extra"] = "unsupported"; self.invalid(changed)
            changed = copy.deepcopy(frame); changed["statement_sha256"] += "="; self.invalid(changed)
        status = {**base, "type": "conversation_interval_status03", "challenge": p["request_id"], "phase": "requested",
            "approved_ms": None, "installed_ms": None, "device_session_digest": p["device_session_digest"],
            "interval_permission": permission(phase="requested", kind="interval_status")}
        self.valid(status)
        del status["interval_permission"]; self.invalid(status)


if __name__ == "__main__":
    unittest.main()
