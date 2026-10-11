# SPDX-License-Identifier: AGPL-3.0-only
"""Independent stdlib byte encoders, not crypto or live-authority adapters.

The discovered SDK Node test invokes this exact file and independently verifies
signatures/HPKE. No signing/private material, current session or provider is used.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import unittest
import uuid

VECTOR = Path(__file__).resolve().parents[1] / "vectors/sealed-profile03-contract-01.json"
V = json.loads(VECTOR.read_text(encoding="utf-8"))
MAX = (1 << 63) - 1


def raw(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value):
        raise ValueError("canonical hex")
    return bytes.fromhex(value)


def sha(value):
    return hashlib.sha256(value).digest()


def framed(domain, value):
    if not domain or "\0" in domain or not domain.isascii():
        raise ValueError("unterminated ASCII domain")
    return domain.encode("ascii") + b"\0" + struct.pack(">I", len(value)) + value


def u64(number, positive=True):
    if type(number) is not int or not (1 if positive else 0) <= number <= MAX:
        raise ValueError("signed storage integer")
    return struct.pack(">Q", number)


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ValueError("canonical digest")
    result = base64.urlsafe_b64decode(value + "=")
    if len(result) != 32 or base64.urlsafe_b64encode(result).decode().rstrip("=") != value:
        raise ValueError("digest roundtrip")
    return result


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value):
        raise ValueError("canonical UUID")
    parsed = uuid.UUID(value)
    if parsed.int == 0 or str(parsed) != value:
        raise ValueError("nonzero UUID")
    return parsed.bytes


def key_id(role, public):
    return sha(b"ZTSE/key/v1\0" + struct.pack(">H", 16 if role <= 3 else 257) + public)


def manifest_unsigned(profile, predecessor, version, previous, issue):
    ids = {name: raw(value) for name, value in V["identitiesHex"].items()}
    public = {name: raw(value) for name, value in V["publicPointsHex"].items()}
    records = []
    for role, name, device, line, scope in [
        (1, "payload", ids["device"], ids["line"], 4),
        (2, "archive", bytes(16), bytes(16), 12),
        (5, "signer", bytes(16), ids["line"], 1),
        (6, "root", bytes(16), bytes(16), 0),
    ]:
        records.append(bytes([role]) + key_id(role, public[name]) + public[name]
                       + device + line + struct.pack(">H", scope)
                       + u64(V["nowMs"] - 1000) + u64(V["nowMs"] + 3600000) + b"\x01")
    prefix = b"ZTMA" + bytes([profile]) + (bytes([3, predecessor]) if profile == 3 else b"")
    return (prefix + ids["account"] + u64(1) + u64(version) + u64(issue)
            + u64(V["nowMs"] + 3600000) + previous + public["root"]
            + bytes([len(records)]) + b"".join(records))


CORE_FIELDS = [
    ("magic", 5), ("operationProfiles", 3), ("account", 16), ("device", 16),
    ("line", 16), ("challenge", 16), ("oldBinding", 16),
    ("oldBindingGeneration", 8), ("newBindingGeneration", 8),
    ("oldBindingProofDigest", 32), ("rootFingerprint", 32), ("vaultGeneration", 8),
    ("priorManifestVersion", 8), ("priorManifestDigest", 32),
    ("successorManifestVersion", 8), ("successorManifestDigest", 32),
    ("payloadReaderKeyId", 32), ("deviceSigningKeyId", 32), ("ownerApprovalKeyId", 32),
    ("nonce", 32), ("issuedMs", 8), ("expiresMs", 8), ("originDigest", 32),
    ("ownerSessionBindingDigest", 32), ("deviceSessionBindingDigest", 32), ("reserved", 4),
]


def election_core(fields):
    if set(fields) != {name for name, _ in CORE_FIELDS}:
        raise ValueError("closed election fields")
    parts = [raw(fields[name]) for name, _ in CORE_FIELDS]
    if any(len(part) != width for part, (_, width) in zip(parts, CORE_FIELDS)):
        raise ValueError("election width")
    if parts[0] != b"ZTPE\x03" or parts[1] != b"\x01\x02\x03" or parts[-1] != bytes(4):
        raise ValueError("election version/profile/reserved")
    if any(not any(part) for part in parts[2:-1]):
        raise ValueError("zero identity")
    for name, width in CORE_FIELDS:
        if width == 8:
            u64(int.from_bytes(raw(fields[name]), "big"))
    return b"".join(parts)


IDS = ["account_id", "device_id", "line_id", "message_id", "attempt_id"]
NUMBERS = ["connection_epoch", "deployment_epoch", "binding_generation", "attempt_generation",
           "expires_at_ms", "trust_generation", "manifest_version"]
DIGESTS = ["reader_key_id", "envelope_sha256", "unsigned_sha256", "manifest_digest",
           "root_fingerprint", "election_digest"]
FIXED = {"v": 1, "type": "sealed_execution_grant", "grant_version": 3,
         "envelope_profile": 3, "manifest_profile": 3, "reader_role": 1}


def fetch(frame):
    if set(frame) != set(IDS + NUMBERS + DIGESTS + list(FIXED) + ["segment_count"]):
        raise ValueError("closed grant")
    if any(type(frame[k]) is not type(v) or frame[k] != v for k, v in FIXED.items()):
        raise ValueError("grant profile")
    segments = frame["segment_count"]
    if type(segments) is not int or not 1 <= segments <= 6:
        raise ValueError("segment count")
    return (b"ZT/sealed-envelope-fetch/v3\0" + bytes([1, 3, 3, 3, 1, segments])
            + b"".join(identity(frame[k]) for k in IDS)
            + b"".join(u64(frame[k]) for k in NUMBERS)
            + b"".join(digest(frame[k]) for k in DIGESTS))


def ready(frame):
    fixed = {"v": 1, "type": "sealed_ready", "grant_version": 3,
             "envelope_profile": 3, "manifest_profile": 3}
    numbers = ["connection_epoch", "deployment_epoch", "binding_generation",
               "trust_generation", "manifest_version"]
    digests = ["reader_key_id", "manifest_digest", "root_fingerprint", "election_digest"]
    if set(frame) != set(list(fixed) + numbers + digests + ["line_id"]):
        raise ValueError("closed readiness")
    if any(type(frame[k]) is not type(v) or frame[k] != v for k, v in fixed.items()):
        raise ValueError("readiness header/profile")
    identity(frame["line_id"])
    for key in numbers:
        u64(frame[key])
    for key in digests:
        digest(frame[key])
    # No live authenticated session, current binding or capability is simulated.


class Profile03Bytes(unittest.TestCase):
    def test_complete_root_pin_and_all_manifest_unsigned_bytes(self):
        pin = b"ZTRP\x02" + raw(V["identitiesHex"]["account"]) + u64(1) + raw(V["publicPointsHex"]["root"])
        self.assertEqual(pin, raw(V["rootPinHex"]))
        self.assertEqual(sha(b"ZTSE/root-pin/v2\0" + pin), raw(V["rootFingerprintHex"]))
        m = V["manifests"]
        for name, profile, predecessor, version, previous, issue in [
            ("prior02", 2, 0, 1, bytes(32), V["nowMs"] - 1000),
            ("successor03", 3, 2, 2, raw(m["prior02"]["semanticDigestHex"]), V["nowMs"] - 1000),
            ("alternateSignature03", 3, 2, 2, raw(m["prior02"]["semanticDigestHex"]), V["nowMs"] - 1000),
            ("sameVersionFork03", 3, 2, 2, raw(m["prior02"]["semanticDigestHex"]), V["nowMs"] - 1001),
            ("after03", 3, 3, 3, raw(m["successor03"]["semanticDigestHex"]), V["nowMs"] - 1000),
            ("genesis03ContractOnly", 3, 0, 1, bytes(32), V["nowMs"] - 1000),
        ]:
            with self.subTest(name=name):
                unsigned = manifest_unsigned(profile, predecessor, version, previous, issue)
                self.assertEqual(unsigned, raw(m[name]["unsignedHex"]))
                self.assertEqual(unsigned, raw(m[name]["signedHex"])[:-64])
                self.assertEqual(sha(unsigned), raw(m[name]["semanticDigestHex"]))
        self.assertEqual(217 + 149, 366)
        self.assertEqual(217 + 149 * 64, 9753)

    def test_complete_election_bundle_and_both_signature_transcripts(self):
        e = V["election"]
        core = election_core(e["coreFieldsHex"])
        self.assertEqual(len(core), 500)
        self.assertEqual(core, raw(e["coreHex"]))
        device, owner = raw(e["deviceSignatureHex"]), raw(e["ownerSignatureHex"])
        self.assertEqual(len(device), 64)
        self.assertEqual(len(owner), 64)
        self.assertEqual(core + device + owner, raw(e["bundleHex"]))
        self.assertEqual(len(raw(e["bundleHex"])), 628)
        self.assertEqual(framed("ZTSE/line/payload-profile/device/v1", core), raw(e["deviceTranscriptHex"]))
        self.assertEqual(framed("ZTSE/line/payload-profile/owner/v1", core + sha(device)), raw(e["ownerTranscriptHex"]))
        self.assertEqual(sha(framed("ZTSE/line/payload-profile/commitment/v1", core)), raw(e["semanticCommitmentHex"]))
        with self.assertRaises(ValueError):
            framed("ZTSE/line/payload-profile/device/v1\0", core)

    def test_election_reconstruction_refuses_missing_unknown_wrong_width_profile_and_reserved(self):
        fields = V["election"]["coreFieldsHex"]
        for name in ["account", "nonce", "successorManifestDigest", "ownerSessionBindingDigest"]:
            with self.subTest(name=name):
                missing = dict(fields)
                del missing[name]
                with self.assertRaises(ValueError):
                    election_core(missing)
                with self.assertRaises(ValueError):
                    election_core({**fields, name: fields[name][2:]})
        for name, value in [("operationProfiles", "01020300"), ("reserved", "00000001"),
                            ("account", "00" * 16), ("vaultGeneration", "ff" * 8)]:
            with self.assertRaises(ValueError):
                election_core({**fields, name: value})
        with self.assertRaises(ValueError):
            election_core({**fields, "unknown": "00"})

    def test_complete_grant_transcript_and_opaque_identity_hashes(self):
        g = V["grant"]
        self.assertEqual(fetch(g["frame"]), raw(g["transcriptHex"]))
        self.assertEqual(len(fetch(g["frame"])), 362)
        self.assertEqual(sha(raw(g["envelopeIdentityBytesHex"])), digest(g["frame"]["envelope_sha256"]))
        self.assertEqual(sha(raw(g["unsignedIdentityBytesHex"])), digest(g["frame"]["unsigned_sha256"]))

    def test_closed_grant_integer_uuid_digest_and_field_mutations(self):
        frame = V["grant"]["frame"]
        ready(V["readyFrame"])
        self.assertEqual(len(V["readyFrame"]), 15)
        expected_ready = {key: frame[key] for key in [
            "v", "grant_version", "envelope_profile", "manifest_profile", "connection_epoch",
            "deployment_epoch", "line_id", "binding_generation", "reader_key_id",
            "trust_generation", "manifest_version", "manifest_digest", "root_fingerprint", "election_digest",
        ]}
        expected_ready["type"] = "sealed_ready"
        self.assertEqual(V["readyFrame"], expected_ready)
        for key, value in [("v", 2), ("type", "sealed_execution_grant"),
                           ("envelope_profile", 2), ("connection_epoch", "2"),
                           ("line_id", None), ("unknown", 1)]:
            with self.subTest(ready=key), self.assertRaises((ValueError, TypeError)):
                ready({**V["readyFrame"], key: value})
        missing_header = dict(V["readyFrame"])
        del missing_header["type"]
        with self.assertRaises(ValueError):
            ready(missing_header)
        for key in frame:
            missing = dict(frame)
            del missing[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                fetch(missing)
        for key, value in [("unknown", 1), ("envelope_profile", 2), ("grant_version", 1),
                           ("connection_epoch", 0), ("trust_generation", MAX + 1),
                           ("manifest_version", True), ("segment_count", 7),
                           ("account_id", frame["account_id"].upper()),
                           ("line_id", "00000000-0000-0000-0000-000000000000"),
                           ("manifest_digest", frame["manifest_digest"] + "=")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                fetch({**frame, key: value})
        # Python losslessly reconstructs the full signed-storage boundary;
        # Node Number fixtures deliberately stay in the safe integer subset.
        self.assertEqual(len(fetch({**frame, "attempt_generation": MAX})), 362)
        self.assertNotEqual(fetch({**frame, "attempt_generation": MAX}), fetch(frame))

    def test_exact_nonempty_distinct_wrap_and_body_domain_bytes(self):
        c = V["hpkeContext"]
        header, protected = raw(c["headerHex"]), raw(c["protectedHex"])
        self.assertEqual(header, b"ZTSE\x03\x01\0\0" + struct.pack(">H", len(protected)))
        self.assertEqual(len(protected), 157)
        suffix = header + protected + bytes([c["recipientRole"]]) + raw(c["recipientKeyIdHex"])
        info, aad = b"ZTSE/wrap/v3\0" + suffix, b"ZTSE/wrap-aad/v3\0" + suffix
        self.assertEqual(info, raw(c["infoHex"]))
        self.assertEqual(aad, raw(c["aadHex"]))
        self.assertNotEqual(info, aad)
        self.assertTrue(info and aad)
        self.assertEqual(b"ZTSE/body/v3\0" + header + protected, raw(c["bodyAadHex"]))


if __name__ == "__main__":
    unittest.main()
