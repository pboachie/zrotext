"""Export public signed envelope component fixtures as TSV; no private material."""
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
VECTORS = ROOT / "protocol/v1/vectors"


def label(value):
    return value.encode("ascii") + b"\0"


def rows():
    proof = json.loads((VECTORS / "ztse-draft-01.json").read_text())
    signatures = json.loads((VECTORS / "ztse-draft-02-signatures.json").read_text())
    signer = bytes.fromhex(signatures["signerPublicPointHex"])
    identity = hashlib.sha256(label("ZTSE/key/v1") + b"\x01\x01" + signer).digest()
    envelopes = []
    # Exact independently signed reconstruction used by Rust's sealed_envelope tests.
    for name in ("outbound", "inbound"):
        unsigned = bytearray.fromhex(proof[name]["unsignedHex"])
        unsigned[4] = 2
        unsigned[114:146] = identity
        envelopes.append(("profile2-" + name, bytes(unsigned) + bytes.fromhex(signatures[name]["signatureV2Hex"]), signer))
    candidate = json.loads((VECTORS / "sealed-profile03-sdk-outbound-01.json").read_text())
    envelope = base64.b64decode(candidate["envelope_b64"], validate=True)
    manifest = base64.b64decode(candidate["manifest03_b64"], validate=True)
    record = next(manifest[153+149*i:153+149*(i+1)] for i in range(manifest[152])
                  if manifest[153+149*i] == 5 and manifest[154+149*i:186+149*i] == envelope[114:146])
    envelopes.append(("profile3-outbound", envelope, record[33:98]))
    for name, envelope, signer in envelopes:
        profile = envelope[4]
        prefix_end = 10 + int.from_bytes(envelope[8:10], "big")
        prefix = envelope[:prefix_end]
        body_aad = label(f"ZTSE/body/v{profile}") + prefix
        body_end = prefix_end + 16 + int.from_bytes(envelope[prefix_end+12:prefix_end+16], "big")
        if profile == 3:
            assert body_aad == base64.b64decode(candidate["body_aad_b64"])
            assert hashlib.sha256(envelope[:-64]).digest() == base64.b64decode(candidate["unsigned_sha256_b64"])
        for i in range(envelope[body_end]):
            at = body_end + 1 + i * 146
            role, identity = envelope[at], envelope[at+1:at+33]
            suffix = prefix + bytes([role]) + identity
            info = label(f"ZTSE/wrap/v{profile}") + suffix
            aad = b"" if profile == 2 else label("ZTSE/wrap-aad/v3") + suffix
            if profile == 3 and role == 1:
                assert info == base64.b64decode(candidate["device_info_b64"])
                assert aad == base64.b64decode(candidate["device_aad_b64"])
            yield [name, str(profile), envelope.hex(), signer.hex(), body_aad.hex(), str(role), identity.hex(), info.hex(), aad.hex()]


if __name__ == "__main__":
    for row in rows():
        print("\t".join(row))
