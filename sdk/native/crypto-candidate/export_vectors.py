"""Test-only adapter from the existing JSON corpus to dependency-free native TSV readers.

Envelope slicing here is fixture preparation, NOT a production authority verifier.
"""
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[3]
fixture = json.loads((root / "protocol/v1/vectors/ztse-body-text-01.json").read_text(encoding="utf-8"))
rows = []
for case in fixture["textCases"]:
    raw = bytes.fromhex(case["hex"])
    outcome = "accept" if case["verdict"] == "accept" else case["reason"]
    rows.append([case["name"], "text", "", "", "", raw.hex(), outcome, raw.hex() if outcome == "accept" else ""])
for case in fixture["authenticatedCases"]:
    envelope = bytes.fromhex(case["envelopeHex"])
    assert envelope[:4] == b"ZTSE" and envelope[4] in (1, 2)
    end = 10 + int.from_bytes(envelope[8:10], "big")
    nonce = envelope[end:end + 12]
    length = int.from_bytes(envelope[end + 12:end + 16], "big")
    ciphertext = envelope[end + 16:end + 16 + length]
    aad = f"ZTSE/body/v{envelope[4]}\0".encode() + envelope[:end]
    outcome = "accept" if case["verdict"] == "accept" else case["reason"]
    row = [case["name"], "open", case["cekHex"], nonce.hex(), aad.hex(), ciphertext.hex(), outcome,
           case.get("text", "").encode().hex() if outcome == "accept" else ""]
    rows.append(row)
    if outcome == "accept":
        for field in (2, 3, 4, 5):
            damaged = row.copy()
            raw = bytearray.fromhex(damaged[field])
            raw[-1] ^= 1
            damaged[field] = raw.hex()
            damaged[0] += f"_tamper_{field}"
            damaged[6:] = ["authentication", ""]
            rows.append(damaged)
        damaged = row.copy()
        raw = bytearray.fromhex(damaged[5])
        raw[0] ^= 1
        damaged[5] = raw.hex()
        damaged[0] += "_tamper_ciphertext"
        damaged[6:] = ["authentication", ""]
        rows.append(damaged)
        for field in (2, 3, 4, 5):
            damaged = row.copy()
            damaged[field] = ""
            damaged[0] += f"_empty_{field}"
            damaged[6:] = ["shape", ""]
            rows.append(damaged)
Path(sys.argv[1]).write_text("\n".join("\t".join(row) for row in rows) + "\n", encoding="utf-8")
print(f"Exported {len(rows)} candidate conformance cases")
