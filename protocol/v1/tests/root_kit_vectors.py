"""Independent standard-library verification; all secret inputs are synthetic labels."""

import base64
import hashlib
import json
from pathlib import Path


def check_recovery_kit_vector():
    vectors = Path(__file__).resolve().parents[1] / "vectors"
    kit = json.loads((vectors / "recovery-kit-01.json").read_text(encoding="utf-8"))
    backup = json.loads((vectors / "root-backup-01.json").read_text(encoding="utf-8"))
    assert kit["status"] == "PROPOSED_RECOVERY_KIT_01_SYNTHETIC_ONLY"
    pin = bytes.fromhex(kit["rootPinHex"])
    cipher = bytes.fromhex(backup["ciphertextHex"])
    account = bytes.fromhex(kit["accountIdHex"])
    backup_id = bytes.fromhex(kit["backupIdHex"])
    fingerprint = hashlib.sha256(b"ZTSE/root-pin/v2\0" + pin).digest()
    origin = kit["origin"].encode("ascii")
    assert len(pin) == 94 and pin[:5] == b"ZTRP\2" and pin[29] == 4
    assert pin[5:21] == account and pin[21:29] == (1).to_bytes(8, "big")
    assert pin.hex() == backup["rootPinHex"]
    assert backup_id == cipher[6:22]
    assert fingerprint.hex() == kit["fingerprintHex"] == backup["fingerprintHex"]
    secret = hashlib.sha256(b"ZROtext synthetic root-backup test recovery").digest()
    base32 = base64.b32encode(secret).decode("ascii").rstrip("=")
    checksum = hashlib.sha256(
        b"ZTSE/recovery-kit/v1\0" + account + (1).to_bytes(8, "big") + backup_id
        + fingerprint + len(origin).to_bytes(2, "big") + origin + secret
    ).digest()[:4].hex().upper()
    token = "ZTRK1-" + "-".join(base32[i:i + 4] for i in range(0, 52, 4)) + "-" + checksum
    assert len(token) == 79
    assert hashlib.sha256(token.encode("ascii")).hexdigest() == kit["tokenSha256Hex"]
    decoded = base64.b32decode("".join(token.split("-")[1:14]) + "====")
    assert decoded == secret
    digest = hashlib.sha256(cipher).digest()
    assert digest.hex() == kit["encryptedBackupSha256Hex"]
    card = b"ZTRC\1" + len(origin).to_bytes(2, "big") + origin + pin + digest
    assert len(card) == 133 + len(origin) <= 645
    assert card.hex() == kit["cardHex"]
