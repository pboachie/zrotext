"""Public signed provenance fixtures. No generated authority or private keys."""
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def raw(value):
    return base64.b64decode(value, validate=True)


def main():
    genesis = json.loads((ROOT / "sdk/typescript/test/vectors/draft02-genesis.json").read_text())
    chain = json.loads((ROOT / "protocol/v1/vectors/sealed-profile03-sdk-outbound-01.json").read_text())
    for name, fixture, key, time in (
        ("genesis", genesis, "manifest_b64", "now_ms"),
        ("profile03-chain", chain, "manifest02_b64", "historical_comparison_ms"),
    ):
        manifest = raw(fixture[key])
        digest_key = "semantic_manifest_digest_b64" if name == "genesis" else "manifest02_digest_b64"
        assert hashlib.sha256(manifest[:-64]).digest() == raw(fixture[digest_key])
        fields = [name, str(fixture[time]), raw(fixture["root_pin_b64"]).hex(),
                  raw(fixture["root_fingerprint_b64"]).hex(), manifest.hex(), raw(fixture[digest_key]).hex()]
        if name != "genesis":
            for key in ("manifest03_b64", "successor03_b64", "current_alternate03_b64"):
                fields.append(raw(fixture[key]).hex())
            fields.append(str(fixture["now_ms"]))
        print("\t".join(fields))


if __name__ == "__main__":
    main()
