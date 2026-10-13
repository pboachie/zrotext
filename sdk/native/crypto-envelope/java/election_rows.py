"""Flatten independently produced public election proof fields for native tests."""
import base64
import json
import sys

sys.stdin.reconfigure(encoding="utf-8")
fixture = json.load(sys.stdin)
for name in ("rootPin", "fingerprint", "signed02", "signed03", "core", "bundle",
             "deviceSigningPoint", "ownerApprovalPoint"):
    print(name, "b", base64.b64decode(fixture[name], validate=True).hex(), sep="\t")
for prefix in ("accepted", "authority"):
    for name, value in fixture[prefix].items():
        if isinstance(value, str):
            print(prefix + "." + name, "b", base64.b64decode(value, validate=True).hex(), sep="\t")
        else:
            assert type(value) is int
            print(prefix + "." + name, "n", value, sep="\t")
