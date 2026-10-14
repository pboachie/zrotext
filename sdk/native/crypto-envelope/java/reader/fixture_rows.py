"""Adapt independent producer JSON on stdin to managed reader TSV; never persist secrets."""
import base64
import json
import sys

sys.stdin.reconfigure(encoding="utf-8")
fixture = json.load(sys.stdin)
def data(key):
    return base64.b64decode(fixture[key], validate=True)
manifest = data("manifest")
identity = data("reader")
point = next(manifest[151+149*i+33:151+149*i+98] for i in range(manifest[150])
             if manifest[151+149*i] == 2 and manifest[152+149*i:184+149*i] == identity)
for name in ("inbound", "outbound"):
    print("\t".join([name, str(fixture["now"])] + [data(key).hex() for key in
        ("rootPin", "fingerprint", "manifest", name, "archiveScalar", "reader")]
        + [point.hex(), fixture["text"].encode().hex(), data("inboundBackdated").hex(),
           data("liveSuccessor").hex(), data("rotatedSuccessor").hex()]))
