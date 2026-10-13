"""Adapt fresh synthetic elected envelope+recipient material to temporary native input."""
import base64
import json
import sys

sys.stdin.reconfigure(encoding="utf-8")
fixture = json.load(sys.stdin)
def data(name):
    return base64.b64decode(fixture[name], validate=True)
for name in ("rootPin", "fingerprint", "signed02", "signed03", "core", "bundle",
             "deviceSigningPoint", "ownerApprovalPoint", "envelope", "message", "readerScalar"):
    print(name, "b", data(name).hex(), sep="\t")
manifest = data("signed03")
reader = base64.b64decode(fixture["authority"]["selectedReaderKeyId"], validate=True)
point = next(manifest[153+149*i+33:153+149*i+98] for i in range(manifest[152])
             if manifest[153+149*i] == 1 and manifest[154+149*i:186+149*i] == reader)
print("readerPoint", "b", point.hex(), sep="\t")
print("text", "b", fixture["bodyText"].encode().hex(), sep="\t")
for prefix in ("accepted", "authority"):
    for name, value in fixture[prefix].items():
        if isinstance(value, str):
            print(prefix+"."+name, "b", base64.b64decode(value, validate=True).hex(), sep="\t")
        else:
            assert type(value) is int
            print(prefix+"."+name, "n", value, sep="\t")
