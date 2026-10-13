"""Export only maintained public root-rotation fixture fields for native tests."""
import base64
import json
from pathlib import Path
root=Path(__file__).resolve().parents[3]
f=json.loads((root/'sdk/typescript/test/vectors/draft02-rotation.json').read_text())
for name in ('old_root_pin_b64','old_root_fingerprint_b64','old_manifest_b64','transition_b64','new_root_point_b64','new_manifest_b64','new_root_pin_b64','new_root_fingerprint_b64'):
    print(name+'\t'+base64.b64decode(f[name],validate=True).hex())
print('now_ms\t'+str(f['now_ms']))
