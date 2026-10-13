"""Isolated installed ZTWC01 consumer; no source package imports."""
import base64
import json
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric import ec
import zrotext_native_candidate as n
from zrotext_native_candidate import sealed_candidate as s

assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
f=json.load(sys.stdin)
def dec(v):return base64.b64decode(v,validate=True)
root=s.enroll_root02(dec(f['rootPin']),dec(f['fingerprint']))
manifest=s.verify_manifest02(dec(f['manifest']),root,f['now'])
scope={k:v if type(v) is int else dec(v) for k,v in f['scope'].items()}
custody=n.SoftwareRecipient(ec.derive_private_key(int.from_bytes(dec(f['selectedScalar']),'big'),ec.SECP256R1()))
seal,opened=(n.seal_workflow_context,n.open_workflow_context) if f['role']==2 else (n.seal_integration_workflow_context,n.open_integration_workflow_context)
assert n.workflow_context_aad(scope)==dec(f['aad'])
assert opened(manifest,scope,f['now'],custody,dec(f['envelope']),require_protected=False)==dec(f['plaintext'])
raw=seal(manifest,scope,f['now'],dec(f['plaintext']))
print(json.dumps(dict(installed=True,envelope=base64.b64encode(raw).decode('ascii'))))
