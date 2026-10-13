"""Ordinary installed template encryption plus exact persistence messages."""
import base64
import json
from pathlib import Path
import sys
import zrotext_native_candidate as n
from zrotext_native_candidate import sealed_candidate as s

assert Path(n.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
f=json.load(sys.stdin)
def dec(v):return base64.b64decode(v,validate=True)
root=s.enroll_root02(dec(f['rootPin']),dec(f['fingerprint']));manifest=s.verify_manifest02(dec(f['manifest']),root,f['now'])
scope={k:v if type(v) is int else dec(v) for k,v in f['scope'].items()}
envelope=n.seal_encrypted_template(manifest,scope,f['now'],f['content'])
request=n.template_save_request(scope,'00000000-0000-0000-0000-000000000041',0,envelope)
assert n.template_save_receipt(request,b'\xef\xbb\xbf{"revision":1.0}')==dict(revision=1)
try:n.template_save_receipt(request,b'{"revision":1,"send":true}')
except n.TemplateStoreError:pass
else:raise AssertionError('Invalid receipt accepted')
result=dict(path=request.path,headers=dict(request.headers),body=base64.b64encode(request.body).decode('ascii'),revision=request.revision,encryptedDigest=request.encrypted_digest)
print(json.dumps(dict(installed=True,request=result)))
