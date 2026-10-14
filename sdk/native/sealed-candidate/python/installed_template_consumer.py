"""Isolated installed native templates; maintained TS validates returned bytes."""
import base64
import json
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric import ec
import zrotext_native_candidate as native
from zrotext_native_candidate import sealed_candidate as s


def main():
    assert Path(native.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    f=json.load(sys.stdin);decode=lambda v:base64.b64decode(v,validate=True)
    root=s.enroll_root02(decode(f['rootPin']),decode(f['fingerprint']))
    manifest=s.verify_manifest02(decode(f['manifest']),root,f['now'])
    scope={k:v if type(v) is int else decode(v) for k,v in f['scope'].items()}
    custody=native.SoftwareRecipient(ec.derive_private_key(int.from_bytes(decode(f['archiveScalar']),'big'),ec.SECP256R1()))
    assert native.open_encrypted_template(manifest,scope,f['now'],custody,decode(f['envelope']),require_protected=False)==f['content']
    assert native.preview_encrypted_template(f['content'])==f['preview']
    for vector in f['estimates']:
        if vector.get('refused'):
            try:native.estimate_segments(vector['text'])
            except native.TemplateError:pass
            else:raise AssertionError('invalid SMS estimate accepted')
        else:assert native.estimate_segments(vector['text'])==vector['estimate']
    for key in ('malformed','invalidUtf8'):
        try:native.open_encrypted_template(manifest,scope,f['now'],custody,decode(f[key]),require_protected=False)
        except native.TemplateError:pass
        else:raise AssertionError('noncanonical template accepted')
    envelope=native.seal_encrypted_template(manifest,scope,f['now'],f['content'])
    assert envelope!=decode(f['envelope'])
    print(json.dumps(dict(installed=True,envelope=base64.b64encode(envelope).decode(),canonical=f['canonical'])))


if __name__=='__main__':main()
