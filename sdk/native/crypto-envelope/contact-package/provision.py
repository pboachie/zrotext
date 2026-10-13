"""Installed contact capability with separate synthetic enrollment provisioning.

The consumer owns its fresh PCP key and durable receipt. This fixture opens only
that exact alias to sign synthetic setup evidence, closes its borrowed handle,
and leaves field production plus deletion to ordinary installed public APIs.
"""
import base64
import ctypes
import hashlib
import json
import re
import subprocess
import sys

PIN = 'ccf28fe445ba959aa01d99fed6bd9ee3188b749c'


def node(source, name, value=None, *args):
    return json.loads(subprocess.check_output(
        ['node', str(source / 'sdk/native/sealed-candidate/python' / name), *args],
        input=None if value is None else json.dumps(value), text=True, encoding='utf-8', timeout=60))


def provision(source, identity):
    # Fixture-only API access, never imported into the installed consumer.
    sys.path.insert(0, str(source / 'sdk/native/sealed-candidate/python'))
    from zrotext_native_candidate.cng_signing import HardwareSigner
    from zrotext_native_candidate.cng_custody import SILENT
    alias, point = identity['alias'], base64.b64decode(identity['public'], validate=True)
    assert re.fullmatch(r'zrotext-managed-(java|csharp|ruby)-contact-p256-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', alias)
    assert len(point) == 65
    f = node(source, 'contact-interop.mjs')
    template = node(source, 'contact-producer-interop.mjs', dict(fixture=f, point=identity['public']), '--root-template')
    f.update(rootPin=template['rootPin'], fingerprint=template['fingerprint'])
    borrowed = HardwareSigner._start()
    try:
        borrowed.name = alias
        borrowed._api.call('NCryptOpenKey', borrowed._provider, ctypes.byref(borrowed._key), alias, 0, SILENT)
        borrowed._qualify()
        assert borrowed.public_point() == point

        def sign(domain, unsigned):
            digest = hashlib.sha256(domain.encode() + b'\0' + len(unsigned).to_bytes(4, 'big') + unsigned).digest()
            return base64.b64encode(unsigned + borrowed._sign_digest(digest)).decode()

        unsigned = base64.b64decode(template['manifestUnsigned'], validate=True)
        f['manifest'] = sign('ZTSE/manifest/v2', unsigned)
        next_manifest = bytearray(unsigned)
        next_manifest[29:37] = (2).to_bytes(8, 'big')
        next_manifest[53:85] = hashlib.sha256(unsigned).digest()
        f['nextManifest'] = sign('ZTSE/manifest/v2', bytes(next_manifest))
        statements = node(source, 'contact-producer-interop.mjs', dict(fixture=f), '--statement-template')
        for key in ('statement', 'nextStatement'):
            f[key] = sign('ZT/contact-reader/authorization/v1', base64.b64decode(statements[key + 'Unsigned'], validate=True))
    finally:
        borrowed.close()
    return f
