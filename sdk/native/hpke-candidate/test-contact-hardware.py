"""Installed contact capability with separate synthetic enrollment provisioning.

The consumer owns its fresh PCP key and durable receipt. This fixture opens only
that exact alias to sign synthetic setup evidence, closes its borrowed handle,
and leaves field production plus deletion to ordinary installed public APIs.
"""
import argparse
import base64
import concurrent.futures
import ctypes
import hashlib
import json
from pathlib import Path
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
    assert re.fullmatch(r'zrotext-candidate-contact-root-[0-9a-f]{32}', alias)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    source = args.producer.resolve(strict=True)
    assert subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip()
    for setup_failure in (False, True):
        child = subprocess.Popen([str(args.binary.resolve(strict=True)), '--hardware'], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        cleanup_verified = False
        try:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pending = pool.submit(child.stdout.readline)
                try:
                    identity = json.loads(pending.result(timeout=60))
                except BaseException:
                    child.stdin.close()
                    try: child.wait(timeout=30)
                    except subprocess.TimeoutExpired: child.terminate()
                    raise
            if setup_failure:
                out, _ = child.communicate('', timeout=30)
                assert child.returncode != 0
                assert json.loads(out.splitlines()[-1]) == dict(owned_key_deleted=True)
                cleanup_verified = True
                continue
            fixture = provision(source, identity)
            requests = [dict(operation='produce', fixture=fixture, field=field, statement=statement)
                        for field, statement in [('name', 'statement'), ('notes', 'statement'), ('replacement', 'nextStatement')]]
            requests += [dict(requests[0], cancel=True), dict(requests[0], closed=True)]
            # Wrong historical scope must never become a signed result.
            wrong = dict(fixture, routing=base64.b64encode(bytes(32)).decode())
            requests.append(dict(requests[0], fixture=wrong))
            out, _ = child.communicate(json.dumps(requests), timeout=90)
            assert child.returncode == 0, 'installed protected contact consumer failed'
            lines = out.splitlines()
            assert len(lines) == 2 and json.loads(lines[-1]) == dict(owned_key_deleted=True)
            cleanup_verified = True
            results = json.loads(lines[0])
            assert [r['accepted'] for r in results] == [True, True, True, False, False, False]
            outputs = [dict(bytes=row['bytes'], statement=request['statement']) for request, row in zip(requests, results) if row['accepted']]
            report = json.loads(subprocess.check_output(
                ['node', str(Path(__file__).with_name('contact-field-interop.mjs')), str(source), '--consume'],
                input=json.dumps(dict(fixture=fixture, outputs=outputs)), text=True, encoding='utf-8', timeout=60))
            assert report == dict(verified=True, fields=3)
        finally:
            if not cleanup_verified:
                if not child.stdin.closed: child.stdin.close()
                child.stdin = None
                try:
                    remaining, _ = child.communicate(timeout=30)
                    assert remaining.splitlines() and json.loads(remaining.splitlines()[-1]) == dict(owned_key_deleted=True), 'owned cleanup not confirmed; private receipt retained'
                except subprocess.TimeoutExpired:
                    child.terminate(); child.communicate(timeout=10)
                    raise AssertionError('unresponsive owned child; private cleanup receipt retained')
    print('6 protected contact consumer controls and setup-failure EOF cleanup passed; 3 fields independently verified')


if __name__ == '__main__':
    main()
