"""Exercise ordinary installed contact APIs and exact-owned protected cleanup."""
import argparse
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from provision import provision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--command-file', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--origin-asset', type=Path, required=True)
    parser.add_argument('--mutation-fixture', type=Path)
    parser.add_argument('--hardware', action='store_true')
    args = parser.parse_args()
    for source, pin in ((args.fixture, '62a00c790ef7537b92f196e9de44a94debbb088f'),
                        (args.producer, 'ccf28fe445ba959aa01d99fed6bd9ee3188b749c')):
        assert subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == pin
        assert not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip()
    if args.mutation_fixture:
        assert subprocess.check_output(['git', '-C', str(args.mutation_fixture), 'rev-parse', 'HEAD'], text=True).strip() == '0381f71dc8a67d25562d5a6e23ac4ed50faeed4e'
        assert not subprocess.check_output(['git', '-C', str(args.mutation_fixture), 'status', '--porcelain'], text=True).strip()
    command = json.loads(args.command_file.read_text(encoding='utf-8'))
    if not isinstance(command, list) or not command or any(not isinstance(x, str) or not x or '\0' in x for x in command):
        raise ValueError('Trusted command must be a nonempty argument array')
    command += [str(args.origin_asset.resolve(strict=True))]
    with tempfile.TemporaryDirectory(prefix='zrotext-installed-contact-') as temporary:
        path = Path(temporary) / 'command.json'; path.write_text(json.dumps(command), encoding='utf-8')
        if not args.hardware:
            subprocess.run([sys.executable, str((args.mutation_fixture or args.fixture) / ('sdk/native/hpke-candidate/test-contact-mutation.py' if args.mutation_fixture else 'sdk/native/hpke-candidate/test-contact-field.py')),
                            '--producer', str(args.producer), '--command-file', str(path)], check=True)
            return
    if os.name != 'nt':
        raise ValueError('Actual protected acceptance requires Windows')
    subprocess.run(command + ['--probe'], check=True, timeout=30)
    for failed_setup in (False, True):
        receipt = Path(tempfile.gettempdir()) / ('zrotext-installed-contact-' + os.urandom(16).hex() + '.json')
        child = subprocess.Popen(command + ['--hardware', str(receipt)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        cleaned = False
        try:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pending = pool.submit(child.stdout.readline)
                try:
                    identity = json.loads(pending.result(timeout=60))
                except BaseException:
                    child.stdin.close()
                    try:
                        child.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        child.terminate()
                    raise
            if failed_setup:
                out, _ = child.communicate('', timeout=30)
                assert child.returncode != 0
            else:
                fixture = provision(args.producer, identity)
                requests = [dict(operation='produce', fixture=fixture, field=field, statement=statement)
                            for field, statement in [('name', 'statement'), ('notes', 'statement'), ('replacement', 'nextStatement')]]
                requests += [dict(requests[0], cancel=True), dict(requests[0], closed=True),
                             dict(requests[0], fixture=dict(fixture, routing=base64.b64encode(bytes(32)).decode()))]
                if args.mutation_fixture:
                    requests.append(dict(operation='mutation-chain', fixture=fixture))
                out, _ = child.communicate(json.dumps(requests), timeout=120)
                assert child.returncode == 0, 'Installed protected contact operation failed'
                rows = json.loads(out.splitlines()[0])
                assert [r['accepted'] for r in rows[:6]] == [True, True, True, False, False, False]
                outputs = [dict(bytes=row['bytes'], statement=request['statement']) for row, request in zip(rows[:3], requests[:3]) if row['accepted']]
                verified = json.loads(subprocess.check_output(['node', str(args.fixture / 'sdk/native/hpke-candidate/contact-field-interop.mjs'),
                    str(args.producer), '--consume'], input=json.dumps(dict(fixture=fixture, outputs=outputs)), text=True, encoding='utf-8', timeout=60))
                assert verified == dict(verified=True, fields=3)
                if args.mutation_fixture:
                    assert rows[6]['accepted'] and rows[6]['value']['refusals'] == 12
                    proof = dict(fixture=fixture, fields=rows[6]['value']['fields'], mutations=rows[6]['value']['mutations'])
                    value = json.loads(subprocess.check_output(['node', str(args.producer / 'sdk/native/sealed-candidate/python/contact-producer-interop.mjs'), '--consume'], input=json.dumps(proof), text=True, encoding='utf-8', timeout=60))
                    assert value['verified'] is True and value['fields'] == 3 and value['transitions'] == 4
                    assert len(base64.b64decode(value['finalDigest'], validate=True)) == 32
            assert json.loads(out.splitlines()[-1]) == dict(owned_key_deleted=True)
            assert json.loads(receipt.read_text())['state'] == 'owned_key_deleted'
            cleaned = True
        finally:
            if not cleaned:
                if not child.stdin.closed:
                    child.stdin.close()
                child.stdin = None
                try:
                    remaining, _ = child.communicate(timeout=30)
                    assert remaining.splitlines() and json.loads(remaining.splitlines()[-1]) == dict(owned_key_deleted=True), 'Owned cleanup incomplete; private receipt retained'
                except subprocess.TimeoutExpired:
                    child.terminate(); child.communicate(timeout=10)
                    raise AssertionError('Unresponsive owned child; private receipt retained')
    if args.mutation_fixture:
        print('Installed protected mutations: four transitions, twelve refusals and independent maintained verification passed')
    print('Installed protected contact: six controls, three independent verifications and setup-failure EOF cleanup passed')


if __name__ == '__main__':
    main()
