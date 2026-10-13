"""Exercise the shared signed outbound03 policy with native protected signers."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import urllib.request

HERE = Path(__file__).resolve().parent
JNA_HASH = 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0'


def run(*args, **kw):
    return subprocess.run([str(v) for v in args], check=True, **kw)


def rows(fixture):
    policy = fixture['policy']
    result = ['\t'.join(map(str, (fixture['name'], str(fixture['accept']).lower(),
                                 policy['observed_ms'], policy['now_ms'], policy['expires_ms'])))]
    for name in ('rootPin', 'fingerprint', 'signed02', 'signed03', 'core', 'bundle',
                 'deviceSigningPoint', 'ownerApprovalPoint', 'message', 'readerScalar', 'signerPoint'):
        result.append(name + '\tb\t' + base64.b64decode(fixture[name], validate=True).hex())
    if 'envelope' in fixture:
        result.append('envelope\tb\t' + base64.b64decode(fixture['envelope'], validate=True).hex())
    result.append('readerPoint\tb\t' + base64.b64decode(next(v['point'] for v in fixture['recipients'] if v['role'] == 1), validate=True).hex())
    result.append('bodyText\tb\t' + fixture['bodyText'].encode('utf-8').hex())
    for record in ('accepted', 'authority'):
        for name, value in fixture[record].items():
            kind, value = ('b', base64.b64decode(value, validate=True).hex()) if isinstance(value, str) else ('n', value)
            result.append(f'{record}.{name}\t{kind}\t{value}')
    return '\n'.join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--producer-pin', required=True, help='Exact reviewed fixture commit; checked before execution')
    parser.add_argument('--jna', type=Path)
    parser.add_argument('--ruby', default='ruby')
    parser.add_argument('--require-hardware', action='store_true')
    args = parser.parse_args(); producer = args.producer.resolve()
    if len(args.producer_pin) != 40 or any(c not in '0123456789abcdef' for c in args.producer_pin):
        raise ValueError('Full fixture commit required')
    if run('git', '-C', producer, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != args.producer_pin:
        raise ValueError('Unexpected fixture commit')
    run('git', '-C', producer, 'diff', '--quiet', 'HEAD', '--')
    corpus = json.loads((producer / 'protocol/v1/vectors/sealed-profile03-outbound-time-policy.json').read_text(encoding='utf-8'))
    expected = {case['name']: case['accept'] for case in corpus['cases']}
    if len(expected) != 14:
        raise ValueError('Review changed policy inventory')
    cli = producer / 'sdk/typescript/test/fixtures/profile03-time-cli.mjs'
    env = {k: v for k, v in os.environ.items() if k not in ('NODE_OPTIONS', 'NODE_PATH', 'CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'RUBYOPT', 'RUBYLIB', 'DOTNET_STARTUP_HOOKS')}
    with tempfile.TemporaryDirectory(prefix='zrotext-time-policy-') as directory:
        temp = Path(directory)
        if args.language == 'java':
            jar = args.jna.resolve() if args.jna else temp / 'jna.jar'
            if not args.jna:
                urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar', jar)
            if hashlib.sha256(jar.read_bytes()).hexdigest() != JNA_HASH:
                raise ValueError('JNA checksum mismatch')
            spec = importlib.util.spec_from_file_location('packages', HERE / 'package-managed.py')
            packages = importlib.util.module_from_spec(spec); spec.loader.exec_module(packages)
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', jar, '-d', temp,
                *packages.runtime_sources('java'), HERE / 'java/time-policy/TimePolicyTest.java', env=env)
            command = ['java', '-cp', str(temp) + os.pathsep + str(jar), 'org.zrotext.candidate.TimePolicyTest']
        elif args.language == 'csharp':
            run('dotnet', 'build', HERE / 'csharp/time-policy/TimePolicyTest.csproj', '-o', temp, env=env)
            command = ['dotnet', str(temp / 'TimePolicyTest.dll')]
        else:
            command = [args.ruby, str(HERE / 'ruby/time-policy/test.rb')]
        reader_fixtures = json.loads(run('node', cli, '--reader-cases', capture_output=True, text=True,
                                        encoding='utf-8', timeout=90, env=env).stdout)['cases']
        if len(reader_fixtures) != len(expected) or {f['name']: f['accept'] for f in reader_fixtures} != expected:
            raise ValueError('Shared reader fixture inventory differs')
        reader_process = subprocess.run(command + ['--readers'], input='\n\n'.join(map(rows, reader_fixtures)) + '\n',
                                        capture_output=True, text=True, encoding='utf-8', timeout=90, env=env)
        if reader_process.returncode:
            raise RuntimeError('Native authenticated reader policy failed: ' + reader_process.stderr)
        reader_output = reader_process.stdout
        read_results = {}
        for line in reader_output.splitlines():
            if line.startswith('READ '):
                _, name, status = line.split(' ')
                if name in read_results or status not in ('accepted', 'refused'):
                    raise ValueError('Duplicate or malformed reader result')
                read_results[name] = status == 'accepted'
            elif not line.startswith('READERS:'):
                raise ValueError('Unexpected reader output')
        if read_results != expected:
            raise ValueError('Reader policy mismatch')
        print('All 14 authenticated native reader cases matched (including signed/encrypted policy negatives)')
        probe = subprocess.run(command + ['--probe'], env=env, timeout=30)
        if probe.returncode == 77:
            if args.require_hardware:
                raise ValueError('Required native signing capability unavailable')
            print('UNQUALIFIED: read-only native signing capability refused before creation')
            return
        probe.check_returncode()
        receipt = Path(tempfile.gettempdir()) / (temp.name + '-pending.txt')
        child = subprocess.Popen(command + [str(receipt)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, encoding='utf-8', env=env)
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True).start()
        try:
            point = ready.get(timeout=30).strip()
            if len(point) != 130 or not point.startswith('04'):
                raise ValueError('Native signer handshake missing')
            bytes.fromhex(point)
            fixtures = json.loads(run('node', cli, '--signer-point', point, capture_output=True,
                                      text=True, encoding='utf-8', timeout=90, env=env).stdout)['cases']
            if len(fixtures) != len(expected) or {f['name']: f['accept'] for f in fixtures} != expected:
                raise ValueError('Shared fixture inventory differs')
            if any('signerScalar' in f or f['signerPoint'] != base64.b64encode(bytes.fromhex(point)).decode() for f in fixtures):
                raise ValueError('Producer did not preserve native signer boundary')
            output, error = child.communicate('\n\n'.join(map(rows, fixtures)) + '\n', timeout=90)
            if child.returncode:
                raise RuntimeError('Native time-policy acceptance failed: ' + error)
            actual = {}; by_name = {f['name']: f for f in fixtures}
            for line in output.splitlines():
                if line.startswith('ENVELOPE '):
                    _, name, envelope = line.split(' ')
                    if name in actual or expected.get(name) is not True:
                        raise ValueError('Unexpected native success')
                    fixture = by_name[name]
                    result = json.loads(run('node', cli, '--consume', input=json.dumps(dict(fixture=fixture, envelope=envelope, expectedText=fixture['bodyText'])), capture_output=True, text=True, encoding='utf-8', timeout=45, env=env).stdout)
                    if result != dict(verified=True, name=name, recipients=3):
                        raise ValueError('Independent consumer failed to open all recipients')
                    actual[name] = True
                elif line.startswith('REFUSED '):
                    name = line.removeprefix('REFUSED ')
                    if name in actual or expected.get(name) is not False:
                        raise ValueError('Unexpected native refusal')
                    actual[name] = False
                elif line.startswith('QUALIFIED:'):
                    print(line)
                else:
                    raise ValueError('Unexpected native output')
            if actual != expected or receipt.exists():
                raise ValueError('Incomplete policy results or pending owned cleanup receipt')
            print('All shared policy cases matched; maintained TypeScript independently opened every accepted case for three recipients')
        finally:
            if child.poll() is None:
                child.stdin.close()
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
                    raise RuntimeError('Native signer interrupted; preserve exact pending receipt for cleanup')


if __name__ == '__main__':
    main()
