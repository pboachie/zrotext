"""Compile pinned native Java signer and independently consume its ciphertext."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import urllib.request

HERE = Path(__file__).resolve().parent
PRODUCER = '304d512b7a420a3102278f32baed095f3e778989'
JNA_SHA256 = 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0'


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--jna', type=Path)
    args = parser.parse_args()
    producer = args.producer.resolve()
    if run('git', '-C', producer, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != PRODUCER:
        raise ValueError('Unexpected producer revision')
    run('git', '-C', producer, 'diff', '--quiet', 'HEAD', '--')
    env = {k: v for k, v in os.environ.items() if k not in ('NODE_OPTIONS', 'NODE_PATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS')}
    with tempfile.TemporaryDirectory(prefix='zrotext-java-compose-build-') as folder:
        temp = Path(folder)
        jar = args.jna.resolve() if args.jna else temp / 'jna.jar'
        if not args.jna:
            urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar', jar)
        if hashlib.sha256(jar.read_bytes()).hexdigest() != JNA_SHA256:
            raise ValueError('JNA checksum mismatch')
        java = HERE.parent
        sources = sorted(java.glob('*.java')) + sorted((java / 'reader').glob('*.java')) + [java / 'custody/ProtectedSigner.java'] + sorted(HERE.glob('*.java'))
        sources.append(java.parent.parent / 'crypto-candidate/java/CandidateBody.java')
        run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', jar, '-d', temp, *sources, env=env)
        command = ['java', '-cp', str(temp) + os.pathsep + str(jar), 'org.zrotext.candidate.ComposeTest']
        probe = subprocess.run(command + ['--probe'], timeout=30, env=env)
        if probe.returncode == 77:
            print('UNQUALIFIED: PCP signing unavailable before creation; compilation/refusal only')
            return
        probe.check_returncode()
        receipt = Path(tempfile.gettempdir()) / ('zrotext-java-sign-pending-' + temp.name + '.txt')
        child = subprocess.Popen(command + [str(receipt)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', env=env)
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True).start()
        try:
            point = ready.get(timeout=30).strip()
            if len(bytes.fromhex(point)) != 65:
                raise ValueError('Native signer point missing')
            scripts = producer / 'sdk/native/sealed-candidate/python'
            fixture = json.loads(run('node', scripts / 'produce-election03.mjs', '--signer-point', point, capture_output=True, encoding='utf-8', timeout=45, env=env).stdout)
            rows = []
            for name in 'rootPin fingerprint signed02 signed03 core bundle deviceSigningPoint ownerApprovalPoint message'.split():
                rows.append(f'{name}\tb\t{base64.b64decode(fixture[name], validate=True).hex()}')
            for record in ('accepted', 'authority'):
                for name, value in fixture[record].items():
                    kind, value = ('b', base64.b64decode(value, validate=True).hex()) if isinstance(value, str) else ('n', value)
                    rows.append(f'{record}.{name}\t{kind}\t{value}')
            output, error = child.communicate('\n'.join(rows) + '\n', timeout=90)
            if child.returncode:
                raise RuntimeError('Native Java composition failed: ' + error)
            if receipt.exists():
                raise RuntimeError('Pending signer receipt retained after successful acceptance')
            count = 0
            for line in output.splitlines():
                if line.startswith('ENVELOPE '):
                    envelope = line.removeprefix('ENVELOPE ')
                    base64.b64decode(envelope, validate=True)
                    value = json.loads(run('node', scripts / 'consume-native03.mjs', input=json.dumps(dict(fixture=fixture,envelope=envelope,expectedText='Native composed 🌱')),capture_output=True,encoding='utf-8',timeout=45,env=env).stdout)
                    if value != dict(verified=True,openedRecipients=2):
                        raise ValueError('Independent consumer did not verify both recipients')
                    count += 1
                else:
                    print(line)
            if count != 3:
                raise ValueError('Missing native composed envelopes')
            print('Independent maintained TypeScript verified and opened both recipients for three compositions')
        finally:
            if child.poll() is None:
                child.stdin.close()
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                    raise RuntimeError('Native signer stopped; preserve pending receipt for owned-key recovery')


if __name__ == '__main__':
    main()
