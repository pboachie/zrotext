"""Build pinned JNA bridge and exercise native protected readers with synthetic inputs."""
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

JNA_SHA256 = 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0'
PRODUCER = 'a5fb59c2c5bc81e80b5b8d4b836afd51c5304653'
HERE = Path(__file__).resolve().parent


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
    with tempfile.TemporaryDirectory(prefix='zrotext-java-cng-build-') as folder:
        temp = Path(folder)
        jar = args.jna.resolve() if args.jna else temp / 'jna.jar'
        if not args.jna:
            urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar', jar)
        if hashlib.sha256(jar.read_bytes()).hexdigest() != JNA_SHA256:
            raise ValueError('JNA checksum mismatch')
        java = HERE.parent
        sources = sorted(java.glob('*.java')) + sorted((java / 'reader').glob('*.java')) + sorted(HERE.glob('*.java'))
        sources.append(java.parent.parent / 'crypto-candidate/java/CandidateBody.java')
        run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', jar, '-d', temp, *sources)
        command = ['java', '-cp', str(temp) + os.pathsep + str(jar), 'org.zrotext.candidate.CustodyTest']
        probe = subprocess.run(command + ['--probe'], timeout=30)
        if probe.returncode == 77:
            print('UNQUALIFIED: native PCP unavailable before creation; compilation/refusal only')
            return
        probe.check_returncode()
        # Receipt is outside the auto-deleted build folder; retain it after any failure.
        receipt = Path(tempfile.gettempdir()) / ('zrotext-java-pending-' + temp.name + '.txt')
        child = subprocess.Popen(command + [str(receipt)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True).start()
        try:
            point = ready.get(timeout=30).strip()
            if len(bytes.fromhex(point)) != 65:
                raise ValueError('Native public point missing')
            rows = []
            env = {k: v for k, v in os.environ.items() if k not in ('NODE_OPTIONS', 'NODE_PATH')}
            for profile, script in [('02', 'produce-fixture.mjs'), ('03', 'produce-election03.mjs')]:
                data = json.loads(run('node', producer / 'sdk/native/sealed-candidate/python' / script, '--recipient-point', point, capture_output=True, encoding='utf-8', timeout=45, env=env).stdout)
                if ('archiveScalar' if profile == '02' else 'readerScalar') in data:
                    raise ValueError('Producer exported selected private scalar')
                names = ('rootPin fingerprint manifest inbound outbound reader' if profile == '02' else 'rootPin fingerprint signed02 signed03 core bundle deviceSigningPoint ownerApprovalPoint envelope message').split()
                for name in names:
                    rows.append(f'{profile}.{name}\tb\t{base64.b64decode(data[name], validate=True).hex()}')
                rows.append(f'{profile}.text\tb\t{data["text" if profile == "02" else "bodyText"].encode("utf-8").hex()}')
                if profile == '03':
                    for record in ('accepted', 'authority'):
                        for name, value in data[record].items():
                            kind, value = ('b', base64.b64decode(value, validate=True).hex()) if isinstance(value, str) else ('n', value)
                            rows.append(f'{record}.{name}\t{kind}\t{value}')
            output, error = child.communicate('\n'.join(rows) + '\n', timeout=60)
            if child.returncode:
                raise RuntimeError('Native Java acceptance failed: ' + error)
            if receipt.exists():
                raise RuntimeError('Pending receipt retained after successful acceptance')
            print(output.strip())
        finally:
            if child.poll() is None:
                # Closing input lets Java unwind and delete its owned key.
                child.stdin.close()
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                    raise RuntimeError('Native process stopped; retain pending receipt for owned-key recovery')


if __name__ == '__main__':
    main()
