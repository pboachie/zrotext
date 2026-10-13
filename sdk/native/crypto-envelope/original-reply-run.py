"""Verify maintained selected role3 ciphertext using native software and PCP recipients."""
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
PIN = '72124e1a3ff28e782f870eeddbdc33cacf8ca3b4'
JNA_HASH = 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0'


def run(*args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)


def rows(fixture):
    return '\n'.join(name + '\t' + (value.encode('utf-8') if name == 'text' else
                     base64.b64decode(value, validate=True)).hex()
                     for name, value in fixture.items() if name != 'now') + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--jna', type=Path)
    parser.add_argument('--ruby', default='ruby')
    parser.add_argument('--require-hardware', action='store_true')
    args = parser.parse_args(); producer = args.producer.resolve()
    if run('git', '-C', producer, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != PIN:
        raise ValueError('Unexpected producer revision')
    run('git', '-C', producer, 'diff', '--quiet', 'HEAD', '--')
    env = {k: v for k, v in os.environ.items() if k not in ('NODE_OPTIONS', 'NODE_PATH',
           'CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
           'DOTNET_STARTUP_HOOKS', 'RUBYOPT', 'RUBYLIB')}
    cli = producer / 'sdk/native/sealed-candidate/python/produce-selected-reply02.mjs'
    with tempfile.TemporaryDirectory(prefix='zrotext-original-reply-') as folder:
        temp = Path(folder)
        if args.language == 'java':
            jar = args.jna.resolve() if args.jna else temp / 'jna.jar'
            if not args.jna:
                urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar', jar)
            if hashlib.sha256(jar.read_bytes()).hexdigest() != JNA_HASH:
                raise ValueError('JNA checksum mismatch')
            spec = importlib.util.spec_from_file_location('packages', HERE / 'package-managed.py')
            packages = importlib.util.module_from_spec(spec); spec.loader.exec_module(packages)
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', jar, '-d', temp,
                *packages.runtime_sources('java'), *sorted((HERE / 'java/original-reply').glob('*.java')), env=env)
            base = ['java', '-cp', str(temp) + os.pathsep + str(jar)]
            software = base + ['org.zrotext.candidate.OriginalReplyTest']
            protected = base + ['org.zrotext.candidate.OriginalProtectedTest']
        elif args.language == 'csharp':
            software = ['dotnet', str(temp / 'software/OriginalReplyTest.dll')]
            protected = ['dotnet', str(temp / 'protected/OriginalProtectedTest.dll')]
            for kind, name, output in [('original-reply', 'OriginalReplyTest', 'software'),
                                       ('original-protected', 'OriginalProtectedTest', 'protected')]:
                run('dotnet', 'build', HERE / 'csharp' / kind / (name + '.csproj'), '-o', temp / output, env=env)
        else:
            software = [args.ruby, str(HERE / 'ruby/original-reply/test.rb')]
            protected = [args.ruby, str(HERE / 'ruby/original-reply/protected.rb')]
        fixture = json.loads(run('node', cli, capture_output=True, text=True, encoding='utf-8', env=env).stdout)
        run(*software, input=rows(fixture), text=True, encoding='utf-8', timeout=60, env=env)
        probe = subprocess.run(protected + ['--probe'], env=env, timeout=30)
        if probe.returncode == 77:
            if args.require_hardware:
                raise RuntimeError('Required hardware unavailable before creation')
            print('UNQUALIFIED: PCP unavailable before creation; software acceptance only')
            return
        probe.check_returncode()
        receipt = Path(tempfile.gettempdir()) / ('zrotext-original-pending-' + temp.name + '.txt')
        child = subprocess.Popen(protected + [str(receipt)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, encoding='utf-8', env=env)
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True).start()
        try:
            point = ready.get(timeout=30).strip().lower()
            if len(bytes.fromhex(point)) != 65:
                raise ValueError('Native public point missing')
            fixture = json.loads(run('node', cli, '--reader-point', point, capture_output=True,
                                     text=True, encoding='utf-8', env=env, timeout=60).stdout)
            if 'originalScalar' in fixture:
                raise ValueError('Native selected private scalar present')
            output, error = child.communicate(rows(fixture), timeout=90)
            if child.returncode or 'QUALIFIED:' not in output or receipt.exists():
                raise RuntimeError('Protected original reply failed: ' + error)
            print(output.strip())
        finally:
            if child.poll() is None:
                child.stdin.close()
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
            if receipt.exists():
                raise RuntimeError('Owned-key cleanup remains pending in receipt: ' + str(receipt))


if __name__ == '__main__':
    main()
