"""Build managed transports and exercise the exact shared native local TLS suite."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
PIN = '78a3900ed1fea531c3fbe894696ee19805e0f1c9'
JARS = (
    ('com/google/code/gson/gson/2.14.0/gson-2.14.0.jar',
     '2cbd119bf1961c28788310963dc80ba65f58cdeec1dd139c8bdb1240faa2c36f'),
    ('com/google/errorprone/error_prone_annotations/2.48.0/error_prone_annotations-2.48.0.jar',
     'b49c5c958316ed67a09c699dda9aa749caf434d51d863dea599ef36a49b9c855'),
)


def run(*args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--ruby', default='ruby')
    args = parser.parse_args()
    fixture = args.fixture.resolve(strict=True)
    if run('git', '-C', fixture, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != PIN:
        raise ValueError('Unexpected shared TLS suite revision')
    run('git', '-C', fixture, 'diff', '--quiet', 'HEAD', '--')
    env = {k: v for k, v in os.environ.items() if k not in (
        'CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'DOTNET_STARTUP_HOOKS', 'RUBYOPT', 'RUBYLIB')}
    with tempfile.TemporaryDirectory(prefix='zrotext-managed-http-') as directory:
        folder = Path(directory)
        if args.language == 'java':
            jars = []
            for path, expected in JARS:
                target = folder / Path(path).name
                with urllib.request.urlopen('https://repo.maven.apache.org/maven2/' + path, timeout=30) as response:
                    content = response.read()
                if hashlib.sha256(content).hexdigest() != expected:
                    raise ValueError('Unexpected pinned JSON dependency bytes')
                target.write_bytes(content); jars.append(str(target))
            classpath = os.pathsep.join([str(folder), *jars])
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', classpath, '-d', folder,
                HERE / 'java/http/OriginalHttp.java', HERE / 'java/http/HttpTest.java', env=env)
            command = ['java', '-cp', classpath, 'org.zrotext.candidate.HttpTest']
        elif args.language == 'csharp':
            run('dotnet', 'build', HERE / 'csharp/http/HttpTest.csproj', '-o', folder, env=env)
            command = ['dotnet', str(folder / 'HttpTest.dll')]
        else:
            command = [args.ruby, str(HERE / 'ruby/http/test.rb')]
        command_file = folder / 'command.json'
        command_file.write_text(json.dumps(command), encoding='utf-8')
        run(sys.executable, fixture / 'sdk/native/hpke-candidate/test-original-http.py',
            '--command-file', command_file, env=env)
        run(sys.executable, HERE / 'original-http-hostname.py', '--fixture', fixture,
            '--command-file', command_file, env=env)


if __name__ == '__main__':
    main()
