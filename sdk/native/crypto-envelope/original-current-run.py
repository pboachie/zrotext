"""Exercise managed signed current proof, local TLS and durable history fences."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
PIN = '50c7258eb7e616ba8f0574d167bff7b999a9bd8d'


def run(*args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--ruby', default='ruby')
    args = parser.parse_args(); fixture = args.fixture.resolve(strict=True)
    if run('git', '-C', fixture, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != PIN:
        raise ValueError('Unexpected shared signed TLS suite revision')
    run('git', '-C', fixture, 'diff', '--quiet', 'HEAD', '--')
    env = {k: v for k, v in os.environ.items() if k not in (
        'CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'DOTNET_STARTUP_HOOKS', 'RUBYOPT', 'RUBYLIB', 'NODE_OPTIONS', 'NODE_PATH')}
    with tempfile.TemporaryDirectory(prefix='zrotext-managed-current-') as directory:
        folder = Path(directory)
        if args.language == 'java':
            spec = importlib.util.spec_from_file_location('http_build', HERE / 'original-http-run.py')
            http = importlib.util.module_from_spec(spec); spec.loader.exec_module(http)
            jars = []
            for path, expected in http.JARS:
                with urllib.request.urlopen('https://repo.maven.apache.org/maven2/' + path, timeout=30) as response:
                    content = response.read()
                if hashlib.sha256(content).hexdigest() != expected:
                    raise ValueError('Unexpected pinned JSON dependency bytes')
                target = folder / Path(path).name; target.write_bytes(content); jars.append(str(target))
            classpath = os.pathsep.join([str(folder), *jars])
            sources = [HERE / 'java' / name for name in ('HpkeRecipient.java', 'ManifestChain.java', 'SignedEnvelope.java',
                       'reader/OriginalReplyReader.java', 'original-history/OriginalReplyCheckpoint.java',
                       'http/OriginalHttp.java', 'http/OriginalCurrentClient.java', 'http/CurrentTest.java')]
            sources.append(HERE.parent / 'crypto-candidate/java/CandidateBody.java')
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', classpath, '-d', folder, *sources, env=env)
            command = ['java', '-cp', classpath, 'org.zrotext.candidate.CurrentTest']
        elif args.language == 'csharp':
            run('dotnet', 'build', HERE / 'csharp/current-http/CurrentTest.csproj', '-o', folder, env=env)
            command = ['dotnet', str(folder / 'CurrentTest.dll')]
        else:
            command = [args.ruby, str(HERE / 'ruby/http/current_test.rb')]
        command_file = folder / 'command.json'; command_file.write_text(json.dumps(command), encoding='utf-8')
        run(sys.executable, fixture / 'sdk/native/hpke-candidate/test-original-current.py', '--command-file', command_file,
            '--producer', args.producer.resolve(strict=True), env=env)
        run(sys.executable, HERE / 'original-current-duplicates.py', '--command-file', command_file,
            '--fixture', fixture, '--producer', args.producer.resolve(strict=True), env=env)


if __name__ == '__main__':
    main()
