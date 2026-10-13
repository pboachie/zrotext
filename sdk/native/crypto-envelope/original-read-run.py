"""Exercise managed verified original reads and final network proof over local TLS."""
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
PIN = 'd127e5c86f3b17db371acc608eedcf6419264ba7'


def run(*args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--ruby', default='ruby')
    parser.add_argument('--hardware', action='store_true')
    parser.add_argument('--jna', type=Path)
    args = parser.parse_args(); fixture = args.fixture.resolve(strict=True)
    if run('git', '-C', fixture, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != PIN:
        raise ValueError('Unexpected shared signed TLS suite revision')
    if run('git', '-C', fixture, 'status', '--porcelain', capture_output=True, text=True).stdout.strip():
        raise ValueError('Clean reviewed shared TLS fixture required')
    env = {k: v for k, v in os.environ.items() if k not in (
        'CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'DOTNET_STARTUP_HOOKS', 'RUBYOPT', 'RUBYLIB', 'NODE_OPTIONS', 'NODE_PATH')}
    with tempfile.TemporaryDirectory(prefix='zrotext-managed-read-') as directory:
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
            if args.hardware:
                if args.jna is None or hashlib.sha256(args.jna.read_bytes()).hexdigest() != 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0':
                    raise ValueError('Exact JNA 5.17.0 required for native acceptance')
                jars.append(str(args.jna.resolve(strict=True)))
            classpath = os.pathsep.join([str(folder), *jars])
            sources = [HERE / 'java' / name for name in ('HpkeRecipient.java', 'ManifestChain.java', 'SignedEnvelope.java',
                       'reader/OriginalReplyReader.java', 'original-history/OriginalReplyCheckpoint.java',
                       'http/OriginalHttp.java', 'http/OriginalCurrentClient.java', 'http/ReadTest.java')]
            sources.append(HERE.parent / 'crypto-candidate/java/CandidateBody.java')
            if args.hardware:
                sources.extend([HERE / 'java/custody/ProtectedRecipient.java', HERE / 'java/http/ProtectedReadTest.java'])
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', classpath, '-d', folder, *sources, env=env)
            command = ['java', '-cp', classpath, 'org.zrotext.candidate.ProtectedReadTest' if args.hardware else 'org.zrotext.candidate.ReadTest']
        elif args.language == 'csharp':
            run('dotnet', 'build', HERE / 'csharp/read-http/ReadTest.csproj', '-o', folder, env=env)
            command = ['dotnet', str(folder / 'ReadTest.dll')]
        else:
            command = [args.ruby, str(HERE / 'ruby/http/read_test.rb')]
        command_file = folder / 'command.json'; command_file.write_text(json.dumps(command), encoding='utf-8')
        run(sys.executable, fixture / 'sdk/native/hpke-candidate/test-original-read.py', '--command-file', command_file,
            '--producer', args.producer.resolve(strict=True), *(['--hardware'] if args.hardware else []), env=env)



if __name__ == '__main__':
    main()
