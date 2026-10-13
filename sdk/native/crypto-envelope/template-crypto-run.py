"""Exercise managed ZTWT01 templates against maintained independent TypeScript."""
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
PIN = '5d6d683a78461ccb1782014989cb5e4a3f2927f2'


def run(*args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--ruby', default='ruby')
    parser.add_argument('--hardware', action='store_true')
    parser.add_argument('--fail-setup', action='store_true')
    args = parser.parse_args(); fixture = args.fixture.resolve(strict=True)
    if run('git', '-C', fixture, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != PIN:
        raise ValueError('Unexpected shared template suite revision')
    if run('git', '-C', fixture, 'status', '--porcelain', capture_output=True, text=True).stdout.strip():
        raise ValueError('Clean reviewed shared template fixture required')
    env = {k: v for k, v in os.environ.items() if k not in (
        'CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'DOTNET_STARTUP_HOOKS', 'RUBYOPT', 'RUBYLIB', 'NODE_OPTIONS', 'NODE_PATH')}
    with tempfile.TemporaryDirectory(prefix='zrotext-managed-template-crypto-') as directory:
        folder = Path(directory)
        if args.language == 'java':
            spec = importlib.util.spec_from_file_location('http_build', HERE / 'original-http-run.py')
            http = importlib.util.module_from_spec(spec); spec.loader.exec_module(http)
            jars = []
            for path, expected in [*http.JARS, ('net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar', 'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0')]:
                with urllib.request.urlopen('https://repo.maven.apache.org/maven2/' + path, timeout=30) as response:
                    content = response.read()
                if hashlib.sha256(content).hexdigest() != expected:
                    raise ValueError('Unexpected pinned JSON dependency bytes')
                target = folder / Path(path).name; target.write_bytes(content); jars.append(str(target))
            classpath = os.pathsep.join([str(folder), *jars])
            sources = [HERE / 'java' / name for name in ('HpkeRecipient.java', 'ManifestChain.java', 'SignedEnvelope.java',
                       'reader/SealedReader02.java', 'reader/ElectedReader03.java', 'Election03.java', 'reader/OriginalReplyReader.java',
                       'custody/ProtectedRecipient.java', 'template/TemplateContent.java', 'template-crypto/EncryptedTemplate.java',
                       'template-crypto/TemplateCryptoTest.java', 'template-crypto/ProtectedTemplateTest.java')]
            sources.append(HERE.parent / 'crypto-candidate/java/CandidateBody.java')
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', classpath, '-d', folder, *sources, env=env)
            command = ['java', '-cp', classpath, 'org.zrotext.candidate.ProtectedTemplateTest']
        elif args.language == 'csharp':
            run('dotnet', 'build', HERE / 'csharp/template-crypto/TemplateCryptoTest.csproj', '-o', folder, env=env)
            command = ['dotnet', str(folder / 'TemplateCryptoTest.dll')]
        else:
            command = [args.ruby, str(HERE / 'ruby/template-crypto/test.rb')]
        command_file = folder / 'command.json'; command_file.write_text(json.dumps(command), encoding='utf-8')
        run(sys.executable, fixture / 'sdk/native/hpke-candidate/test-template-crypto.py', '--command-file', command_file,
            '--producer', args.producer.resolve(strict=True), *(['--hardware'] if args.hardware else []), *(['--fail-setup'] if args.fail_setup else []), env=env)



if __name__ == '__main__':
    main()
