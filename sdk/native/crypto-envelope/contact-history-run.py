"""Exercise managed contact local history restart, process CAS and interrupted-append refusal."""
import argparse
import base64
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
PRODUCER = 'ccf28fe445ba959aa01d99fed6bd9ee3188b749c'


def run(*args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--origin-asset', type=Path, required=True)
    parser.add_argument('--ruby', default='ruby')
    args = parser.parse_args()
    producer = args.producer.resolve(strict=True)
    if run('git', '-C', producer, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != PRODUCER:
        raise ValueError('Unexpected maintained producer revision')
    if run('git', '-C', producer, 'diff', '--quiet', 'HEAD', '--').returncode:
        raise ValueError('Clean maintained producer required')
    env = {k: v for k, v in os.environ.items() if k not in (
        'CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'DOTNET_STARTUP_HOOKS', 'RUBYOPT', 'RUBYLIB', 'NODE_OPTIONS', 'NODE_PATH')}
    with tempfile.TemporaryDirectory(prefix='zrotext-contact-history-') as temporary:
        folder = Path(temporary)
        record = json.loads(run('node', producer / 'sdk/native/sealed-candidate/python/contact-interop.mjs',
                                capture_output=True, text=True, encoding='utf-8', env=env).stdout)
        keys = ('rootPin', 'fingerprint', 'manifest', 'nextManifest', 'account', 'statement', 'nextStatement',
                'contact', 'routing', 'name', 'notes', 'replacement', 'create', 'update', 'clear')
        wire = ''.join(f"{key}\t{base64.b64decode(record[key]).hex()}\n" for key in keys)
        if args.language == 'java':
            import hashlib, urllib.request
            jars = []
            for path, digest in (runpy.run_path(str(HERE / 'contact-mutation-run.py'))['JNA'],):
                data = urllib.request.urlopen('https://repo.maven.apache.org/maven2/' + path, timeout=30).read()
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError('Unexpected Java dependency')
                target = folder / Path(path).name
                target.write_bytes(data)
                jars.append(str(target))
            cp = os.pathsep.join([str(folder), *jars])
            sources = [HERE / 'java/HpkeRecipient.java', HERE / 'java/ManifestChain.java', HERE / 'java/SignedEnvelope.java',
                       HERE / 'java/contact/ContactField.java', HERE / 'java/contact/ContactOrigin.java',
                       HERE / 'java/contact/ProtectedContactSigner.java',
                       *sorted((HERE / 'java/contact-history').glob('*.java'))]
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', cp, '-d', folder, *sources, env=env)
            command = ['java', '-cp', cp, 'org.zrotext.candidate.ContactHistoryTest', str(args.origin_asset.resolve(strict=True))]
        elif args.language == 'csharp':
            run('dotnet', 'build', HERE / 'csharp/contact-history/HistoryTest.csproj', '-o', folder / 'bin', env=env)
            command = ['dotnet', str(folder / 'bin/HistoryTest.dll'), str(args.origin_asset.resolve(strict=True))]
        else:
            command = [args.ruby, str(HERE / 'ruby/contact/history_test.rb'), str(args.origin_asset.resolve(strict=True))]
        path = folder / 'history.dat'

        def execute(mode, target=path):
            return subprocess.run(command + [str(target), record['origin'], mode], input=wire, text=True,
                                  encoding='utf-8', capture_output=True, timeout=120, env=env)

        result = execute('--exercise'); result.check_returncode(); print(result.stdout.strip())
        cas_path = folder / 'history-cas.dat'
        result = execute('--seed', cas_path); result.check_returncode(); print(result.stdout.strip())
        result = execute('--advance', cas_path); result.check_returncode(); print(result.stdout.strip())
        result = execute('--compete', cas_path)
        if result.returncode != 3:
            raise RuntimeError('Expected the competing successor process to refuse the fork: ' + result.stderr)
        result = execute('--verify', cas_path); result.check_returncode(); print(result.stdout.strip())
        interrupted = folder / 'interrupted.dat'; shutil.copyfile(cas_path, interrupted)
        if execute('--partial', interrupted).returncode != 19:
            raise RuntimeError('Expected abrupt child exit after partial append')
        result = execute('--refused', interrupted); result.check_returncode(); print(result.stdout.strip())
        result = execute('--verify', cas_path); result.check_returncode()
        print('Process CAS, fresh restart and fail-closed interrupted append passed')


if __name__ == '__main__':
    main()
