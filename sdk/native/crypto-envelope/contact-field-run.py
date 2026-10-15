"""Build managed contact probes; verify shared software and optional owned PCP fields."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
FIXTURE = '62a00c790ef7537b92f196e9de44a94debbb088f'
PRODUCER = 'ccf28fe445ba959aa01d99fed6bd9ee3188b749c'
JNA = ('net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar',
       'b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0')


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def fetch(path, digest):
    # Maven Central occasionally answers a transient 404 under load; retry
    # briefly before treating the artifact as missing.
    import time
    data = None
    for attempt in range(4):
        try:
            data = urllib.request.urlopen('https://repo.maven.apache.org/maven2/' + path, timeout=30).read()
            break
        except urllib.error.HTTPError as error:
            if error.code != 404 or attempt == 3:
                raise
            time.sleep(2 * (attempt + 1))
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Unexpected Java dependency')
    return data


def clean(path, pin):
    path = path.resolve(strict=True)
    if run('git', '-C', path, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != pin:
        raise ValueError('Unexpected fixture revision')
    if run('git', '-C', path, 'status', '--porcelain', capture_output=True, text=True).stdout.strip():
        raise ValueError('Clean reviewed fixture required')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--origin-asset', type=Path, required=True, help='Trusted artifact from contact-origin/build.py')
    parser.add_argument('--ruby', default='ruby')
    parser.add_argument('--hardware', action='store_true', help='Require actual Windows PCP; unavailable is failure')
    parser.add_argument('--receipt', type=Path, help='New private receipt retained outside temporary staging')
    args = parser.parse_args()
    fixture, producer = clean(args.fixture, FIXTURE), clean(args.producer, PRODUCER)
    if args.hardware and (os.name != 'nt' or not args.receipt or args.receipt.exists()):
        raise ValueError('Protected run requires Windows and a new caller-owned private receipt')
    env = {k: v for k, v in os.environ.items() if k not in (
        'CLASSPATH', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'DOTNET_STARTUP_HOOKS', 'RUBYOPT', 'RUBYLIB', 'NODE_OPTIONS', 'NODE_PATH')}
    with tempfile.TemporaryDirectory(prefix='zrotext-contact-managed-') as temporary:
        folder = Path(temporary)
        # Relocation tests a complete source/licensed artifact, never a private DLL lookup.
        source = args.origin_asset.resolve(strict=True)
        manifest = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
        builder = runpy.run_path(str(HERE / 'contact-origin/build.py'))
        if manifest['ada_revision'] != builder['REVISION'] or manifest['ada_version'] != '3.3.0':
            raise ValueError('Unexpected origin dependency')
        library = ('zrotext_contact_origin.dll' if os.name == 'nt' else
                   'libzrotext_contact_origin.dylib' if sys.platform == 'darwin' else 'libzrotext_contact_origin.so')
        required = {library, 'LICENSE', 'ADA-LICENSE-MIT', 'source/contact_origin.cpp', 'source/BUILDING.md',
                    *('source/' + name for name in builder['FILES'])}
        if manifest['library'] != library or set(manifest['sha256']) != required:
            raise ValueError('Incomplete origin source/license inventory')
        for name, (_, digest) in builder['FILES'].items():
            if hashlib.sha256((source / 'source' / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Origin dependency source changed')
        if (source / 'source/BUILDING.md').read_text(encoding='utf-8') != builder['BUILDING']:
            raise ValueError('Origin build recipe changed')
        for actual, expected in ((source / 'source/contact_origin.cpp', HERE / 'contact-origin/contact_origin.cpp'),
                                 (source / 'LICENSE', HERE.parents[2] / 'LICENSE'),
                                 (source / 'ADA-LICENSE-MIT', source / 'source/LICENSE-MIT')):
            if actual.read_bytes() != expected.read_bytes():
                raise ValueError('Origin wrapper or license changed')
        for name, digest in manifest['sha256'].items():
            target = (source / name).resolve(strict=True)
            if source not in target.parents or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise ValueError('Invalid origin asset inventory')
        asset = folder / 'origin'; shutil.copytree(source, asset)
        if args.language == 'java':
            jars = []
            for path, digest in (*runpy.run_path(str(HERE / 'original-http-run.py'))['JARS'], JNA):
                data = fetch(path, digest)
                target = folder / Path(path).name; target.write_bytes(data); jars.append(str(target))
            cp = os.pathsep.join([str(folder), *jars])
            sources = [HERE / 'java/HpkeRecipient.java', HERE / 'java/ManifestChain.java',
                       *sorted((HERE / 'java/contact').glob('*.java'))]
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-cp', cp, '-d', folder, *sources, env=env)
            command = ['java', '-cp', cp, 'org.zrotext.candidate.ContactTest', str(asset)]
        elif args.language == 'csharp':
            run('dotnet', 'build', HERE / 'csharp/contact/ContactTest.csproj', '--artifacts-path', folder / 'build', '-o', folder / 'bin', env=env)
            command = ['dotnet', str(folder / 'bin/ContactTest.dll'), str(asset)]
        else:
            command = [args.ruby, str(HERE / 'ruby/contact/test.rb'), str(asset)]
        command_file = folder / 'command.json'; command_file.write_text(json.dumps(command), encoding='utf-8')
        run(sys.executable, fixture / 'sdk/native/hpke-candidate/test-contact-field.py',
            '--producer', producer, '--command-file', command_file, env=env)
        missing = command[:-1] + [str(folder / 'missing-origin')]
        result = subprocess.run(missing, input='[]', text=True, encoding='utf-8', capture_output=True, env=env, timeout=20)
        if result.returncode == 0:
            raise AssertionError('Missing parser capability silently accepted')
        if args.hardware:
            record = json.loads(run('node', producer / 'sdk/native/sealed-candidate/python/contact-interop.mjs',
                                    capture_output=True, text=True, encoding='utf-8', env=env).stdout)
            if args.language == 'ruby':
                protected = [args.ruby, str(HERE / 'ruby/contact/protected_test.rb'), str(asset), str(args.receipt.resolve())]
            else:
                protected = command + ['--hardware', str(args.receipt.resolve())]
            # Receipt survives exceptions/timeouts; never infer deletion from child exit.
            output = run(*protected, input=json.dumps(record), text=True, encoding='utf-8', capture_output=True, env=env, timeout=90)
            value = json.loads(output.stdout)
            accepted = run('node', fixture / 'sdk/native/hpke-candidate/contact-field-interop.mjs', producer, '--consume',
                           input=json.dumps(value), text=True, encoding='utf-8', capture_output=True, env=env)
            if json.loads(accepted.stdout) != {'verified': True, 'fields': 3} or value['controls'] != 8:
                raise AssertionError('Protected field acceptance incomplete')
            if json.loads(args.receipt.read_text(encoding='utf-8'))['state'] != 'owned_key_deleted':
                raise AssertionError('Owned protected key cleanup pending')
            print('Protected contact: three independent field verifications; four retained worker slots; actual ten-second deadline; owned key deleted')


if __name__ == '__main__':
    main()
