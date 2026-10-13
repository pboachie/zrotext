"""Exercise managed accepted-history restart, process CAS and interrupted-append refusal."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
PIN = '72124e1a3ff28e782f870eeddbdc33cacf8ca3b4'


def run(*args, **kw):
    return subprocess.run(list(map(str, args)), check=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=('java', 'csharp', 'ruby'), required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--ruby', default='ruby')
    args = parser.parse_args(); producer = args.producer.resolve()
    if run('git', '-C', producer, 'rev-parse', 'HEAD', capture_output=True, text=True).stdout.strip() != PIN:
        raise ValueError('Unexpected maintained producer revision')
    run('git', '-C', producer, 'diff', '--quiet', 'HEAD', '--')
    env = {k: v for k, v in os.environ.items() if k not in ('NODE_OPTIONS', 'NODE_PATH', 'CLASSPATH',
           'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'DOTNET_STARTUP_HOOKS', 'RUBYOPT', 'RUBYLIB')}
    spec = importlib.util.spec_from_file_location('original', HERE / 'original-reply-run.py')
    original = importlib.util.module_from_spec(spec); spec.loader.exec_module(original)
    fixture = json.loads(run('node', producer / 'sdk/native/sealed-candidate/python/produce-selected-reply02.mjs',
                            capture_output=True, text=True, encoding='utf-8', env=env).stdout)
    wire = original.rows(fixture)
    with tempfile.TemporaryDirectory(prefix='zrotext-original-history-') as folder:
        temp = Path(folder)
        if args.language == 'java':
            java = HERE / 'java'
            sources = [java / name for name in ('HpkeRecipient.java', 'ManifestChain.java', 'SignedEnvelope.java',
                       'reader/OriginalReplyReader.java', 'original-history/OriginalReplyCheckpoint.java',
                       'original-history/OriginalHistoryTest.java')]
            sources.append(HERE.parent / 'crypto-candidate/java/CandidateBody.java')
            run('javac', '--release', '17', '-Xlint:all', '-Werror', '-d', temp, *sources, env=env)
            command = ['java', '-cp', str(temp), 'org.zrotext.candidate.OriginalHistoryTest']
        elif args.language == 'csharp':
            run('dotnet', 'build', HERE / 'csharp/original-history/OriginalHistoryTest.csproj', '-o', temp, env=env)
            command = ['dotnet', str(temp / 'OriginalHistoryTest.dll')]
        else:
            command = [args.ruby, str(HERE / 'ruby/original-history/test.rb')]
        path = temp / 'history.dat'
        def execute(mode, target=path):
            return subprocess.run(command + [mode, str(target)], input=wire, text=True, encoding='utf-8',
                                  capture_output=True, timeout=60, env=env)
        result = execute('--exercise'); result.check_returncode(); print(result.stdout.strip())
        # Separate simultaneous processes must not both commit the same revision.
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: execute('--advance'), range(2)))
        if sorted(r.returncode for r in results) != [0, 3]:
            raise RuntimeError('Expected one native process CAS winner and one refusal: ' +
                               ' '.join(r.stderr for r in results))
        result = execute('--verify'); result.check_returncode(); print(result.stdout.strip())
        interrupted = temp / 'interrupted.dat'; shutil.copyfile(path, interrupted)
        if execute('--partial', interrupted).returncode != 19:
            raise RuntimeError('Expected abrupt native child exit after partial append')
        result = execute('--refused', interrupted); result.check_returncode(); print(result.stdout.strip())
        result = execute('--verify'); result.check_returncode()
        print('Process CAS, fresh restart and fail-closed interrupted append passed')


if __name__ == '__main__':
    main()
