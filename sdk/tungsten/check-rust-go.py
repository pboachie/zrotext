"""Compile generated Rust SDK/CLI and Go against the locked runtime source.

This is source-build evidence only: temporary dependency overrides deliberately
avoid registry dependencies. No tracked/generated files or source are changed.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def run(args, **kwargs):
    subprocess.run([str(a) for a in args], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    spec = importlib.util.spec_from_file_location('generation_policy', ROOT / 'scripts/tungsten_sdk.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    config = ROOT / 'sdk/tungsten'
    policy.verify_source(source, json.loads((config / 'generator.lock.json').read_text()))
    with tempfile.TemporaryDirectory(prefix='zrotext-native-source-check-') as temporary:
        scratch = Path(temporary)
        for language in ('rust', 'go'):
            shutil.copytree(config / 'generated' / language, scratch / language,
                            ignore=shutil.ignore_patterns('target', '.git'))
        runtime = source / 'runtimes/rust/runtime'
        kit = source / 'runtimes/rust/cli-kit'
        manifest = scratch / 'rust/Cargo.toml'
        with manifest.open('a', encoding='utf-8') as output:
            output.write('\n[patch.crates-io]\n')
            output.write('tungsten-runtime = { path = ' + json.dumps(runtime.as_posix()) + ' }\n')
            output.write('tungsten-cli-kit = { path = ' + json.dumps(kit.as_posix()) + ' }\n')
        env = dict(os.environ, CARGO_TARGET_DIR=str(scratch / 'target'))
        run(['cargo', '+1.88.0', 'check', '--workspace', '--all-targets'], cwd=scratch / 'rust', env=env)
        run(['cargo', '+1.88.0', 'run', '-p', 'zrotext-api-cli', '--', '--help'], cwd=scratch / 'rust', env=env)
        run(['go', 'mod', 'edit', '-replace=github.com/pboachie/tungsten/runtimes/go=' + (source / 'runtimes/go').as_posix()], cwd=scratch / 'go')
        run(['go', 'test', './...'], cwd=scratch / 'go')
        run(['go', 'vet', './...'], cwd=scratch / 'go')
    print('Rust SDK/CLI and Go source-build checks passed; registry installation was not tested.')


if __name__ == '__main__':
    main()
