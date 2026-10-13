"""Build a relocatable licensed origin-parser asset from integrity-pinned source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
REVISION = '9c0370e26b9f9ac1c07c91c5bd7301fc3aaf8794'
FILES = {
    'ada.h': ('https://github.com/ada-url/ada/releases/download/v3.3.0/ada.h', '5f60f2708b7a6ff4ede1baa45b2ad2abc613c2db4483099fce8653b0cb0422ba'),
    'ada.cpp': ('https://github.com/ada-url/ada/releases/download/v3.3.0/ada.cpp', '1e3225743961998510c87c9aa59572ed441cf89d7e192e4b90d0754c2b74b94f'),
    'LICENSE-MIT': ('https://raw.githubusercontent.com/ada-url/ada/' + REVISION + '/LICENSE-MIT', 'af0d7d2cef91fc243cf4ad98570b03d1f26f5e0227cad0f5f4a7376e2feb3160'),
}


def build(output):
    output = output.resolve()
    root = HERE.parents[3]
    if output.exists() or output == root or root in output.parents:
        raise ValueError('Use a new directory outside the source checkout')
    with tempfile.TemporaryDirectory(prefix='zrotext-contact-origin-build-') as temporary:
        stage = Path(temporary)
        for name, (url, digest) in FILES.items():
            data = urllib.request.urlopen(url, timeout=60).read()
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('Unexpected Ada dependency bytes')
            (stage / name).write_bytes(data)
        shutil.copyfile(HERE / 'contact_origin.cpp', stage / 'contact_origin.cpp')
        if os.name == 'nt':
            # Caller selects an installed, trusted compiler environment. No system changes.
            compiler = shutil.which('cl')
            if not compiler:
                raise ValueError('Run from a Visual Studio x64 developer environment')
            artifact = 'zrotext_contact_origin.dll'
            command = [compiler, '/nologo', '/std:c++20', '/O2', '/EHsc', '/MT', '/LD',
                       'ada.cpp', 'contact_origin.cpp', '/link', '/OUT:' + artifact]
        else:
            compiler = shutil.which(os.environ.get('CXX', 'c++'))
            if not compiler:
                raise ValueError('C++20 compiler unavailable')
            artifact = 'libzrotext_contact_origin.dylib' if os.sys.platform == 'darwin' else 'libzrotext_contact_origin.so'
            command = [compiler, '-std=c++20', '-O2', '-fPIC', '-fvisibility=hidden',
                       '-dynamiclib' if os.sys.platform == 'darwin' else '-shared',
                       'ada.cpp', 'contact_origin.cpp', '-o', artifact]
        subprocess.run(command, cwd=stage, check=True)
        output.mkdir(parents=True)
        shutil.copyfile(stage / artifact, output / artifact)
        # Include complete corresponding source and notices with the native asset.
        sources = output / 'source'
        sources.mkdir()
        for name in (*FILES, 'contact_origin.cpp'):
            shutil.copyfile(stage / name, sources / name)
        shutil.copyfile(root / 'LICENSE', output / 'LICENSE')
        shutil.copyfile(stage / 'LICENSE-MIT', output / 'ADA-LICENSE-MIT')
        manifest = {'ada_version': '3.3.0', 'ada_revision': REVISION,
                    'scope': 'Candidate native canonical-origin parser; platform-specific, not a published SDK',
                    'library': artifact,
                    'sha256': {str(p.relative_to(output)).replace(os.sep, '/'): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in output.rglob('*') if p.is_file()}}
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        return output / artifact


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    print(build(parser.parse_args().out))
