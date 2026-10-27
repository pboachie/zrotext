"""Build source wheels, install offline, and import the generated Python SDK.

This qualifies local artifacts and injected synthetic HTTP, not publication.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv

ROOT = Path(__file__).resolve().parents[2]


def run(*args, **kwargs):
    subprocess.run(list(map(str, args)), check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        raise ValueError("Python 3.12 or newer is required")
    source = args.source.resolve()
    spec = importlib.util.spec_from_file_location("generation_policy", ROOT / "scripts/tungsten_sdk.py")
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    config = ROOT / "sdk/tungsten"
    policy.verify_source(source, json.loads((config / "generator.lock.json").read_text()))
    with tempfile.TemporaryDirectory(prefix="zrotext-python-consumer-") as temp:
        stage = Path(temp)
        consumer = stage / "consumer"
        venv.EnvBuilder(with_pip=True).create(consumer)
        python = consumer / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run(python, "-I", ROOT / "scripts/bootstrap_python_pip.py", cwd=stage)
        wheels = stage / "wheels"
        run(python, "-m", "pip", "--disable-pip-version-check", "wheel", "--wheel-dir", wheels,
            source / "runtimes/python", config / "generated/python", cwd=stage)
        run(python, "-m", "pip", "--disable-pip-version-check", "install", "--no-index", "--find-links", wheels,
            "zrotext-sdk", cwd=stage)
        run(python, "-I", "-c",
            "import importlib,pkgutil,zrotext_sdk; "
            "mods=list(pkgutil.walk_packages(zrotext_sdk.__path__,zrotext_sdk.__name__+'.')); "
            "[importlib.import_module(m.name) for m in mods]; print('Imported',len(mods),'SDK modules')",
            cwd=stage)
        run(python, "-I", config / "python-contract.py", cwd=stage)
    print("Python wheel and synthetic wire checks passed; registry and live HTTP were not tested")


if __name__ == "__main__":
    main()
