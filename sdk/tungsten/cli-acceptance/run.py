"""Build the locked generated CLI in isolation and run synthetic HTTP acceptance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--foundation", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    foundation, source = args.foundation.resolve(), args.source.resolve()
    dependency = json.loads((HERE / "dependency.json").read_text())
    config = foundation / "sdk/tungsten"
    inventory = (config / "generated.lock.json").read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(inventory).hexdigest() != dependency["inventory_sha256"]:
        raise ValueError("Foundation inventory differs from the reviewed dependency")
    spec = importlib.util.spec_from_file_location("generation_policy", foundation / "scripts/tungsten_sdk.py")
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    policy.verify_source(source, {"revision": dependency["runtime_revision"], "runtime_revision": dependency["runtime_revision"]})
    if policy.output_inventory(config / "generated", config / "extensions") != json.loads(inventory):
        raise ValueError("Generated artifacts differ from the reviewed inventory")
    with tempfile.TemporaryDirectory(prefix="zrotext-cli-acceptance-") as tmp:
        stage = Path(tmp)
        sdk = stage / "rust"
        shutil.copytree(config / "generated/rust", sdk, ignore=shutil.ignore_patterns("target", ".git"))
        with (sdk / "Cargo.toml").open("a", encoding="utf-8") as output:
            output.write("\n[patch.crates-io]\n")
            for package, directory in [("tungsten-runtime", "runtime"), ("tungsten-cli-kit", "cli-kit")]:
                output.write(package + " = { path = " + json.dumps((source / "runtimes/rust" / directory).as_posix()) + " }\n")
        env = dict(os.environ, CARGO_TARGET_DIR=str(stage / "target"))
        subprocess.run(["cargo", "+1.88.0", "build", "-p", "zrotext-api-cli"], cwd=sdk, env=env, check=True)
        suffix = ".exe" if os.name == "nt" else ""
        spec = importlib.util.spec_from_file_location("cli_acceptance_tests", HERE / "test_cli.py")
        tests = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tests)
        tests.Acceptance.binary = stage / "target/debug" / ("zrotext-api" + suffix)
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromModule(tests))
        if not result.wasSuccessful():
            raise ValueError("CLI acceptance failed")
    print("CLI source build and synthetic acceptance passed; no registry or deployed acceptance implied")

if __name__ == "__main__":
    main()
