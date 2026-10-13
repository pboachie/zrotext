"""Build locked generated native harnesses in isolation and run synthetic HTTP acceptance."""
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

    with tempfile.TemporaryDirectory(prefix="zrotext-native-wire-") as tmp:
        stage = Path(tmp)
        sdk = stage / "rust"
        shutil.copytree(config / "generated/rust", sdk, ignore=shutil.ignore_patterns("target", ".git"))
        harness = stage / "harness"
        harness.mkdir()
        shutil.copyfile(HERE / "rust-main.rs", harness / "main.rs")
        manifest = '\n'.join([
            '[package]', 'name="native-wire"', 'version="0.0.0"', 'edition="2024"',
            '[workspace]', '[[bin]]', 'name="native-wire"', 'path="main.rs"', '[dependencies]',
            'serde_json="1"', 'tokio={version="1", features=["macros","rt-multi-thread"]}',
            'tungsten-runtime="=0.1.0"',
            'zrotext-sdk={path="../rust/zrotext-sdk"}',
            '[patch.crates-io]',
            'tungsten-runtime={path='+json.dumps((source / 'runtimes/rust/runtime').as_posix())+'}',
        ])
        (harness / "Cargo.toml").write_text(manifest, encoding="utf-8")
        env = dict(os.environ, CARGO_TARGET_DIR=str(stage / "target"))
        subprocess.run(["cargo", "+1.88.0", "build"], cwd=harness, env=env, check=True)
        go = stage / "go"
        shutil.copytree(config / "generated/go", go)
        (go / "cmd/wire").mkdir(parents=True)
        shutil.copyfile(HERE / "go-main.go", go / "cmd/wire/main.go")
        subprocess.run(["go", "mod", "edit", "-replace=github.com/pboachie/tungsten/runtimes/go="+(source / "runtimes/go").as_posix()], cwd=go, check=True)
        suffix = ".exe" if os.name == "nt" else ""
        subprocess.run(["go", "build", "-o", stage / ("go-wire"+suffix), "./cmd/wire"], cwd=go, check=True)
        for binary in [stage / "target/debug" / ("native-wire"+suffix), stage / ("go-wire"+suffix)]:
            env["ZROTEXT_TEST_NATIVE"] = str(binary)
            env["ZROTEXT_NATIVE_LANGUAGE"] = "go" if binary.name.startswith("go-") else "rust"
            subprocess.run([sys.executable, HERE / "test_wire.py"], env=env, check=True)
            subprocess.run([sys.executable, HERE / "probe_redirect.py"], env=env, check=True)
    print("Native SDK source build and synthetic acceptance passed; no registry or deployed acceptance implied")

if __name__ == "__main__":
    main()
