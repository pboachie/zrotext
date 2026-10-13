"""Qualify licensed raw webhook archives through fresh ordinary consumers."""
import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent
VECTOR_REVISION = "da72e1ecbde5f5c81febf1562f9f33b3ea03101a"
MODULE = "github.com/pboachie/zrotext/sdk/native/go"
CRATE = "zrotext-webhook"
VERSION = "0.1.0"
FILES = {
    "rust": ("Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "src/lib.rs"),
    "go": ("go.mod", "LICENSE", "README.md", "webhook.go"),
}


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def environment(stage, vector):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CARGO_", "RUST", "GO"))}
    env.update(ZROTEXT_WEBHOOK_VECTOR_FILE=str(vector), RUSTUP_TOOLCHAIN="1.88.0",
               CARGO_HOME=str(stage / "cargo-home"), CARGO_TARGET_DIR=str(stage / "target"),
               GOPATH=str(stage / "go-home"), GOMODCACHE=str(stage / "go-modules"), GOCACHE=str(stage / "go-cache"),
               GOWORK="off", GOENV="off", GOFLAGS="", GOTOOLCHAIN="local", GOPRIVATE="", GONOPROXY="none",
               GONOSUMDB=MODULE, GOSUMDB="sum.golang.org")
    return env


def stage_source(stage, language):
    project = stage / "source"
    for name in FILES[language]:
        source = ROOT / language / name
        if not source.is_file() or source.is_symlink():
            raise ValueError("Expected ordinary source file")
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return project


class QuietRegistry(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def rust(stage, output, env):
    for tool in ("cargo", "rustc"):
        if not run(tool, "--version", env=env, capture_output=True, text=True).stdout.startswith(tool + " 1.88.0 "):
            raise ValueError("Rust/Cargo 1.88.0 required")
    source = stage_source(stage, "rust")
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    if manifest["package"]["name"] != CRATE or manifest["package"]["version"] != VERSION:
        raise ValueError("Unexpected crate coordinate")
    dependencies = []
    for name, version in manifest["dependencies"].items():
        if not isinstance(version, str):
            raise ValueError("Only ordinary version dependencies accepted")
        dependencies.append({"name": name, "req": version, "features": [], "optional": False,
                             "default_features": True, "target": None, "kind": "normal",
                             "registry": "https://github.com/rust-lang/crates.io-index"})
    run("cargo", "package", "--locked", "--allow-dirty", "--no-verify", cwd=source, env=env)
    artifact = stage / "target/package" / (CRATE + "-" + VERSION + ".crate")
    with tarfile.open(artifact) as archive:
        prefix = CRATE + "-" + VERSION + "/"
        expected = {prefix + name for name in (*FILES["rust"], "Cargo.toml.orig")}
        members = archive.getmembers()
        if len(members) != len(expected) or {m.name for m in members} != expected or not all(m.isfile() for m in members):
            raise ValueError("Unexpected Rust archive inventory")
        if archive.extractfile(prefix + "LICENSE").read() != (source / "LICENSE").read_bytes():
            raise ValueError("License mismatch")
    result = output / artifact.name
    shutil.copy2(artifact, result)
    feed = stage / "registry"
    (feed / "crates").mkdir(parents=True)
    shutil.copy2(artifact, feed / "crates" / artifact.name)
    server = http.server.ThreadingHTTPServer(("localhost", 0), functools.partial(QuietRegistry, directory=str(feed)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = "http://localhost:" + str(server.server_port) + "/"
        (feed / "config.json").write_text(json.dumps({"dl": url + "crates/{crate}-{version}.crate"}))
        index = feed / CRATE[:2] / CRATE[2:4] / CRATE
        index.parent.mkdir(parents=True)
        index.write_text(json.dumps({"name": CRATE, "vers": VERSION, "deps": dependencies,
            "cksum": hashlib.sha256(result.read_bytes()).hexdigest(), "features": {}, "yanked": False, "rust_version": "1.88"}) + "\n")
        consumer = stage / "consumer"
        (consumer / "tests").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text('''[package]
name = "installed-webhook-consumer"
version = "0.0.0"
edition = "2024"
[dependencies]
zrotext-webhook = { version = "=0.1.0", registry = "candidate" }
''')
        shutil.copy2(ROOT / "rust/tests/webhook.rs", consumer / "tests/native.rs")
        shutil.copy2(ROOT / "rust/package-consumer.rs", consumer / "tests/vectors.rs")
        shutil.rmtree(source)
        shutil.rmtree(stage / "cargo-home")
        shutil.rmtree(stage / "target")
        home = stage / "consumer-cargo-home"
        home.mkdir()
        (home / "config.toml").write_text('[registries.candidate]\nindex = "sparse+' + url + '"\n')
        env.update(CARGO_HOME=str(home), CARGO_TARGET_DIR=str(stage / "consumer-target"))
        run("cargo", "test", cwd=consumer, env=env)
        metadata = json.loads(run("cargo", "metadata", "--locked", "--format-version", "1", cwd=consumer, env=env, capture_output=True, text=True).stdout)
        for package in metadata["packages"]:
            expected_source = (None if package["name"] == "installed-webhook-consumer" else
                               "sparse+" + url if package["name"] == CRATE else
                               "registry+https://github.com/rust-lang/crates.io-index")
            if package["source"] != expected_source:
                raise ValueError("Unexpected consumer dependency source")
        shutil.copy2(consumer / "Cargo.lock", output / "consumer.Cargo.lock")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    return result


def go(stage, output, env):
    if "go1.22.12 " not in run("go", "version", env=env, capture_output=True, text=True).stdout:
        raise ValueError("Go 1.22.12 required")
    source = stage_source(stage, "go")
    if (source / "go.mod").read_text().split() != ["module", MODULE, "go", "1.22"]:
        raise ValueError("Expected dependency-free module without overrides")
    feed = stage / "feed"
    destination = feed / MODULE / "@v"
    destination.mkdir(parents=True)
    version = "v" + VERSION
    (destination / "list").write_text(version + "\n")
    (destination / (version + ".info")).write_text(json.dumps({"Version": version, "Time": "1970-01-01T00:00:00Z"}))
    (destination / (version + ".mod")).write_bytes((source / "go.mod").read_bytes())
    artifact = destination / (version + ".zip")
    with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in FILES["go"]:
            info = zipfile.ZipInfo(MODULE + "@" + version + "/" + name)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (source / name).read_bytes())
    result = output / (CRATE + "-go-" + version + ".zip")
    shutil.copy2(artifact, result)
    consumer = stage / "consumer"
    consumer.mkdir()
    (consumer / "go.mod").write_text("module example.invalid/webhook-consumer\n\ngo 1.22\n\nrequire " + MODULE + " " + version + "\n")
    native = (ROOT / "go/webhook_test.go").read_text()
    if not native.startswith("package webhook\n"):
        raise ValueError("Native test adapter no longer matches")
    (consumer / "native_test.go").write_text(native.replace("package webhook\n", 'package webhook_test\n\nimport . "' + MODULE + '"\n', 1))
    shutil.copy2(ROOT / "go/package-consumer.go.txt", consumer / "vectors_test.go")
    shutil.rmtree(source)
    env["GOPROXY"] = feed.as_uri()
    run("go", "mod", "tidy", cwd=consumer, env=env)
    listing = run("go", "list", "-m", "-json", "all", cwd=consumer, env=env, capture_output=True, text=True).stdout
    if '"Replace"' in listing:
        raise ValueError("Unexpected source replacement")
    run("go", "test", "-v", "./...", cwd=consumer, env=env)
    run("go", "mod", "verify", cwd=consumer, env=env)
    shutil.copy2(consumer / "go.sum", output / "consumer.go.sum")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("rust", "go"), required=True)
    parser.add_argument("--vectors", type=Path, required=True, help="Exact reviewed shared-vector checkout")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    if args.output.is_relative_to(ROOT.parents[1]):
        raise ValueError("Use a new artifact directory outside the public checkout")
    vectors = args.vectors.resolve()
    if run("git", "-C", vectors, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip() != VECTOR_REVISION:
        raise ValueError("Unexpected vector revision")
    run("git", "-C", vectors, "diff", "--quiet", "HEAD", "--")
    vector = vectors / "sdk/native/webhook-vectors.tsv"
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="zrotext-webhook-package-") as temporary:
        stage = Path(temporary)
        env = environment(stage, vector)
        artifact = (rust if args.language == "rust" else go)(stage, args.output, env)
        report = {"experimental": True, "published": False, "language": args.language,
                  "license": "AGPL-3.0-only", "version": VERSION, "artifact": artifact.name,
                  "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                  "shared_vector_revision": VECTOR_REVISION, "native_vector_cases": 16,
                  "unsigned_clock_boundary_refusals": 1, "native_test_groups": 3,
                  "source_removed_before_consumer": True, "ordinary_registry_consumer": True}
        (args.output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
