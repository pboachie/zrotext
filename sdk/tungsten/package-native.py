"""Ordinary local registry consumers for generated Go and Rust packages."""
import copy
import functools
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import threading
import tomllib
import unittest
import zipfile

CRATES_IO = "https://github.com/rust-lang/crates.io-index"
CANDIDATES = {"tungsten-runtime", "tungsten-cli-kit", "zrotext-sdk", "zrotext-api-cli"}


def toml_value(value):
    if isinstance(value, dict):
        return "{ " + ", ".join(json.dumps(key) + " = " + toml_value(item)
                                 for key, item in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    return json.dumps(value)


def standalone_manifest(manifest, workspace, license_id):
    """Resolve workspace metadata and turn local crate paths into registry deps."""
    result = copy.deepcopy(manifest)
    for key, value in list(result["package"].items()):
        if isinstance(value, dict) and value.get("workspace"):
            result["package"][key] = workspace["package"][key]
    result["package"]["license"] = license_id
    result["package"]["publish"] = False
    # All four crates depend on the runtime's actual supported compiler floor.
    result["package"]["rust-version"] = "1.88"
    if result.get("lints", {}).get("workspace"):
        result["lints"] = workspace["lints"]
    for name, value in list(result.get("dependencies", {}).items()):
        if isinstance(value, dict) and value.get("workspace"):
            inherited = workspace["dependencies"][name]
            value = copy.deepcopy(inherited if isinstance(inherited, dict) else {"version": inherited})
        else:
            value = copy.deepcopy(value if isinstance(value, dict) else {"version": value})
        if name in CANDIDATES:
            value.pop("path", None)
            value["version"] = "=0.1.0"
            value["registry"] = "candidate"
        if "path" in value or "git" in value or "workspace" in value:
            raise ValueError("Unresolved source dependency")
        result["dependencies"][name] = value
    return result


def index_entry(manifest, checksum):
    package = manifest["package"]
    dependencies = []
    for name, value in manifest.get("dependencies", {}).items():
        dependencies.append({"name": name, "req": value["version"],
            "features": value.get("features", []), "optional": value.get("optional", False),
            "default_features": value.get("default-features", True), "target": None,
            "kind": "normal", "registry": None if name in CANDIDATES else CRATES_IO,
            "package": value.get("package")})
    return {"name": package["name"], "vers": package["version"], "deps": dependencies,
            "cksum": checksum, "features": manifest.get("features", {}), "yanked": False,
            "rust_version": package["rust-version"]}


def check_crate(archive, name, expected_license):
    prefix = name + "-0.1.0/"
    with tarfile.open(archive) as package:
        for member in package.getmembers():
            if not member.isfile() or not member.name.startswith(prefix) or ".." in member.name.split("/"):
                raise ValueError("Unexpected crate member")
        if package.extractfile(prefix + "LICENSE").read() != expected_license:
            raise ValueError("Incorrect crate license")
        metadata = tomllib.loads(package.extractfile(prefix + "Cargo.toml").read().decode())
        for dependency in metadata.get("dependencies", {}).values():
            if isinstance(dependency, dict) and ("path" in dependency or "git" in dependency):
                raise ValueError("Crate contains a source dependency")


class QuietRegistry(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def cargo_command(executable, env):
    if executable is None:
        return ["cargo", "+1.88.0"]
    executable = Path(executable).resolve()
    suffix = ".exe" if os.name == "nt" else ""
    compiler = executable.parent / ("rustc" + suffix)
    for command, prefix in ((executable, "cargo 1.88.0 "), (compiler, "rustc 1.88.0 ")):
        version = run(command, "--version", env=env, capture_output=True, text=True).stdout
        if not version.startswith(prefix):
            raise ValueError("Direct Cargo and rustc must both be Rust 1.88.0")
    env["RUSTC"] = str(compiler)
    env["RUSTDOC"] = str(executable.parent / ("rustdoc" + suffix))
    return [str(executable)]


def rust_package(stage, feed, cargo_executable=None):
    projects = stage / "projects"
    projects.mkdir()
    manifests = []
    for parent, names, license_id in (
        (stage / "runtime", ("runtime", "cli-kit"), "Apache-2.0"),
        (stage / "sdk", ("zrotext-sdk", "zrotext-api-cli"), "AGPL-3.0-only"),
    ):
        workspace = tomllib.loads((parent / "Cargo.toml").read_text())["workspace"]
        for name in names:
            source = parent / name
            manifest = standalone_manifest(tomllib.loads((source / "Cargo.toml").read_text()),
                                           workspace, license_id)
            destination = projects / manifest["package"]["name"]
            shutil.copytree(source, destination)
            shutil.copy2(parent / "LICENSE", destination / "LICENSE")
            (destination / "Cargo.toml").write_text("\n".join(
                json.dumps(key) + " = " + toml_value(value) for key, value in manifest.items()) + "\n")
            manifests.append((destination, manifest))
    # No source-replacement or patch table: this is an ordinary distinct Cargo
    # registry. Its index explicitly routes public transitive deps to crates.io.
    handler = functools.partial(QuietRegistry, directory=str(feed))
    server = http.server.ThreadingHTTPServer(("localhost", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = "http://localhost:" + str(server.server_port) + "/"
    (feed / "config.json").write_text(json.dumps({"dl": url + "crates/{crate}-{version}.crate"}) + "\n")
    cargo_home = stage / "cargo-home"
    cargo_home.mkdir()
    (cargo_home / "config.toml").write_text(
        '[registries.candidate]\nindex = "sparse+' + url + '"\n'
        '[resolver]\nincompatible-rust-versions = "fallback"\n')
    env = dict(os.environ, CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(stage / "target"),
               CARGO_BUILD_JOBS="2")
    try:
        cargo = cargo_command(cargo_executable, env)
        for project, manifest in manifests:
            run(*cargo, "package", "--no-verify", "--allow-dirty",
                "--manifest-path", project / "Cargo.toml", env=env, cwd=stage)
            name = manifest["package"]["name"]
            archive_name = name + "-0.1.0.crate"
            archive = stage / "target/package" / archive_name
            check_crate(archive, name, (project / "LICENSE").read_bytes())
            crates = feed / "crates"
            crates.mkdir(exist_ok=True)
            shutil.copy2(archive, crates / archive_name)
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            entry = feed / name[:2] / name[2:4] / name
            entry.parent.mkdir(parents=True, exist_ok=True)
            entry.write_text(json.dumps(index_entry(manifest, checksum)) + "\n")
        # Both original source and flattened packaging source are absent when
        # the clean consumer resolves and compiles the registry archives.
        shutil.rmtree(projects)
        shutil.rmtree(stage / "runtime")
        shutil.rmtree(stage / "sdk")
        consumer = stage / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text('''[package]
name = "zrotext-package-consumer"
version = "0.1.0"
edition = "2024"
rust-version = "1.88"
[dependencies]
zrotext-sdk = { version = "=0.1.0", registry = "candidate" }
tungsten-runtime = { version = "=0.1.0", registry = "candidate" }
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
''')
        (consumer / "src/main.rs").write_text('''fn main() {
let options = zrotext_sdk::ClientOptions { base_url: Some("https://sdk.example.invalid".into()), ..Default::default() };
let client = zrotext_sdk::ZrotextClient::new(options).expect("candidate client");
let _ = (client.public(), client.sealed(), client.workflow());
println!("Installed Rust client loaded");
}
''')
        # A new Cargo home prevents packaging resolution/cache from masking
        # missing registry entries or source files in the finished crates.
        fresh_home = stage / "consumer-cargo-home"
        fresh_home.mkdir()
        shutil.copy2(cargo_home / "config.toml", fresh_home / "config.toml")
        env["CARGO_HOME"] = str(fresh_home)
        run(*cargo, "generate-lockfile", env=env, cwd=consumer)
        run(*cargo, "run", "--locked", env=env, cwd=consumer)
        wire = Path(__file__).resolve().parent / "package-wire"
        (consumer / "src/bin").mkdir()
        shutil.copy2(wire / "rust-main.rs", consumer / "src/bin/archive-wire.rs")
        run(*cargo, "build", "--locked", "--bin", "archive-wire", env=env, cwd=consumer)
        suffix = ".exe" if os.name == "nt" else ""
        wire_checks(stage / "target/debug" / ("archive-wire" + suffix), "rust")
        run(*cargo, "install", "--locked", "--registry", "candidate", "--version", "0.1.0",
            "--root", stage / "installed", "zrotext-api-cli", env=env, cwd=consumer)
        binary = stage / "installed/bin" / ("zrotext-api.exe" if os.name == "nt" else "zrotext-api")
        run(binary, "--help", env=env, cwd=consumer)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def wire_checks(binary, language):
    wire = Path(__file__).resolve().parent / "package-wire/test_wire.py"
    spec = importlib.util.spec_from_file_location("installed_" + language + "_wire", wire)
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    checks.Wire.binary, checks.Wire.language = str(binary), language
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromModule(checks))
    if not result.wasSuccessful():
        raise ValueError("Installed " + language + " archive wire contracts failed")


def go_archive(project, feed):
    module_text = (project / "go.mod").read_text()
    if re.search(r"(?m)^\s*replace(?:\s|\()", module_text):
        raise ValueError("Package module must not contain replace directives")
    module = next(line.split()[1] for line in module_text.splitlines() if line.startswith("module "))
    version = "v0.1.0"
    destination = feed / module / "@v"
    destination.mkdir(parents=True)
    (destination / "list").write_text(version + "\n")
    (destination / (version + ".info")).write_text(json.dumps({
        "Version": version, "Time": "1970-01-01T00:00:00Z"}) + "\n")
    (destination / (version + ".mod")).write_bytes((project / "go.mod").read_bytes())
    with zipfile.ZipFile(destination / (version + ".zip"), "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(project.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(project).as_posix()
            # Only reviewed Go sources and runtime data needed by go:embed,
            # package metadata, and licenses belong in the module archive.
            if not (path.suffix in (".go", ".json") or relative in ("go.mod", "go.sum", "LICENSE", "README.md")):
                continue
            info = zipfile.ZipInfo(module + "@" + version + "/" + relative)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    return module


def go_package(stage, feed):
    modules = [go_archive(stage / name, feed) for name in ("runtime", "sdk")]
    for name in ("runtime", "sdk"):
        shutil.rmtree(stage / name)
    consumer = stage / "consumer"
    consumer.mkdir()
    (consumer / "go.mod").write_text(
        "module example.invalid/zrotext-consumer\n\ngo 1.22\n\nrequire " + modules[1] + " v0.1.0\n")
    (consumer / "main.go").write_text('''package main
import (
    "fmt"
    sdk "''' + modules[1] + '''"
    runtime "''' + modules[0] + '''"
)
func main() {
    client, err := sdk.New(runtime.ClientOptions{BaseURL: "https://sdk.example.invalid"})
    if err != nil { panic(err) }
    if client.Public() == nil || client.Sealed() == nil || client.Workflow() == nil { panic("missing namespace") }
    fmt.Println("Installed Go client loaded")
}
''')
    env = dict(os.environ, GOPROXY=feed.as_uri(), GOSUMDB="off", GOPRIVATE="", GONOPROXY="none",
               GONOSUMDB="", GOWORK="off", GOFLAGS="", GOENV="off", GOPATH=str(stage / "go-home"),
               GOMODCACHE=str(stage / "module-cache"), GOCACHE=str(stage / "build-cache"),
               GOTOOLCHAIN="local")
    run("go", "mod", "tidy", cwd=consumer, env=env)
    listing = run("go", "list", "-m", "-json", "all", cwd=consumer, env=env,
                  capture_output=True, text=True).stdout
    if '"Replace"' in listing:
        raise ValueError("Go consumer used a source replacement")
    run("go", "run", ".", cwd=consumer, env=env)
    wire = Path(__file__).resolve().parent / "package-wire"
    shutil.copy2(wire / "go-main.go", consumer / "main.go")
    binary = consumer / ("archive-wire.exe" if os.name == "nt" else "archive-wire")
    run("go", "build", "-o", binary, ".", cwd=consumer, env=env)
    wire_checks(binary, "go")
    run("go", "mod", "verify", cwd=consumer, env=env)
    # Retain ordinary module checksums, not temporary checkout/cache paths.
    shutil.copy2(consumer / "go.sum", feed / "consumer.go.sum")
