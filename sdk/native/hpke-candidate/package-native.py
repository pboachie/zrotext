"""Build experimental native archives and qualify ordinary installed consumers.

No publication, dependency replacement, private-source injection or protected
capability claim on hosts without a qualified native provider.
"""
import argparse
import functools
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent
MODULE = "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
CRATE = "zrotext-hpke-candidate"
VERSION = "0.1.0"
PRODUCERS = {
    "archive": "a13ea1e3d6f6db594485c19b36c43fe642e67c7a",
    "election": "304d512b7a420a3102278f32baed095f3e778989",
    "original": "72124e1a3ff28e782f870eeddbdc33cacf8ca3b4",
    "template": "26e876da9f34372d9cf26511993cf633971e0037",
    "save_oracle": "5a25bac026bebee5eba20dc6048ddc1c773c41ed",
    "opening_oracle": "c843543f13e3bbd6ac17a260a4b0523f0748324f",
    "authoring_oracle": "059556de2fe314ec0d88833a8d3e4d6ee41a8066",
    "contact": "ccf28fe445ba959aa01d99fed6bd9ee3188b749c",
    "context": "7e61c5b2461c82a5fbd05e62d06d14e34a0424d6",
}
HARNESSES = ("journal", "root", "cng", "compose", "compose02", "original", "reply_checkpoint",
             "reply_http", "reply_current", "reply_read", "reply_page", "reply_consumption", "reply_proposal",
             "template", "template_crypto", "owner_template", "template_save", "template_opening", "template_authoring", "contact", "contact_mutation", "contact_history", "workflow_context")
ORIGINAL_TLS = ("http", "current", "read", "page", "consumption", "proposal")


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def source_files(language):
    """Closed archive surface; harnesses and build outputs are never shipped."""
    project = ROOT / language
    names = ["LICENSE", "README.md"]
    if language == "rust":
        names += ["Cargo.toml", "Cargo.lock"]
        names += [p.relative_to(project).as_posix() for p in sorted((project / "src").glob("*.rs"))]
    else:
        names += ["go.mod", "go.sum"]
        names += [p.name for p in sorted(project.glob("*.go")) if not p.name.endswith("_test.go")]
    for name in names:
        path = project / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("Archive requires ordinary reviewed file: " + name)
    return names


def stage_sources(language, stage):
    project = stage / "source"
    for name in source_files(language):
        destination = project / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / language / name, destination)
    return project


def safe_env():
    prefixes = ("CARGO_", "RUST", "GO", "NODE_")
    return {k: v for k, v in os.environ.items() if not k.startswith(prefixes)}


def index_entry(manifest, checksum):
    deps = []
    for section, kind in (("dependencies", "normal"), ("dev-dependencies", "dev")):
        for name, value in manifest.get(section, {}).items():
            value = {"version": value} if isinstance(value, str) else value
            if set(value) - {"version", "features", "default-features", "optional"}:
                raise ValueError("Unexpected dependency source/options")
            deps.append({"name": name, "req": value["version"], "features": value.get("features", []),
                         "optional": value.get("optional", False), "default_features": value.get("default-features", True),
                         "target": None, "kind": kind, "registry": "https://github.com/rust-lang/crates.io-index"})
    return {"name": CRATE, "vers": VERSION, "deps": deps, "cksum": checksum,
            "features": {}, "yanked": False, "rust_version": manifest["package"]["rust-version"]}


class QuietRegistry(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def rust_package(stage, output):
    project = stage_sources("rust", stage)
    manifest = tomllib.loads((project / "Cargo.toml").read_text())
    if manifest["package"]["name"] != CRATE or manifest["package"]["version"] != VERSION:
        raise ValueError("Unexpected experimental package coordinate")
    env = safe_env()
    env.update(CARGO_HOME=str(stage / "packaging-home"), CARGO_TARGET_DIR=str(stage / "packaging-target"), RUSTUP_TOOLCHAIN="1.97.1")
    if not run("cargo", "--version", capture_output=True, text=True).stdout.startswith("cargo 1.97.1 "):
        raise ValueError("Cargo 1.97.1 required")
    if not run("rustc", "--version", capture_output=True, text=True).stdout.startswith("rustc 1.97.1 "):
        raise ValueError("Rust 1.97.1 required")
    run("cargo", "package", "--locked", "--allow-dirty", "--no-verify", cwd=project, env=env)
    artifact = stage / "packaging-target/package" / (CRATE + "-" + VERSION + ".crate")
    with tarfile.open(artifact) as archive:
        members = archive.getmembers()
        allowed = set(source_files("rust")) | {"Cargo.toml.orig"}
        prefix = CRATE + "-" + VERSION + "/"
        for member in members:
            if not member.isfile() or not member.name.startswith(prefix) or member.name[len(prefix):] not in allowed:
                raise ValueError("Unexpected Rust archive member")
        if archive.extractfile(prefix + "LICENSE").read() != (project / "LICENSE").read_bytes():
            raise ValueError("Rust license differs")
    result = output / artifact.name
    shutil.copy2(artifact, result)
    feed = stage / "registry"
    (feed / "crates").mkdir(parents=True)
    shutil.copy2(result, feed / "crates" / result.name)
    server = http.server.ThreadingHTTPServer(("localhost", 0), functools.partial(QuietRegistry, directory=str(feed)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = "http://localhost:" + str(server.server_port) + "/"
        (feed / "config.json").write_text(json.dumps({"dl": url + "crates/{crate}-{version}.crate"}))
        entry = feed / CRATE[:2] / CRATE[2:4] / CRATE
        entry.parent.mkdir(parents=True)
        entry.write_text(json.dumps(index_entry(manifest, hashlib.sha256(result.read_bytes()).hexdigest())) + "\n")
        consumer = stage / "consumer"
        (consumer / "src/bin").mkdir(parents=True)
        for name in HARNESSES:
            shutil.copy2(ROOT / "rust/examples" / (name + ".rs"), consumer / "src/bin" / (name + ".rs"))
        shutil.copytree(ROOT / "rust/examples/read_custody", consumer / "src/bin/read_custody")
        shutil.copytree(ROOT / "rust/examples/template_custody", consumer / "src/bin/template_custody")
        shutil.copytree(ROOT / "rust/examples/opening_custody", consumer / "src/bin/opening_custody")
        shutil.copytree(ROOT / "rust/examples/contact_custody", consumer / "src/bin/contact_custody")
        shutil.copytree(ROOT / "rust/examples/contact_mutation_custody", consumer / "src/bin/contact_mutation_custody")
        shutil.copytree(ROOT / "rust/examples/context_custody", consumer / "src/bin/context_custody")
        (consumer / "Cargo.toml").write_text('''[package]
name = "native-installed-consumer"
version = "0.0.0"
edition = "2024"
[dependencies]
zrotext-hpke-candidate = { version = "=0.1.0", registry = "candidate" }
base64 = "0.22"
serde_json = "1"
getrandom = "0.4"
p256 = { version = "0.14.0", features = ["ecdh", "ecdsa"] }
zeroize = "1.9.0"
rusqlite = { version = "=0.40.2", features = ["bundled"] }
''')
        shutil.rmtree(project)
        shutil.rmtree(stage / "packaging-home")
        shutil.rmtree(stage / "packaging-target")
        home = stage / "consumer-home"
        home.mkdir()
        (home / "config.toml").write_text('[registries.candidate]\nindex = "sparse+' + url + '"\n')
        env.update(CARGO_HOME=str(home), CARGO_TARGET_DIR=str(stage / "consumer-target"), CARGO_BUILD_JOBS="2")
        run("cargo", "build", "--bins", cwd=consumer, env=env)
        metadata = json.loads(run("cargo", "metadata", "--locked", "--format-version", "1", cwd=consumer, env=env, capture_output=True, text=True).stdout)
        for package in metadata["packages"]:
            expected = (None if package["name"] == "native-installed-consumer" else
                        "sparse+" + url if package["name"] == CRATE else
                        "registry+https://github.com/rust-lang/crates.io-index")
            if package["source"] != expected:
                raise ValueError("Consumer resolved an unexpected dependency source: " + package["name"])
        shutil.copy2(consumer / "Cargo.lock", output / "consumer.Cargo.lock")
        yield {name: stage / "consumer-target/debug" / (name + (".exe" if os.name == "nt" else "")) for name in HARNESSES}, result
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def go_package(stage, output):
    project = stage_sources("go", stage)
    text = (project / "go.mod").read_text()
    if "replace" in text or not text.startswith("module " + MODULE + "\n"):
        raise ValueError("Unexpected module or replacement directive")
    feed = stage / "feed"
    destination = feed / MODULE / "@v"
    destination.mkdir(parents=True)
    version = "v" + VERSION
    (destination / "list").write_text(version + "\n")
    (destination / (version + ".info")).write_text(json.dumps({"Version": version, "Time": "1970-01-01T00:00:00Z"}))
    (destination / (version + ".mod")).write_bytes((project / "go.mod").read_bytes())
    artifact = destination / (version + ".zip")
    with zipfile.ZipFile(artifact, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in source_files("go"):
            info = zipfile.ZipInfo(MODULE + "@" + version + "/" + name)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (project / name).read_bytes())
    result = output / ("zrotext-hpke-candidate-go-" + version + ".zip")
    shutil.copy2(artifact, result)
    consumer = stage / "consumer"
    consumer.mkdir()
    (consumer / "go.mod").write_text("module example.invalid/native-consumer\n\ngo 1.26.0\n\nrequire " + MODULE + " " + version + "\n")
    for name in HARNESSES:
        shutil.copytree(ROOT / "go/cmd" / name.replace("_", "-"), consumer / "cmd" / name)
    shutil.rmtree(project)
    env = safe_env()
    env.update(GOPROXY=feed.as_uri() + ",https://proxy.golang.org", GOSUMDB="sum.golang.org", GONOSUMDB=MODULE,
               GOPRIVATE="", GONOPROXY="none", GOWORK="off", GOFLAGS="", GOENV="off", GOTOOLCHAIN="local",
               GOPATH=str(stage / "go-home"), GOMODCACHE=str(stage / "module-cache"), GOCACHE=str(stage / "build-cache"))
    if "go1.26.9 " not in run("go", "version", capture_output=True, text=True).stdout:
        raise ValueError("Go 1.26.9 required")
    run("go", "mod", "tidy", cwd=consumer, env=env)
    listing = run("go", "list", "-m", "-json", "all", cwd=consumer, env=env, capture_output=True, text=True).stdout
    if '"Replace"' in listing:
        raise ValueError("Consumer resolved a replacement")
    binaries = {}
    for name in HARNESSES:
        binaries[name] = stage / (name + (".exe" if os.name == "nt" else ""))
        run("go", "build", "-o", binaries[name], "./cmd/" + name, cwd=consumer, env=env)
    run("go", "mod", "verify", cwd=consumer, env=env)
    shutil.copy2(consumer / "go.sum", output / "consumer.go.sum")
    yield binaries, result


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def original_acceptance(binaries, producer):
    """Every executable comes from the ordinary installed consumer build."""
    env = safe_env()
    fixture = run("node", producer / "sdk/native/sealed-candidate/python/produce-selected-reply02.mjs",
                  env=env, capture_output=True, text=True).stdout
    for name in ("original", "reply_checkpoint"):
        run(binaries[name], input=fixture, text=True, timeout=90)
    for name in ORIGINAL_TLS:
        argv = [sys.executable, ROOT / ("test-original-" + name + ".py"),
                "--binary", binaries["reply_" + name]]
        if name != "http":
            argv += ["--producer", producer]
        run(*argv, env=env)


def template_acceptance(binaries, original, template, *, hardware=False):
    """Reuse independent oracles against installed consumer executables only."""
    env = safe_env()
    if not hardware:
        run(sys.executable, ROOT / "test-template-content.py", "--producer", original,
            "--binary", binaries["template"], env=env)
    argv = [sys.executable, ROOT / "test-template-crypto.py", "--producer", template,
            "--binary", binaries["template_crypto"]]
    if hardware:
        argv.append("--hardware")
    run(*argv, env=env)
    if hardware:
        run(*argv, "--fail-setup", env=env)


def owner_template_acceptance(binaries, template, save_oracle, deadline_case_ms):
    """Cold reads and explicit save recovery use only installed public APIs."""
    common = ["--producer", template, "--deadline-case-ms", str(deadline_case_ms)]
    run(sys.executable, ROOT / "test-owner-template.py", *common,
        "--binary", binaries["owner_template"], env=safe_env())
    run(sys.executable, ROOT / "test-template-save.py", *common,
        "--save-oracle", save_oracle, "--binary", binaries["template_save"], env=safe_env())


def template_opening_acceptance(binaries, template, opening_oracle, deadline_case_ms, hardware=False):
    """Opening and owned-key cleanup run against the installed public API."""
    if hardware:
        run(sys.executable, ROOT / "test-template-opening-hardware.py", "--producer", opening_oracle,
            "--binary", binaries["template_opening"], env=safe_env())
    else:
        run(sys.executable, ROOT / "test-template-opening.py", "--producer", template,
            "--opening-oracle", opening_oracle, "--deadline-case-ms", str(deadline_case_ms),
            "--binary", binaries["template_opening"], env=safe_env())


def template_authoring_acceptance(binaries, template, authoring_oracle):
    """Reviewed preparation and explicit persistence use installed public APIs."""
    run(sys.executable, ROOT / "test-template-authoring.py", "--producer", template,
        "--authoring-oracle", authoring_oracle, "--binary", binaries["template_authoring"], env=safe_env())


def contact_acceptance(binaries, contact, hardware=False):
    """Historical integrity and domain-limited custody through installed APIs."""
    script = "test-contact-hardware.py" if hardware else "test-contact-field.py"
    run(sys.executable, ROOT / script, "--producer", contact,
        "--binary", binaries["contact"], env=safe_env())
    run(sys.executable, ROOT / ("test-contact-hardware.py" if hardware else "test-contact-mutation.py"),
        "--producer", contact, "--binary", binaries["contact_mutation"],
        *(["--mutation"] if hardware else []), env=safe_env())
    if not hardware:
        run(sys.executable, ROOT / "test-contact-history.py", "--producer", contact,
            "--binary", binaries["contact_history"], env=safe_env())


def context_acceptance(binaries, context, hardware=False):
    """Explicit owner/integration roles through ordinary installed public APIs."""
    for role in (2, 3):
        flags = ["--hardware"] if hardware else []
        run(sys.executable, ROOT / "test-workflow-context.py", "--producer", context,
            "--binary", binaries["workflow_context"], "--role", str(role), *flags, env=safe_env())
        if hardware:
            run(sys.executable, ROOT / "test-workflow-context.py", "--producer", context,
                "--binary", binaries["workflow_context"], "--role", str(role),
                "--hardware", "--fail-setup", env=safe_env())


def acceptance(binaries, archive, election, original, template, save_oracle, opening_oracle, authoring_oracle, contact, context, deadline_case_ms):
    env = safe_env()
    fixture = run("node", election / "sdk/native/sealed-candidate/python/produce-election03.mjs", env=env, capture_output=True, text=True).stdout
    run(binaries["journal"], input=fixture, text=True)
    fixture = run("node", archive / "sdk/native/sealed-candidate/python/produce-fixture.mjs", env=env, capture_output=True, text=True).stdout
    fixture = run("node", ROOT / "root-controls.mjs", archive, input=fixture, env=env, capture_output=True, text=True).stdout
    run(binaries["root"], input=fixture, text=True)
    contact_acceptance(binaries, contact)
    context_acceptance(binaries, context)
    template_acceptance(binaries, original, template)
    owner_template_acceptance(binaries, template, save_oracle, deadline_case_ms)
    template_opening_acceptance(binaries, template, opening_oracle, deadline_case_ms)
    template_authoring_acceptance(binaries, template, authoring_oracle)
    original_acceptance(binaries, original)
    qualified = False
    if os.name == "nt":
        results = [load("run-cng").exercise(binaries["cng"], archive, 2),
                   load("run-cng").exercise(binaries["cng"], election, 3),
                   load("run-compose").exercise(binaries["compose"], election),
                   load("run-compose02").exercise(binaries["compose02"], archive)]
        original_protected = load("run-cng").exercise(binaries["cng"], original, original=True)
        results.append(original_protected)
        if original_protected:
            run(sys.executable, ROOT / "test-original-read.py", "--binary", binaries["reply_read"],
                "--producer", original, "--hardware", env=env)
            template_acceptance(binaries, original, template, hardware=True)
            template_opening_acceptance(binaries, template, opening_oracle, deadline_case_ms, hardware=True)
            contact_acceptance(binaries, contact, hardware=True)
            context_acceptance(binaries, context, hardware=True)
        qualified = all(results)
    return qualified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("rust", "go"), required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--election", type=Path, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--save-oracle", type=Path, required=True)
    parser.add_argument("--opening-oracle", type=Path, required=True)
    parser.add_argument("--authoring-oracle", type=Path, required=True)
    parser.add_argument("--contact", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--owner-deadline-case-ms", type=int, default=100,
                        help="Declared caller deadline for post-handshake owner-template fixture cases (100..2000)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-protected", action="store_true")
    args = parser.parse_args()
    if not 100 <= args.owner_deadline_case_ms <= 2000:
        parser.error("--owner-deadline-case-ms must be 100..2000")
    for name, revision in PRODUCERS.items():
        path = getattr(args, name).resolve()
        if run("git", "-C", path, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip() != revision:
            raise ValueError("Unexpected producer revision")
        run("git", "-C", path, "diff", "--quiet", "HEAD", "--")
        setattr(args, name, path)
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="zrotext-native-package-") as directory:
        package = rust_package if args.language == "rust" else go_package
        for binaries, artifact in package(Path(directory), args.output):
            qualified = acceptance(binaries, args.archive, args.election, args.original, args.template,
                                   args.save_oracle, args.opening_oracle, args.authoring_oracle, args.contact, args.context, args.owner_deadline_case_ms)
            report = {"experimental": True, "published": False, "language": args.language,
                      "version": VERSION, "archive": artifact.name, "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                      "license": "AGPL-3.0-only", "producer_revisions": PRODUCERS,
                      "runtime": "Rust 1.97.1" if args.language == "rust" else "Go 1.26.9",
                      "source_inventory": {name: hashlib.sha256((ROOT / args.language / name).read_bytes()).hexdigest()
                                           for name in source_files(args.language)},
                      "ordinary_registry_consumer": True, "staged_library_sources_removed": True,
                      "journal_root_acceptance": True,
                      "original_acceptance": {"reader_checkpoint": True, "tls_suites": list(ORIGINAL_TLS)},
                      "template_acceptance": {"content_segments": True, "software_interop": True},
                      "owner_template_acceptance": {"cold_tls": True, "save_tls": True,
                                                    "maintained_differential": True,
                                                    "deadline_case_ms": args.owner_deadline_case_ms},
                      "template_opening_acceptance": {"software_tls": True, "maintained_differential": True,
                                                      "protected": qualified,
                                                      "deadline_case_ms": args.owner_deadline_case_ms},
                      "template_authoring_acceptance": {"reviewed_prepare": True, "explicit_commit": True,
                                                        "maintained_differential": True},
                      "contact_acceptance": {"historical_integrity": True, "maintained_differential": True,
                                             "protected_fields": qualified, "current_permission": False},
                      "contact_mutation_acceptance": {"historical_transitions": True, "software_production": True,
                                                      "protected_production": qualified, "durable_history": True,
                                                      "current_permission": False},
                      "contact_history_acceptance": {"local_metadata": True, "signed_root_recheck": True,
                                                     "session_cas": True, "restart_and_crash": True,
                                                     "current_permission": False, "external_rollback_protection": False},
                      "workflow_context_acceptance": {"reader_roles": [2, 3], "software_interop": True,
                                                       "protected_opening": qualified,
                                                       "current_authority_recheck": True,
                                                       "persistence": False, "service_acceptance": False},
                      "protected_acceptance": qualified}
            (args.output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report))
            if args.require_protected and not qualified:
                raise ValueError("Installed protected capability remains unqualified")


if __name__ == "__main__":
    main()
