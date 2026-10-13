"""Build licensed SDK archives and install them into clean consumers.

The temporary feed qualifies artifacts, not public registry availability. Never
publish these candidate packages over the existing supported clients.
"""
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
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "sdk/tungsten"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def write_files(directory, files):
    for name, data in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def runtime_files(source, target):
    """Copy only tracked runtime files, never local caches or build products."""
    # verify_source has already checked this exact clean revision. Read via Git
    # to avoid checkout newline conversion and omit every untracked artifact.
    git = ["git", "-C", str(source)]
    if os.name != "nt" and (source / ".git").is_file():
        if ":" in (source / ".git").read_text() and shutil.which("git.exe"):
            windows = run("wslpath", "-w", source, capture_output=True, text=True).stdout.strip()
            git = ["git.exe", "-C", windows]
    prefix = "runtimes/" + target + "/"
    names = run(*git, "ls-tree", "-r", "--name-only", "HEAD", "--", prefix,
                capture_output=True, text=True).stdout.splitlines()
    if not names:
        raise ValueError("Missing tracked runtime")
    files = {name.removeprefix(prefix): run(*git, "show", "HEAD:" + name,
             capture_output=True).stdout for name in names}
    if "LICENSE" not in files:
        files["LICENSE"] = run(*git, "show", "HEAD:LICENSE", capture_output=True).stdout
    return files


def replace_once(path, old, new):
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise ValueError("Unexpected package metadata: " + path.name)
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def check_wheel(path, license_bytes):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if not any(name.endswith("/LICENSE") and archive.read(name) == license_bytes for name in names):
            raise ValueError("Wheel omits expected license: " + path.name)
        if any(name.endswith((".pyc", "direct_url.json")) or "__pycache__" in name for name in names):
            raise ValueError("Wheel contains checkout/install artifacts")


def python_package(stage, feed):
    if sys.version_info < (3, 12):
        raise ValueError("Python 3.12 or newer required")
    sdk = stage / "sdk"
    runtime = stage / "runtime"
    replace_once(sdk / "pyproject.toml", 'readme = "README.md"',
                 'readme = "README.md"\nlicense = "AGPL-3.0-only"\nlicense-files = ["LICENSE"]')
    build = stage / "build-env"
    venv.EnvBuilder(with_pip=True).create(build)
    python = build / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    requirements = CONFIG / "python-package-requirements.txt"
    run(python, "-m", "pip", "download", "--only-binary=:all:", "--dest", feed,
        "-r", requirements, cwd=stage)
    run(python, "-m", "pip", "install", "--no-index", "--find-links", feed,
        "-r", requirements, cwd=stage)
    run(python, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps",
        "--wheel-dir", feed, runtime, sdk, cwd=stage)
    for name, project in (("tungsten_runtime", runtime), ("zrotext_sdk", sdk)):
        wheel = next(feed.glob(name + "-*.whl"))
        check_wheel(wheel, (project / "LICENSE").read_bytes())
    # Remove the build source before the consumer check; imports cannot fall
    # through to editable installs, PYTHONPATH, or the original working tree.
    shutil.rmtree(sdk)
    shutil.rmtree(runtime)
    consumer = stage / "consumer"
    venv.EnvBuilder(with_pip=True).create(consumer)
    python = consumer / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    run(python, "-m", "pip", "install", "--no-index", "--find-links", feed,
        "--constraint", requirements, "zrotext-sdk==0.1.0", cwd=stage)
    run(python, "-m", "pip", "check", cwd=stage)
    run(python, "-I", "-c", "import importlib,pkgutil,zrotext_sdk,tungsten_runtime; "
        "[importlib.import_module(m.name) for m in pkgutil.walk_packages("
        "zrotext_sdk.__path__,zrotext_sdk.__name__+'.')]; print('Installed SDK modules loaded')", cwd=stage)
    run(python, "-I", CONFIG / "python-contract.py", cwd=stage)


def ruby_package(stage, feed, ruby):
    run(ruby, "-e", "abort 'Ruby 3.3 required' if Gem::Version.new(RUBY_VERSION) < Gem::Version.new('3.3')")
    for name, license_id in (("sdk", "AGPL-3.0-only"), ("runtime", "Apache-2.0")):
        project = stage / name
        spec = next(project.glob("*.gemspec"))
        replace_once(spec, '  spec.require_paths = ["lib"]',
                     '  spec.files += ["LICENSE"]\n  spec.license = "' + license_id + '"\n'
                     '  spec.require_paths = ["lib"]')
        run(ruby, "-rrubygems/gem_runner", "-e", "Gem::GemRunner.new.run(ARGV)", "--",
            "build", spec.name, cwd=project)
        gem = next(project.glob("*.gem"))
        shutil.copy2(gem, feed / gem.name)
        # Gem::Package verifies the package checksums and license entry before
        # installation; install consumes archives only, with no source path.
        run(ruby, "-rrubygems/package", "-e",
            "p=Gem::Package.new(ARGV[0]); p.verify; abort 'missing license' unless p.contents.include?('LICENSE')",
            gem, cwd=stage)
    shutil.rmtree(stage / "sdk")
    shutil.rmtree(stage / "runtime")
    home = stage / "gems"
    env = dict(os.environ, GEM_HOME=str(home), GEM_PATH=str(home))
    # Drop injected interpreter options; GEM_HOME/PATH are isolated. RUBYLIB
    # may be needed by a relocated Ruby standard library, but loaded SDK/runtime
    # gems must still resolve from the new installation below.
    env.pop("RUBYOPT", None)
    run(ruby, "-rrubygems/gem_runner", "-e", "Gem::GemRunner.new.run(ARGV)", "--",
        "install", "--local", "--no-document", "--install-dir", home,
        next(feed.glob("zrotext-sdk-*.gem")), env=env, cwd=feed)
    run(ruby, CONFIG / "ruby-package-consumer.rb", env=env, cwd=stage)
    # Prove inherited Ruby source paths cannot falsely qualify the archives,
    # even when that shim loads the real gem and populates Gem.loaded_specs.
    injected = stage / "source-injection"
    injected.mkdir()
    (injected / "zrotext_sdk.rb").write_text(
        'gem "zrotext-sdk", "0.1.0"\n'
        'require File.join(Gem::Specification.find_by_name("zrotext-sdk").full_gem_path, '
        '"lib/zrotext_sdk.rb")\n', encoding="utf-8")
    injected_env = dict(env, RUBYLIB=str(injected) + os.pathsep + env.get("RUBYLIB", ""))
    result = subprocess.run([str(ruby), str(CONFIG / "ruby-package-consumer.rb")],
                            env=injected_env, cwd=stage, capture_output=True, text=True)
    if result.returncode == 0 or "loaded outside installed gem" not in result.stderr:
        raise ValueError("Ruby consumer did not reject source injection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target", choices=["python", "ruby", "typescript", "java", "csharp", "go", "rust"], required=True)
    parser.add_argument("--ruby", default="ruby")
    parser.add_argument("--cargo", type=Path, help="Optional direct Rust 1.88.0 toolchain cargo executable")
    args = parser.parse_args()
    destination = args.out.resolve()
    if destination.is_relative_to(ROOT.resolve()) or destination.exists():
        raise ValueError("Use a new external output directory")
    policy = load("artifact_policy", ROOT / "scripts/tungsten_sdk.py")
    lock = json.loads((CONFIG / "generator.lock.json").read_text())
    policy.verify_source(args.source.resolve(), lock)
    packages = load("source_packages", CONFIG / "package-sources.py")
    inventory = json.loads((CONFIG / "generated.lock.json").read_text())
    generated = packages.reviewed_files(CONFIG / "generated", inventory)[args.target]
    generated["LICENSE"] = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
    with tempfile.TemporaryDirectory(prefix="zrotext-package-consumer-") as temp:
        stage = Path(temp)
        feed = stage / "feed"
        feed.mkdir()
        write_files(stage / "sdk", generated)
        runtime_target = "ts" if args.target == "typescript" else args.target
        write_files(stage / "runtime", runtime_files(args.source.resolve(), runtime_target))
        if args.target == "python":
            python_package(stage, feed)
        elif args.target == "ruby":
            ruby_package(stage, feed, args.ruby)
        elif args.target in ("go", "rust"):
            native = load("native_packages", CONFIG / "package-native.py")
            if args.target == "rust":
                native.rust_package(stage, feed, args.cargo)
            else:
                native.go_package(stage, feed)
        else:
            managed = load("managed_packages", CONFIG / "package-managed.py")
            getattr(managed, args.target + "_package")(stage, feed)
        shutil.copytree(feed, destination)
    sums = {p.relative_to(destination).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(destination.rglob("*")) if p.is_file()}
    report = {
        "target": args.target, "runtime_revision": lock["runtime_revision"],
        "qualification": "isolated archive consumer; public registry availability unverified",
        "sha256": sums}
    if args.target == "rust":
        report["distribution"] = ("Candidate-registry qualification only: crate metadata and locks refer "
                                  "to the temporary registry. Rebuild against released runtime coordinates "
                                  "before distribution; these are not public-registry-ready crates.")
    (destination / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(args.target + " archives and isolated consumer passed; no publication performed")


if __name__ == "__main__":
    main()
