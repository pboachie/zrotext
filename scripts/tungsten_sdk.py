"""Build pinned Tungsten tools and generate/check the experimental SDK surface.

Run with Python on the same platform as cargo and Go (including inside WSL).
The source checkout is caller supplied; this command never fetches or publishes.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "sdk" / "tungsten"


def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def verify_source(source, lock):
    git = ["git", "-C", source]
    # A Windows-created worktree contains a Windows gitdir path. Native Git
    # inside WSL cannot resolve it; use Windows Git for this read-only check.
    gitfile = source / ".git"
    if (os.name != "nt" and gitfile.is_file()
            and re.match(r"gitdir: [A-Za-z]:", gitfile.read_text())
            and shutil.which("git.exe")):
        windows_path = run(["wslpath", "-w", source], capture_output=True, text=True).stdout.strip()
        git = ["git.exe", "-C", windows_path]
    revision = run([*git, "rev-parse", "HEAD"],
                   capture_output=True, text=True).stdout.strip()
    if revision != lock["revision"] or revision != lock["runtime_revision"]:
        raise ValueError("Tungsten source must match generator.lock.json exactly")
    dirty = run([*git, "status", "--porcelain", "--untracked-files=all"],
                capture_output=True, text=True).stdout
    if dirty.strip():
        raise ValueError("Tungsten source must be clean, including untracked source files")


def extension_files(extensions):
    return sorted(file for file in extensions.rglob("*") if file.is_file())


def stage_extensions(directory, extensions):
    directory = directory.resolve()
    extensions = extensions.resolve()
    for source in extension_files(extensions):
        relative = source.relative_to(extensions)
        destination = directory / relative
        if (not source.resolve().is_relative_to(extensions)
                or not destination.resolve().is_relative_to(directory)):
            raise ValueError("Extension escapes the approved source/output directory")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())


def output_inventory(directory, extensions=None):
    """Hash only generator-owned files, excluding caches and installed packages."""
    directory = directory.resolve()
    inventory = {}
    for manifest in sorted(directory.glob("*/.tungsten/manifest.json")):
        target = manifest.parent.parent.resolve()
        owned = json.loads(manifest.read_text(encoding="utf-8"))["files"]
        for item in owned:
            file = (target / item["path"]).resolve()
            if not file.is_relative_to(target):
                raise ValueError("Generated manifest contains a path outside its target")
            name = file.relative_to(directory).as_posix()
            inventory[name] = hashlib.sha256(file.read_bytes()).hexdigest()
    if not inventory:
        raise ValueError("Generator produced no tracked output files")
    # Tungsten preserves these user-owned seeds and omits them from its own
    # manifest, but generated packages import them and require them to build.
    if extensions is not None:
        for source in extension_files(extensions):
            relative = source.relative_to(extensions)
            file = (directory / relative).resolve()
            if not file.is_relative_to(directory):
                raise ValueError("Extension output escapes generated directory")
            inventory[relative.as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
    return inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True,
                        help="clean checkout at the revision in generator.lock.json")
    parser.add_argument("--check", action="store_true", help="fail on generated drift")
    parser.add_argument("--mock", action="store_true", help="run the local contract mock")
    args = parser.parse_args(argv)
    if args.mock and args.check:
        parser.error("--mock and --check are mutually exclusive")
    lock = json.loads((CONFIG / "generator.lock.json").read_text(encoding="utf-8"))
    source = args.source.resolve()
    verify_source(source, lock)
    # Build from the verified source on every run. Cargo's incremental cache is
    # allowed, but an arbitrary pre-existing binary is never accepted as proof.
    target = Path(os.environ.get("CARGO_TARGET_DIR", source / "target" / "zrotext-sdk")).resolve()
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    run(["cargo", "build", "--locked", "-p", "tungsten-cli"], cwd=source, env=env)
    suffix = ".exe" if os.name == "nt" else ""
    binary = target / "debug" / ("tungsten" + suffix)
    version = run([binary, "--version"], capture_output=True, text=True).stdout.strip()
    if version != "tungsten " + lock["version"]:
        raise ValueError("Unexpected Tungsten binary version: " + version)
    emitter = target / "debug" / ("tungsten-emit-go" + suffix)
    run(["go", "build", "-trimpath", "-o", emitter, "."],
        cwd=source / lock["go_emitter"])
    env["PATH"] = str(binary.parent) + os.pathsep + env.get("PATH", "")
    run([binary, "check", CONFIG], cwd=ROOT, env=env)
    if args.mock:
        run([binary, "mock", CONFIG], cwd=ROOT, env=env)
        return 0
    # Outputs are build artifacts. Check mode may regenerate them, but never
    # updates the tracked digest lock. A second pass checks determinism too.
    stage_extensions(CONFIG / "generated", CONFIG / "extensions")
    run([binary, "generate", CONFIG], cwd=ROOT, env=env)
    run([binary, "generate", CONFIG, "--check"], cwd=ROOT, env=env)
    inventory = output_inventory(CONFIG / "generated", CONFIG / "extensions")
    snapshot = CONFIG / "generated.lock.json"
    if args.check:
        expected = json.loads(snapshot.read_text(encoding="utf-8"))
        if inventory != expected:
            changed = sorted(key for key in inventory.keys() | expected.keys()
                             if inventory.get(key) != expected.get(key))
            raise ValueError("Generated SDK drift: " + ", ".join(changed[:12]))
    else:
        snapshot.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Tungsten SDK command failed: {error}", file=sys.stderr)
        sys.exit(1)
