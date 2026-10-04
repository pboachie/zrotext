#!/usr/bin/env python3
"""Stage and inspect the small public npm artifact, without registry writes."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile

from privacy_guard import scan_blob

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "sdk" / "npm"
MODULES = ("index", "alpha-client", "webhook-verify")
DIST = {f"dist/{name}.{suffix}" for name in MODULES for suffix in ("js", "d.ts")}
FILES = DIST | {"package.json", "README.md", "LICENSE", "CHANGELOG.md"}
MAX_FILE_BYTES = 1024 * 1024
MAX_TARBALL_BYTES = 4 * MAX_FILE_BYTES


def checked_path(value, *, external=False, root=ROOT):
    """Reject symlinks/junctions, including ancestors, before resolving paths."""
    raw = Path(value).absolute()
    for part in (raw, *raw.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            raise ValueError(f"linked path is forbidden: {part}")
    path = raw.resolve()
    if external and path.is_relative_to(root.resolve()):
        raise ValueError("temporary package/build destination must be outside checkout")
    return path


def read_regular(path):
    checked_path(path)
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"missing or oversized regular file: {path.name}")
    return path.read_bytes()


def check_manifest(manifest, root=ROOT):
    package = root / "sdk" / "npm"
    expected = json.loads(read_regular(package / "package.json"))
    if manifest != expected:
        raise ValueError("tarball metadata differs from reviewed package manifest")
    if manifest.get("name") != "zrotext" or manifest.get("license") != "AGPL-3.0-only":
        raise ValueError("package identity/license mismatch")
    if manifest.get("type") != "module" or manifest.get("engines") != {"node": ">=24"}:
        raise ValueError("package must be ESM with Node >=24")
    if manifest.get("exports") != {".": {"types": "./dist/index.d.ts", "import": "./dist/index.js"}}:
        raise ValueError("only the typed root import may be exported")
    if manifest.get("main") != "./dist/index.js" or manifest.get("types") != "./dist/index.d.ts":
        raise ValueError("entry point mismatch")
    if set(manifest.get("files", [])) != FILES - {"package.json"}:
        raise ValueError("package files allowlist mismatch")
    if any(key in manifest for key in ("scripts", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundledDependencies", "bin")):
        raise ValueError("public artifact must have no scripts or dependencies")
    if manifest.get("publishConfig") != {"access": "public", "registry": "https://registry.npmjs.org/", "provenance": True}:
        raise ValueError("public registry/provenance settings mismatch")
    if manifest.get("version") == "0.0.0-development" and manifest.get("private") is not True:
        raise ValueError("development sentinel must remain private")
    lock = json.loads(read_regular(package / "package-lock.json"))
    if lock.get("lockfileVersion") != 3 or set(lock.get("packages", {})) != {""}:
        raise ValueError("public lockfile must have no dependencies")
    root = lock["packages"][""]
    for key in ("name", "version"):
        if lock.get(key) != manifest.get(key) or root.get(key) != manifest.get(key):
            raise ValueError(f"manifest/lockfile {key} mismatch")
    for key in ("license", "engines"):
        if root.get(key) != manifest.get(key):
            raise ValueError(f"manifest/lockfile {key} mismatch")


def check_imports(name, contents):
    text = contents.decode("utf-8")
    if not text.strip():
        raise ValueError(f"empty compiled module: {name}")
    # The selected compiler output has only static re-exports in index. Reject
    # dynamic/require imports and every static module specifier outside that pair.
    if re.search(r"\b(?:import\s*\(|require\s*\()", text):
        raise ValueError(f"dynamic module loading is forbidden: {name}")
    imports = re.findall(r"\bfrom\s*[\"']([^\"']+)[\"']|\bimport\s*[\"']([^\"']+)[\"']", text)
    specifiers = [first or second for first, second in imports]
    expected = ["./alpha-client.js", "./webhook-verify.js"] if name.startswith("dist/index.") else []
    if specifiers != expected:
        raise ValueError(f"unexpected import closure: {name}")


def verify_contents(contents, root=ROOT):
    if set(contents) != FILES:
        raise ValueError(f"unexpected package file list: {sorted(set(contents) ^ FILES)}")
    check_manifest(json.loads(contents["package.json"]), root)
    for name in DIST:
        check_imports(name, contents[name])
    for name in ("README.md", "CHANGELOG.md"):
        if contents[name] != read_regular(root / "sdk" / "npm" / name):
            raise ValueError(f"{name} differs from reviewed source")
    if contents["LICENSE"] != read_regular(root / "LICENSE"):
        raise ValueError("full repository license must be included unchanged")
    for name, data in contents.items():
        if scan_blob(name, data):
            raise ValueError(f"package privacy/security scan failed: {name}")


def stage(compiled, out, root=ROOT):
    compiled = checked_path(compiled, external=True, root=root)
    out = checked_path(out, external=True, root=root)
    if not compiled.is_dir() or out.exists():
        raise ValueError("compiled directory must exist and stage destination must be new")
    expected = {f"{name}.{suffix}" for name in MODULES for suffix in ("js", "d.ts")}
    if {p.name for p in compiled.iterdir()} != expected:
        raise ValueError("compiled directory must contain exactly the six selected outputs")
    contents = {f"dist/{name}": read_regular(compiled / name) for name in expected}
    for name in ("package.json", "README.md", "CHANGELOG.md"):
        contents[name] = read_regular(root / "sdk" / "npm" / name)
    contents["LICENSE"] = read_regular(root / "LICENSE")
    verify_contents(contents, root)
    out.mkdir(parents=True)
    (out / "dist").mkdir()
    try:
        for name, data in contents.items():
            (out / name).write_bytes(data)
    except Exception:
        shutil.rmtree(out)
        raise
    return {"package": str(out), "files": sorted(contents)}


def verify_tarball(path, root=ROOT):
    path = checked_path(path)
    if not path.is_file() or path.stat().st_size > MAX_TARBALL_BYTES:
        raise ValueError("missing or oversized tarball")
    contents = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name
            if not member.isfile() or member.size > MAX_FILE_BYTES or not name.startswith("package/"):
                raise ValueError("tarball contains a link, non-file, oversized file or unsafe path")
            relative = name[len("package/"):]
            if relative not in FILES or relative in contents:
                raise ValueError(f"unexpected or duplicate tarball entry: {name}")
            contents[relative] = archive.extractfile(member).read(MAX_FILE_BYTES + 1)
    verify_contents(contents, root)
    raw = path.read_bytes()
    return {"name": "zrotext", "version": json.loads(contents["package.json"])["version"],
            "filename": path.name, "metadata": json.loads(contents["package.json"]),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode("ascii"),
            "files": sorted(contents),
            "entries": [{"path": name, "bytes": len(contents[name]),
                       "sha256": hashlib.sha256(contents[name]).hexdigest()} for name in sorted(contents)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("stage")
    prepare.add_argument("--compiled", required=True)
    prepare.add_argument("--out", required=True)
    inspect = commands.add_parser("verify-tarball")
    inspect.add_argument("tarball")
    args = parser.parse_args()
    try:
        result = stage(args.compiled, args.out) if args.command == "stage" else verify_tarball(args.tarball)
    except (ValueError, OSError, tarfile.TarError) as error:
        parser.exit(1, f"package check failed: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
