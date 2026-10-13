#!/usr/bin/env python3
"""Build and verify reviewed Python preview artifacts; never publish them."""

import argparse
import importlib.util
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import zipfile

from privacy_guard import scan_blob

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 4 * 1024 * 1024


def backend():
    spec = importlib.util.spec_from_file_location("zrotext_package_backend", ROOT / "sdk/python/_build_backend.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked_path(value, external=False):
    path = Path(value).absolute()
    if external and path.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("artifact output must be outside the checkout")
    temporary_root = Path(tempfile.gettempdir()).resolve()
    # Normalize before I/O, then establish an independent filesystem boundary.
    normalized = Path(os.path.normpath(path))
    if os.path.commonpath((str(temporary_root), str(normalized))) != str(temporary_root) or normalized == temporary_root:
        raise ValueError("artifact path must be below the system temporary directory")
    path = normalized
    for item in (path, *path.parents):
        if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
            raise ValueError("linked artifact path refused")
    return path


def verify(path):
    path = checked_path(path)
    if not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("missing or oversized archive")
    builder = backend()
    stem, _ = builder.identity()
    if path.name.endswith(".whl"):
        expected = builder.wheel_files()
        if path.name != stem + "-py3-none-any.whl":
            raise ValueError("unexpected wheel filename")
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) != len(expected) or {e.filename for e in entries} != set(expected):
                raise ValueError("wheel entries differ from allowlist")
            for entry in entries:
                mode = entry.external_attr >> 16
                if entry.file_size > builder.LIMIT or entry.flag_bits & 1 or not stat.S_ISREG(mode):
                    raise ValueError("unsafe wheel entry")
                _check(entry.filename, archive.read(entry), expected[entry.filename])
    elif path.name.endswith(".tar.gz"):
        expected = {stem + "/" + name: data for name, data in builder.sdist_files().items()}
        if path.name != stem + ".tar.gz":
            raise ValueError("unexpected source filename")
        with tarfile.open(path, "r:gz") as archive:
            seen = set()
            for entry in archive:
                if entry.name in seen or entry.name not in expected or not entry.isfile() or entry.size > builder.LIMIT:
                    raise ValueError("unsafe or unexpected source entry")
                seen.add(entry.name)
                _check(entry.name, archive.extractfile(entry).read(), expected[entry.name])
            if seen != set(expected):
                raise ValueError("missing source entries")
    else:
        raise ValueError("unsupported artifact type")


def _check(name, actual, expected):
    if actual != expected:
        raise ValueError("artifact differs from reviewed source: " + name)
    if scan_blob(name, actual):
        raise ValueError("artifact privacy check failed: " + name)


def build(destination):
    destination = checked_path(destination, external=True)
    if destination.exists():
        raise ValueError("artifact destination must not exist")
    destination.mkdir(parents=True)
    builder = backend()
    outputs = [destination / builder.build_wheel(destination), destination / builder.build_sdist(destination)]
    for output in outputs:
        verify(output)
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("build").add_argument("--out", required=True)
    commands.add_parser("verify").add_argument("artifact")
    args = parser.parse_args()
    try:
        if args.command == "build":
            for output in build(args.out):
                print(output)
        else:
            verify(args.artifact)
            print("Python artifact verified")
    except (ValueError, OSError, zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
