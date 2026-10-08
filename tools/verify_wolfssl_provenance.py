#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify the vendored wolfSSL tree against its committed PROVENANCE.

This closes the gaps that per-file regeneration cannot see on its own: the
vendored tree may not contain any file outside the manifest (EXTRA), no
manifest file may be absent (MISSING), and every present file must hash to
its recorded digest (MODIFIED). PROVENANCE itself is the only exempt file.

    python3 tools/verify_wolfssl_provenance.py
    python3 tools/verify_wolfssl_provenance.py --self-test

The self-test plants a deliberate bad commit (an extra file, a modified
file and a deleted file) into temporary copies of the tree and asserts the
checker rejects each one, so the enforcement is exercised on every run.
"""
import argparse
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VENDORED = REPO / "android/app/src/main/cpp/wolfssl"
MANIFEST_NAME = "PROVENANCE"
HEADER_PREFIXES = ("Vendored ", "Upstream: ", "Commit: ", "License: ")


def parse_manifest(text: str) -> dict[str, str]:
    expected: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith(HEADER_PREFIXES):
            continue
        parts = line.split()
        if len(parts) != 2 or len(parts[0]) != 64 or any(c not in "0123456789abcdef" for c in parts[0]):
            print(f"unparsable PROVENANCE line {number}", file=sys.stderr)
            raise SystemExit(2)
        if parts[1] in expected:
            print(f"PROVENANCE line {number}: duplicate entry {parts[1]}", file=sys.stderr)
            raise SystemExit(2)
        expected[parts[1]] = parts[0]
    return expected


def tree_files(vendored: Path) -> set[str]:
    return {
        path.relative_to(vendored).as_posix()
        for path in vendored.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    }


def verify(vendored: Path) -> int:
    problems: list[str] = []
    expected = parse_manifest((vendored / MANIFEST_NAME).read_text(encoding="utf-8"))
    present = tree_files(vendored)
    for relative in sorted(set(expected) - present):
        problems.append(f"missing vendored file: {relative}")
    for relative in sorted(present - set(expected)):
        problems.append(f"unlisted vendored file: {relative}")
    for relative in sorted(set(expected) & present):
        digest = hashlib.sha256((vendored / relative).read_bytes()).hexdigest()
        if digest != expected[relative]:
            problems.append(f"digest mismatch: {relative}")
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"{len(problems)} vendored-tree problem(s) against PROVENANCE", file=sys.stderr)
        return 1
    print(f"vendored tree matches PROVENANCE ({len(expected)} files).")
    return 0


def self_test(vendored: Path) -> int:
    cases: list[tuple[str, Path]] = []

    def copied(name: str) -> Path:
        target = Path(tempfile.mkdtemp(prefix=f"wolfssl-provenance-{name}-")) / "tree"
        shutil.copytree(vendored, target)
        cases.append((name, target))
        return target

    extra = copied("extra")
    (extra / "wolfcrypt" / "src" / "planted.c").write_bytes(b"/* not upstream */\n")
    modified = copied("modified")
    header = next(path for path in sorted(modified.glob("wolfssl/*.h")))
    header.write_bytes(header.read_bytes() + b"\n")
    missing = copied("missing")
    (missing / "ChangeLog.md").unlink()
    failures = []
    for name, tree in cases:
        if verify(tree) == 0:
            failures.append(name)
    if failures:
        print(f"self-test FAILED: undetected plantings in {', '.join(failures)}", file=sys.stderr)
        return 1
    print("self-test passed: extra, modified and missing vendored files are all rejected.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", type=Path, default=VENDORED, help="vendored wolfSSL directory")
    parser.add_argument("--self-test", action="store_true", help="plant bad copies and assert rejection")
    args = parser.parse_args()
    if args.self_test:
        # The self-test always exercises the real vendored tree; --tree exists
        # for verify() only, so the self-test copies never carry a CLI flow.
        return self_test(VENDORED)
    return verify(args.tree)


if __name__ == "__main__":
    raise SystemExit(main())
