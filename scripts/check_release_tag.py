#!/usr/bin/env python3
"""Validate release tags before producing any release artifacts."""

from __future__ import annotations

import os
import re
import subprocess
import sys

VERSION = re.compile(r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-rc\.[1-9]\d*)?\Z")


def main() -> int:
    tag = os.environ.get("GITHUB_REF_NAME", "")
    if not VERSION.fullmatch(tag):
        print(f"Invalid release tag name: {tag!r}", file=sys.stderr)
        return 1
    ref = f"refs/tags/{tag}"
    kind = subprocess.check_output(["git", "cat-file", "-t", ref], text=True).strip()
    if kind != "tag":
        print("Release tags must be annotated.", file=sys.stderr)
        return 1
    commit = subprocess.check_output(["git", "rev-parse", f"{ref}^{{commit}}"], text=True).strip()
    if subprocess.run(["git", "merge-base", "--is-ancestor", commit, "origin/main"], check=False).returncode:
        print("Release tag must point to a commit on main.", file=sys.stderr)
        return 1
    print(f"Release tag {tag} is valid and points to main.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
