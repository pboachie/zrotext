"""Decide which expensive CI suites a pull request needs.

Prints GitHub Actions step outputs (`rust=true|false`, `android=true|false`).
The filters are negative: a suite is skipped only when every changed path is
in a set known not to affect it. An unlisted path, a push to main, or any
error in reading the change runs every suite.
"""

import os
import subprocess
import sys

# Documentation and repository metadata, except explicit test inputs below.
DOCS_PREFIXES = ("docs/", ".github/ISSUE_TEMPLATE/")
DOCS_FILES = {"LICENSE", "DCO", ".github/CODEOWNERS", ".github/PULL_REQUEST_TEMPLATE.md"}
DOCS_SUFFIXES = (".md",)

# Paths the Rust workspace, its tests and the rust job's scripts never read.
NOT_RUST_PREFIXES = ("android/",)
# The quickstart integration test includes these examples at compile time.
RUST_DOCUMENT_INPUTS = {"docs/AGENT-QUICKSTART.md"}
# Paths the Android build and its JVM tests never read. Android test resources
# come from protocol/v1/vectors and sdk/typescript/test/vectors, so those stay.
NOT_ANDROID_PREFIXES = ("crates/", "deploy/", "web/")
NOT_ANDROID_FILES = {"about.toml", "about.hbs"}
# The ordinary APK builds the native owner custodian from these sources.
ANDROID_NATIVE_PREFIXES = ("crates/android-owner-custody/", "crates/root-material/")


def is_docs(path: str) -> bool:
    return path in DOCS_FILES or path.startswith(DOCS_PREFIXES) or path.endswith(DOCS_SUFFIXES)


def suites(paths: list[str]) -> dict[str, bool]:
    """Return which suites must run for these changed repository paths."""
    if not paths:
        return {"rust": True, "android": True}
    rust = any(p in RUST_DOCUMENT_INPUTS or not (is_docs(p) or p.startswith(NOT_RUST_PREFIXES))
               for p in paths)
    android = any(
        p.startswith(ANDROID_NATIVE_PREFIXES) or not (is_docs(p) or p.startswith(NOT_ANDROID_PREFIXES) or p in NOT_ANDROID_FILES)
        for p in paths
    )
    return {"rust": rust, "android": android}


def pull_request_paths() -> list[str]:
    """Paths changed by the checked-out pull request merge commit."""
    parents = subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    if len(parents) != 3:
        raise ValueError("HEAD is not a pull request merge commit")
    diff = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", "HEAD^1", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout
    return [p for p in diff.split("\0") if p]


def main() -> int:
    run = {"rust": True, "android": True}
    if os.environ.get("CI_EVENT_NAME") == "pull_request":
        try:
            run = suites(pull_request_paths())
        except (OSError, subprocess.CalledProcessError, ValueError) as error:
            print(f"Running every suite: {error}", file=sys.stderr)
    for name, needed in run.items():
        print(f"{name}={'true' if needed else 'false'}")
        print(f"{name} suite: {'run' if needed else 'skip'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
