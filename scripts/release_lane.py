#!/usr/bin/env python3
"""Decide and prepare automatic releases from a merged server version bump.

The ZROtext server release version is the `version` field of
`crates/server/Cargo.toml`. When a merge to `main` carries a version that no
`v<version>` tag points at yet, the release lane tags that commit and publishes
the GitHub release, which triggers the existing release workflows. A version
older than the newest existing tag is a regression and fails loudly; an already
tagged version is a no-op, so ordinary merges never release anything.

Release notes come from the version's section in `CHANGELOG.md` (Keep a
Changelog format). A version without a non-empty section is never tagged.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_MANIFEST = "crates/server/Cargo.toml"
CHANGELOG = "CHANGELOG.md"
ANDROID_MANIFEST = "android/app/build.gradle.kts"
TAGGER_NAME = "ZROtext release lane"
TAGGER_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"

# Mirrors the tag shape enforced by scripts/check_release_tag.py.
VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-rc\.[1-9]\d*)?\Z")
SECTION_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?: - .*)?$", re.MULTILINE)
ANDROID_CODE = re.compile(r"^\s*versionCode\s*=\s*(\d+)\s*$", re.MULTILINE)
ANDROID_NAME = re.compile(r"^\s*versionName\s*=\s*\"([^\"]+)\"\s*$", re.MULTILINE)

NOOP = "noop"
TAG = "tag"
REGRESSION = "regression"


class LaneError(Exception):
    """A condition that must stop the lane with a clear message."""


def release_order(version: str) -> tuple[int, int, int, int, int]:
    """Order versions so any release outranks its candidates: 1.0.3-rc.2 < 1.0.3."""
    numbers, _, candidate = version.partition("-rc.")
    major, minor, patch = (int(part) for part in numbers.split("."))
    if candidate:
        return (major, minor, patch, 0, int(candidate))
    return (major, minor, patch, 1, 0)


def validate_version(version: str) -> str:
    if not VERSION.fullmatch(version):
        raise LaneError(
            f"crates/server version {version!r} is not a releasable version "
            "(expected MAJOR.MINOR.PATCH with an optional -rc.N candidate suffix)"
        )
    return version


def server_version(root: Path = ROOT) -> str:
    manifest = root / SERVER_MANIFEST
    if manifest.is_symlink() or not manifest.is_file():
        raise LaneError(f"{SERVER_MANIFEST} is missing or linked")
    with manifest.open("rb") as source:
        try:
            version = tomllib.load(source)["package"]["version"]
        except (KeyError, tomllib.TOMLDecodeError) as error:
            raise LaneError(f"{SERVER_MANIFEST} has no readable package version") from error
    if not isinstance(version, str):
        raise LaneError(f"{SERVER_MANIFEST} package version is not a string")
    return validate_version(version)


def tag_version(tag: str) -> str | None:
    if not tag.startswith("v"):
        return None
    version = tag[1:]
    return version if VERSION.fullmatch(version) else None


def existing_tags(root: Path = ROOT) -> list[str]:
    output = subprocess.run(
        ["git", "tag", "--list"], cwd=root, check=True, capture_output=True, text=True
    ).stdout
    return output.split()


def decide(version: str, tags: list[str]) -> tuple[str, str | None]:
    """Classify the checkout as noop, tag, or regression against the tags."""
    known = [parsed for tag in tags if (parsed := tag_version(tag))]
    if not known:
        return TAG, None
    newest = max(known, key=release_order)
    if release_order(version) > release_order(newest):
        return TAG, f"v{newest}"
    if release_order(version) == release_order(newest):
        return NOOP, f"v{newest}"
    raise LaneError(
        f"crates/server version {version!r} does not advance beyond the newest "
        f"existing tag v{newest}; refusing to regress or fork the release line"
    )


def changelog_section(root: Path, version: str) -> str:
    changelog = root / CHANGELOG
    if changelog.is_symlink() or not changelog.is_file():
        raise LaneError(f"{CHANGELOG} is missing or linked; a release needs its section")
    text = changelog.read_text(encoding="utf-8")
    matches = list(SECTION_HEADING.finditer(text))
    for index, match in enumerate(matches):
        if match.group("version") != version:
            continue
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        section = text[start:end].strip()
        if not section:
            raise LaneError(
                f"{CHANGELOG} has an empty section for {version}; "
                "write the release notes before bumping the version"
            )
        return section
    raise LaneError(
        f"{CHANGELOG} has no `## [{version}]` section; "
        "a version bump cannot be released without release notes"
    )


def android_release_version(root: Path) -> tuple[str, int]:
    manifest = root / ANDROID_MANIFEST
    if manifest.is_symlink() or not manifest.is_file():
        raise LaneError(f"{ANDROID_MANIFEST} is missing or linked")
    text = manifest.read_text(encoding="utf-8")
    name = ANDROID_NAME.search(text)
    code = ANDROID_CODE.search(text)
    if name is None or code is None:
        raise LaneError(f"{ANDROID_MANIFEST} has no readable versionName/versionCode")
    return name.group(1), int(code.group(1))


def build_body(root: Path, version: str) -> str:
    tag = f"v{version}"
    section = changelog_section(root, version)
    app_name, app_code = android_release_version(root)
    return f"""{section}

## Android app

The Android app keeps its own independent version: `{app_name}`, version code `{app_code}`. This backend tag does not by itself announce a new Android app version.

## Release artifacts

- `zrotext-{tag}-unsigned.apk` — unsigned release APK built from this tag's source by the `Android unsigned candidate` workflow and attached here by the `Release server image` workflow. Signing, installation and distribution remain maintainer-side.
- `zrotext-server-{tag}-linux-amd64.zip` — server bundle (binaries, migrations, notices, Compose files) extracted from the attested release image; attached by the `Release server image` workflow.
- The attested container image for this tag is published to `ghcr.io/pboachie/zrotext` by the `Release server image` workflow; its immutable digest is recorded in that workflow's image-receipt artifact.

No other files are attached to this release.
"""


def write_output(line: str, announce: bool = True) -> None:
    """Record a workflow output; the notes command keeps stdout body-only."""
    handle = os.environ.get("GITHUB_OUTPUT")
    if announce:
        print(line)
    if handle:
        with open(handle, "a", encoding="utf-8") as sink:
            sink.write(line + "\n")


def command_check(root: Path) -> int:
    try:
        version = server_version(root)
        decision, reference = decide(version, existing_tags(root))
        write_output(f"version={version}")
        write_output(f"decision={decision}")
        if reference:
            write_output(f"reference={reference}")
        if decision == TAG:
            changelog_section(root, version)
            print(f"Version {version} is new; this merge releases v{version} "
                  f"(newest existing tag: {reference or 'none'}).")
        else:
            print(f"Version {version} is already tagged as {reference}; "
                  "this merge does not release anything.")
    except LaneError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


def command_notes(root: Path) -> int:
    try:
        version = server_version(root)
        decide(version, existing_tags(root))
        body = build_body(root, version)
    except LaneError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    if not body.endswith("\n"):
        sys.stdout.write("\n")
    write_output(f"tag=v{version}", announce=False)
    write_output(f"prerelease={'-rc.' in version and 'true' or 'false'}", announce=False)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Classify the checkout against existing tags")
    check.add_argument("--root", type=Path, default=ROOT)
    notes = commands.add_parser("notes", help="Write the GitHub release body to stdout")
    notes.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    if args.command == "check":
        return command_check(args.root)
    return command_notes(args.root)


if __name__ == "__main__":
    raise SystemExit(main())
