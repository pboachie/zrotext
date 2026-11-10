#!/usr/bin/env python3
"""Tests for the automatic release lane decision and release-notes logic."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "release_lane", Path(__file__).resolve().parent / "release_lane.py"
)
release_lane = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault("release_lane", release_lane)
SPEC.loader.exec_module(release_lane)

SERVER_MANIFEST = """\
[package]
name = "zrotext-server"
version = "{version}"
edition.workspace = true
"""

GRADLE = """\
plugins {{
    id("com.android.application")
}}
android {{
    defaultConfig {{
        applicationId = "org.zrotext.gateway"
        minSdk = 29
        versionCode = {code}
        versionName = "{name}"
    }}
}}
"""

CHANGELOG = """\
# Changelog

## [Unreleased]

### Changed

- Nothing yet.

## [1.0.3-rc.3] - 2026-10-28

### Added

- Candidate fixes.

## [1.0.3]

### Added

- Final fixes.

## [1.1.0]

### Added

- Next features.
"""


class ReleaseOrderTest(unittest.TestCase):
    def test_release_outranks_candidates(self) -> None:
        order = release_lane.release_order
        self.assertLess(order("1.0.3-rc.3"), order("1.0.3"))
        self.assertLess(order("1.0.3-rc.3"), order("1.0.3-rc.10"))
        self.assertLess(order("1.0.2"), order("1.0.3-rc.1"))
        self.assertLess(order("1.0.3-rc.2"), order("1.0.3-rc.3"))
        self.assertLess(order("0.9.99"), order("1.0.0"))

    def test_validate_version_rejects_unreleasable_shapes(self) -> None:
        for bad in ("1.0", "1.0.3.4", "01.0.3", "1.0.3-beta.1", "1.0.3-rc.0", "1.0.3-rc", ""):
            with self.assertRaises(release_lane.LaneError):
                release_lane.validate_version(bad)
        self.assertEqual(release_lane.validate_version("1.0.3"), "1.0.3")
        self.assertEqual(release_lane.validate_version("1.0.3-rc.1"), "1.0.3-rc.1")


class DecideTest(unittest.TestCase):
    def test_existing_tag_is_a_noop(self) -> None:
        self.assertEqual(
            release_lane.decide("1.0.3-rc.3", ["v1.0.3-rc.3", "v1.0.2-rc.1"]),
            (release_lane.NOOP, "v1.0.3-rc.3"),
        )

    def test_newer_version_tags(self) -> None:
        decision, reference = release_lane.decide("1.0.3", ["v1.0.3-rc.3", "v1.0.2-rc.1"])
        self.assertEqual(decision, release_lane.TAG)
        self.assertEqual(reference, "v1.0.3-rc.3")

    def test_no_existing_tags_tags(self) -> None:
        self.assertEqual(release_lane.decide("0.1.0", []), (release_lane.TAG, None))

    def test_older_version_is_a_regression(self) -> None:
        with self.assertRaises(release_lane.LaneError):
            release_lane.decide("1.0.2", ["v1.0.3-rc.3"])

    def test_equal_to_a_non_newest_tag_is_still_a_regression(self) -> None:
        # A reverted version that matches an old tag must fail loudly, never re-tag.
        with self.assertRaises(release_lane.LaneError):
            release_lane.decide("1.0.2", ["v1.0.2", "v1.0.3"])

    def test_unrelated_tags_are_ignored(self) -> None:
        decision, reference = release_lane.decide("1.0.3", ["nightly", "v1.0.3-rc.3-x"])
        self.assertEqual(decision, release_lane.TAG)
        self.assertEqual(reference, None)


class TreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="release-lane-")
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name)

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def write_server(self, version: str) -> None:
        self.write("crates/server/Cargo.toml", SERVER_MANIFEST.format(version=version))


class ServerVersionTest(TreeTest):
    def test_reads_the_server_package_version(self) -> None:
        self.write_server("1.2.3")
        self.assertEqual(release_lane.server_version(self.root), "1.2.3")

    def test_rejects_unreleasable_versions(self) -> None:
        self.write_server("1.2")
        with self.assertRaises(release_lane.LaneError):
            release_lane.server_version(self.root)

    def test_rejects_a_missing_manifest(self) -> None:
        with self.assertRaises(release_lane.LaneError):
            release_lane.server_version(self.root)


class ChangelogSectionTest(TreeTest):
    def setUp(self) -> None:
        super().setUp()
        self.write("CHANGELOG.md", CHANGELOG)

    def test_extracts_the_exact_section(self) -> None:
        section = release_lane.changelog_section(self.root, "1.0.3")
        self.assertIn("Final fixes.", section)
        self.assertNotIn("Candidate fixes.", section)
        self.assertNotIn("Next features.", section)

    def test_extracts_the_final_section_at_end_of_file(self) -> None:
        self.assertIn("Next features.", release_lane.changelog_section(self.root, "1.1.0"))

    def test_missing_section_fails(self) -> None:
        with self.assertRaises(release_lane.LaneError):
            release_lane.changelog_section(self.root, "9.9.9")

    def test_empty_section_fails(self) -> None:
        self.write("CHANGELOG.md", "# Changelog\n\n## [2.0.0]\n\n## [1.0.0]\n\n### Added\n\n- Old.\n")
        with self.assertRaises(release_lane.LaneError):
            release_lane.changelog_section(self.root, "2.0.0")


class BuildBodyTest(TreeTest):
    def setUp(self) -> None:
        super().setUp()
        self.write_server("1.0.3")
        self.write("CHANGELOG.md", CHANGELOG)
        self.write(
            "android/app/build.gradle.kts", GRADLE.format(code=16, name="1.0.2")
        )

    def test_body_carries_notes_android_line_and_asset_contract(self) -> None:
        body = release_lane.build_body(self.root, "1.0.3")
        self.assertIn("Final fixes.", body)
        self.assertIn("`1.0.2`, version code `16`", body)
        self.assertIn("zrotext-v1.0.3-unsigned.apk", body)
        self.assertIn("zrotext-server-v1.0.3-linux-amd64.zip", body)
        self.assertIn("No other files are attached", body)

    def test_missing_changelog_blocks_body_building(self) -> None:
        self.write("CHANGELOG.md", "# Changelog\n")
        with self.assertRaises(release_lane.LaneError):
            release_lane.build_body(self.root, "1.0.3")


class AndroidVersionTest(TreeTest):
    def test_reads_version_name_and_code(self) -> None:
        self.write("android/app/build.gradle.kts", GRADLE.format(code=13, name="0.1.7-rc.3"))
        self.assertEqual(
            release_lane.android_release_version(self.root), ("0.1.7-rc.3", 13)
        )

    def test_rejects_a_manifest_without_versions(self) -> None:
        self.write("android/app/build.gradle.kts", "plugins {}\n")
        with self.assertRaises(release_lane.LaneError):
            release_lane.android_release_version(self.root)


class ReleaseTagWorkflowTest(unittest.TestCase):
    def run_tag_step(self, tagged_commit: str) -> subprocess.CompletedProcess[str]:
        workflow = (
            Path(__file__).resolve().parents[1]
            / ".github/workflows/release-auto.yml"
        ).read_text(encoding="utf-8")
        step = workflow.split("      - name: Create or verify the release tag\n", 1)[1]
        step = step.split("      - name:", 1)[0]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        stubs = r'''
gh() {
  case "$*" in
    'api repos/pboachie/zrotext/git/ref/tags/v1.2.3') return 1 ;;
    'api repos/pboachie/zrotext/git/tags '*) printf '%s\n' synthetic-tag-object ;;
    'api repos/pboachie/zrotext/git/refs '*) return 0 ;;
    'api repos/pboachie/zrotext/commits/v1.2.3 --jq .sha')
      printf '%s\n' "$TEST_TAGGED_COMMIT" ;;
    *) printf 'Unexpected GitHub request: %s\n' "$*" >&2; return 97 ;;
  esac
}
git() { printf 'Unexpected git command\n' >&2; return 98; }
sleep() { printf 'Unexpected retry\n' >&2; return 99; }
'''
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "The release workflow regression needs Bash")
        return subprocess.run(
            [bash, "-c", stubs + script],
            env={
                **os.environ,
                "VERSION": "1.2.3",
                "GITHUB_SHA": "synthetic-merge-commit",
                "TEST_TAGGED_COMMIT": tagged_commit,
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_new_tag_resolves_in_the_publication_repository(self) -> None:
        result = self.run_tag_step("synthetic-merge-commit")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_new_tag_must_resolve_to_the_merge_commit(self) -> None:
        result = self.run_tag_step("another-synthetic-commit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not this merge commit synthetic-merge-commit", result.stderr)


class TagVersionTest(unittest.TestCase):
    def test_only_release_shaped_tags_count(self) -> None:
        self.assertEqual(release_lane.tag_version("v1.0.3-rc.3"), "1.0.3-rc.3")
        self.assertIsNone(release_lane.tag_version("v1.0.3-rc.0"))
        self.assertIsNone(release_lane.tag_version("nightly"))
        self.assertIsNone(release_lane.tag_version("1.0.3"))


if __name__ == "__main__":
    unittest.main()
