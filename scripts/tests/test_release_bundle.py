#!/usr/bin/env python3
"""Cross-artifact release binding regressions."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_bundle as release_module
from release_bundle import (WEB_FILES, file_set_digest, migrations, read_json,
                            release_bundle, verify_tag)


ROOT = Path(__file__).resolve().parents[2]
TAG = "v0.1.6-rc.1"
COMMIT = "a" * 40
HEX = "b" * 64


def candidate(commit=COMMIT):
    return {
        "source_commit": commit,
        "embedded_asset": "assets/zrotext-source-commit.txt",
        "unsigned_apk_sha256": HEX,
        "sbom_sha256": HEX,
        "apk": f"zrotext-android-{commit[:12]}-candidate.apk",
        "apk_sha256": HEX,
        "signing_certificate_sha256": HEX,
        "apk_identity": {
            "package": "org.zrotext.gateway", "version_code": 7,
            "version_name": "0.1.6-m1-inbound-metadata", "min_sdk": 28,
            "target_sdk": 36,
        },
        "min_sdk_verified": 28,
    }


def image(commit=COMMIT, tag=TAG):
    return {
        "schema_version": 1, "source_tag": tag, "source_commit": commit,
        "image": "ghcr.io/pboachie/zrotext", "build_tag": f"{tag}-run123-1",
        "image_digest": "sha256:" + HEX,
        "image_ref": "ghcr.io/pboachie/zrotext@sha256:" + HEX,
        "workflow_run_id": 123, "workflow_run_attempt": 1,
    }


class ReleaseBundleTest(unittest.TestCase):
    def bundle(self, candidate_receipt=None, image_receipt=None):
        return release_bundle(ROOT, TAG, COMMIT, "staging",
                              candidate_receipt or candidate(), "c" * 64,
                              image_receipt or image(), "d" * 64)

    def test_binds_one_tag_commit_android_server_web_protocol_and_migrations(self):
        result = self.bundle()
        self.assertEqual(result["bundle_version"], TAG)
        self.assertEqual(result["source_commit"], COMMIT)
        self.assertEqual(result["android"]["version_code"], 7)
        self.assertEqual(result["server"]["image_digest"], "sha256:" + HEX)
        self.assertEqual(result["web"]["static_sha256"], file_set_digest(ROOT, WEB_FILES))
        self.assertEqual(result["protocol"]["device_stream_version"], "v1")
        self.assertEqual(result["protocol"]["sealed_content"], "disabled")
        self.assertGreaterEqual(result["database"]["migration_last"], 21)

    def test_rejects_cross_commit_or_cross_tag_receipts(self):
        with self.assertRaisesRegex(ValueError, "Android receipt source"):
            self.bundle(candidate_receipt=candidate("e" * 40))
        with self.assertRaisesRegex(ValueError, "Server image receipt source"):
            self.bundle(image_receipt=image(tag="v0.1.7-rc.1"))

    def test_rejects_mutated_image_reference_and_android_identity(self):
        bad_image = image()
        bad_image["image_ref"] = "ghcr.io/pboachie/zrotext@sha256:" + "f" * 64
        with self.assertRaisesRegex(ValueError, "image reference"):
            self.bundle(image_receipt=bad_image)
        bad_candidate = candidate()
        bad_candidate["apk_identity"]["package"] = "org.other"
        with self.assertRaisesRegex(ValueError, "Android package"):
            self.bundle(candidate_receipt=bad_candidate)

    def test_android_version_core_must_match_bundle_version(self):
        bad_candidate = candidate()
        bad_candidate["apk_identity"]["version_name"] = "0.2.0-experimental"
        with self.assertRaisesRegex(ValueError, "bundle version core"):
            self.bundle(candidate_receipt=bad_candidate)

    def test_web_digest_changes_with_content_and_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in WEB_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"original")
            first = file_set_digest(root, WEB_FILES)
            (root / WEB_FILES[0]).write_bytes(b"changed")
            self.assertNotEqual(first, file_set_digest(root, WEB_FILES))
            self.assertNotEqual(first, file_set_digest(root, tuple(reversed(WEB_FILES))))

    def test_duplicate_json_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text('{"source_commit":"a","source_commit":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate JSON field"):
                read_json(path)

    def test_migration_digest_rejects_unbound_sql_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migration_dir = root / "deploy/compose/migrations"
            migration_dir.mkdir(parents=True)
            (migration_dir / "001_foundation.sql").write_text("SELECT 1;", encoding="utf-8")
            self.assertEqual(migrations(root)[0], 1)
            (migration_dir / "invalid.sql").write_text("SELECT 2;", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Invalid migration filename"):
                migrations(root)

    def test_receipts_require_private_fixed_artifact_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / ".zrotext" / "release-bundle"
            with patch.object(release_module, "ARTIFACT_DIR", private):
                with self.assertRaisesRegex(ValueError, "missing or linked"):
                    release_module.checked_artifact_dir()
                private.mkdir(parents=True, mode=0o700)
                release_module.checked_artifact_dir()

    def test_tag_must_be_annotated_on_main_and_exact_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

            git("init", "-q", "-b", "main")
            (root / "file.txt").write_text("source", encoding="utf-8")
            git("add", "file.txt")
            git("-c", "user.name=Test", "-c", "user.email=test@example.test",
                "commit", "-qm", "source")
            commit = git("rev-parse", "HEAD")
            git("update-ref", "refs/remotes/origin/main", commit)
            git("tag", "v0.1.6-rc.1")
            with self.assertRaisesRegex(ValueError, "annotated"):
                verify_tag(root, TAG, commit)
            git("tag", "-d", TAG)
            git("-c", "user.name=Test", "-c", "user.email=test@example.test",
                "tag", "-a", TAG, "-m", "release")
            verify_tag(root, TAG, commit)
            (root / "file.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "clean"):
                verify_tag(root, TAG, commit)


if __name__ == "__main__":
    unittest.main()
