# SPDX-License-Identifier: AGPL-3.0-only
"""Candidate identity and APK isolation failures must stop before emulator operations."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import conversation_compiled_acceptance as acceptance


class CandidateIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = [self.root / "android/app/build/outputs/apk/debug/app-debug.apk",
                          self.root / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"]
        for index, artifact in enumerate(self.artifacts):
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(bytes([index]))
        self.hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in self.artifacts]
        self.commit = "a" * 40
        self.head = self.commit
        self.dirty = ""
        self.permission = "android.permission.INTERNET"
        self.test_target = acceptance.APP
        self.test_only = True

    def command(self, args):
        if "rev-parse" in args:
            return self.head
        if "status" in args:
            return self.dirty
        if args[0] != "fixture-aapt":
            self.fail("Candidate preflight attempted an unexpected command")
        package = acceptance.APP + (".test" if "androidTest" in args[3] else "")
        if args[2] == "badging":
            permission = "" if package.endswith(".test") else f"uses-permission: name='{self.permission}'"
            return f"package: name='{package}'\n{permission}"
        tree = 'android:targetPackage="' + self.test_target + '"'
        if self.test_only:
            tree += " android:testOnly(0x01010272)=(type 0x12)0xffffffff"
        return tree

    def preflight(self):
        with patch.object(acceptance, "run", side_effect=self.command):
            return acceptance.preflight(self.root, "fixture-aapt", self.commit, *self.hashes)

    def test_exact_clean_hash_pinned_isolated_artifacts_pass_host_preflight(self):
        self.assertEqual(tuple(self.artifacts), self.preflight())

    def test_candidate_change_stops_before_aapt_or_adb(self):
        self.head = "b" * 40
        with self.assertRaisesRegex(ValueError, "commit changed"):
            self.preflight()

    def test_dirty_source_cannot_be_claimed_as_candidate(self):
        self.dirty = " M android/example.kt"
        with self.assertRaisesRegex(ValueError, "frozen and clean"):
            self.preflight()

    def test_artifact_mutation_after_hash_capture_is_refused(self):
        self.artifacts[1].write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "hash changed"):
            self.preflight()

    def test_radio_permission_is_refused(self):
        self.permission = "android.permission.SEND_SMS"
        with self.assertRaisesRegex(ValueError, "isolation failed"):
            self.preflight()

    def test_non_test_artifact_or_wrong_instrumentation_target_is_refused(self):
        self.test_only = False
        with self.assertRaisesRegex(ValueError, "isolation failed"):
            self.preflight()
        self.test_only = True
        self.test_target = "org.example.other"
        with self.assertRaisesRegex(ValueError, "another application"):
            self.preflight()


if __name__ == "__main__":
    unittest.main()
