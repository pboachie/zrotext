"""The concurrency fixture may launch only the checked-in, cached wrapper."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_ksp_serialization as fixture


class PinnedWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zrotext-wrapper-test-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.android = root / "android"
        self.home = root / "cache"
        self.cwd = root / "fixture"
        self.cwd.mkdir()
        fixture.write(self.android / "gradlew", "synthetic wrapper")
        fixture.write(self.android / "gradlew.bat", "synthetic wrapper")
        fixture.write(self.android / "gradle/wrapper/gradle-wrapper.jar", "synthetic wrapper JAR")
        self.properties = self.android / "gradle/wrapper/gradle-wrapper.properties"
        fixture.write(self.properties,
                      (fixture.ANDROID / "gradle/wrapper/gradle-wrapper.properties").read_text())
        # Known official PathAssembler key for the checked-in 9.9.0 URL.
        self.cache = self.home / "wrapper/dists/gradle-9.9.0-bin/k7t1gqg1ujh3kgq8oiu7hqi4"
        self.dist = self.cache / "gradle-9.9.0"
        self.marker = self.cache / "gradle-9.9.0-bin.zip.ok"
        self.launcher = self.dist / "lib/gradle-launcher-9.9.0.jar"
        fixture.write(self.marker, "")
        fixture.write(self.launcher, "synthetic launcher")
        self.addCleanup(patch.stopall)
        patch.object(fixture, "ANDROID", self.android).start()
        patch.dict(os.environ, {"GRADLE_USER_HOME": str(self.home)}, clear=True).start()
        self.launch = patch.object(fixture.subprocess, "run").start()

    def test_fixed_repository_wrapper_preserves_fixture_cwd_and_bounds(self):
        fixture.run_fixture(self.cwd)
        arguments, options = self.launch.call_args
        command = arguments[0]
        expected = self.android / ("gradlew.bat" if os.name == "nt" else "gradlew")
        self.assertEqual(command[:3], [str(expected), "--gradle-user-home", str(self.home)])
        self.assertEqual(options["cwd"], self.cwd)
        self.assertEqual(options["timeout"], 240)
        self.assertIn("--offline", command)
        self.assertIn("--configuration-cache-problems=fail", command)
        self.assertNotIn("shell", options)
        self.assertNotIn("env", options)

    def refusal(self):
        with self.assertRaises(AssertionError):
            fixture.run_fixture(self.cwd)
        self.launch.assert_not_called()

    def test_missing_marker_refuses_before_launch(self):
        self.marker.unlink()
        self.refusal()

    def test_missing_launcher_refuses_before_launch(self):
        self.launcher.unlink()
        self.refusal()

    def test_wrong_distribution_version_refuses_before_launch(self):
        self.dist.rename(self.cache / "gradle-9.8.2")
        self.refusal()

    def test_extra_distribution_directory_refuses_before_launch(self):
        (self.cache / "extra").mkdir()
        self.refusal()

    def test_url_escape_is_not_an_executable_selector(self):
        fixture.write(self.properties, self.properties.read_text().replace(
            "gradle-9.9.0-bin.zip", "../custom-bin.zip"))
        self.refusal()

    def test_alternate_cache_layout_refuses(self):
        fixture.write(self.properties, self.properties.read_text().replace(
            "distributionPath=wrapper/dists", "distributionPath=../outside"))
        self.refusal()

    def test_missing_checksum_refuses(self):
        fixture.write(self.properties, "\n".join(line for line in self.properties.read_text().splitlines()
                                               if not line.startswith("distributionSha256Sum=")))
        self.refusal()

    def test_retained_archive_must_match_pinned_checksum(self):
        fixture.write(self.cache / "gradle-9.9.0-bin.zip", "wrong archive")
        self.refusal()

    def test_conflicting_jvm_cache_override_refuses(self):
        with patch.dict(os.environ, {"JAVA_TOOL_OPTIONS": "-Dgradle.user.home=elsewhere"}):
            self.refusal()

    def test_job_local_java_tls_options_remain_allowed(self):
        with patch.dict(os.environ, {"JAVA_TOOL_OPTIONS": "-Djavax.net.ssl.trustStore=gradle.user.home/cacerts"}):
            fixture.run_fixture(self.cwd)
        self.launch.assert_called_once()

    def test_empty_cache_home_refuses(self):
        with patch.dict(os.environ, {"GRADLE_USER_HOME": ""}):
            self.refusal()

    def test_linked_cache_entry_refuses(self):
        with patch.object(Path, "is_symlink", autospec=True,
                          side_effect=lambda path: path == self.launcher):
            self.refusal()

    def test_junction_cache_entry_refuses(self):
        with patch.object(Path, "is_junction", autospec=True,
                          side_effect=lambda path: path == self.cache):
            self.refusal()

    def test_linked_repository_wrapper_refuses(self):
        wrapper = self.android / ("gradlew.bat" if os.name == "nt" else "gradlew")
        with patch.object(Path, "is_symlink", autospec=True,
                          side_effect=lambda path: path == wrapper):
            self.refusal()


if __name__ == "__main__":
    unittest.main()
