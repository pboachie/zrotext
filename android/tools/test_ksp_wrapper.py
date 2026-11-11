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
        root = Path(self.temp.name).resolve()
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

    def link_directory(self, target, link):
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(target), str(link))
        else:
            link.symlink_to(target, target_is_directory=True)
        self.addCleanup(link.rmdir if os.name == "nt" else link.unlink)

    def test_relative_existing_home_refuses_before_launch(self):
        previous = Path.cwd()
        try:
            os.chdir(self.home.parent)
            with patch.dict(os.environ, {"GRADLE_USER_HOME": "cache"}):
                self.refusal()
        finally:
            os.chdir(previous)

    def test_actual_ancestor_link_alias_refuses_before_launch(self):
        alias = self.home.parent / "alias"
        self.link_directory(self.home.parent, alias)
        with patch.dict(os.environ, {"GRADLE_USER_HOME": str(alias / "cache")}):
            self.refusal()

    def test_actual_linked_home_refuses_before_launch(self):
        alias = self.home.parent / "alias"
        self.link_directory(self.home, alias)
        with patch.dict(os.environ, {"GRADLE_USER_HOME": str(alias)}):
            self.refusal()

    def test_actual_descendant_escape_refuses_before_launch(self):
        outside = self.home.parent / "outside"
        self.dist.rename(outside)
        self.link_directory(outside, self.dist)
        self.refusal()

    def test_resolved_descendant_escape_refuses_before_launch(self):
        original = Path.resolve
        outside = self.home.parent / "outside"
        with patch.object(Path, "resolve", autospec=True,
                          side_effect=lambda path, *args, **kwargs:
                          outside if path == self.launcher else original(path, *args, **kwargs)):
            self.refusal()

    def test_unresolvable_home_refuses_with_generic_error(self):
        self.check_generic_resolution_failure(self.home)

    def test_unresolvable_descendant_refuses_with_generic_error(self):
        self.check_generic_resolution_failure(self.launcher)

    def check_generic_resolution_failure(self, target):
        original = Path.resolve
        for error in (OSError("private-path"), RuntimeError("private-path")):
            with self.subTest(error=type(error).__name__):
                def resolve(path, *args, **kwargs):
                    if path == target:
                        raise error
                    return original(path, *args, **kwargs)
                with patch.object(Path, "resolve", autospec=True, side_effect=resolve):
                    with self.assertRaisesRegex(AssertionError, "^Cannot resolve wrapper path$"):
                        fixture.run_fixture(self.cwd)
                self.launch.assert_not_called()

    def test_uninspectable_path_refuses_with_generic_error(self):
        with patch.object(Path, "lstat", side_effect=OSError("private-path")):
            with self.assertRaisesRegex(AssertionError, "^Cannot inspect wrapper path$"):
                fixture.reparse_attributes(self.home)
        self.launch.assert_not_called()

    def test_canonical_custom_absolute_home_is_allowed(self):
        custom = self.home.parent / "custom-cache"
        self.home.rename(custom)
        with patch.dict(os.environ, {"GRADLE_USER_HOME": str(custom)}):
            fixture.run_fixture(self.cwd)
        self.assertEqual(self.launch.call_args.args[0][1:3],
                         ["--gradle-user-home", str(custom)])

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
