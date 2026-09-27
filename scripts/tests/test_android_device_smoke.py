# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("android_device_smoke", Path(__file__).resolve().parents[1] / "android_device_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def result(class_name, name="sample", code=0):
    return f"INSTRUMENTATION_STATUS: class={class_name}\nINSTRUMENTATION_STATUS: test={name}\nINSTRUMENTATION_STATUS_CODE: {code}\n"


class DeviceSmokeTests(unittest.TestCase):
    def test_exact_selected_counts_pass(self):
        output = result(smoke.PRECONDITIONS, code=1) + result(smoke.PRECONDITIONS)
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", {smoke.PRECONDITIONS: 1})
        for index in range(5):
            output += result(smoke.ACCESSIBILITY, f"example{index}")
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 5})
        for index in range(12):
            output += result(smoke.MANIFEST_AUTHORITY, f"example{index}")
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n",
                             {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 5, smoke.MANIFEST_AUTHORITY: 12})

    def test_failure_skips_and_incomplete_runs_fail(self):
        for code in [-1, -2, -3, -4]:
            with self.subTest(code=code), self.assertRaises(ValueError):
                smoke.verify_results(result(smoke.PRECONDITIONS, code=code) + "INSTRUMENTATION_CODE: -1\n", {smoke.PRECONDITIONS: 1})
        for output in ["", "INSTRUMENTATION_CODE: -1\n", result(smoke.PRECONDITIONS),
                       result(smoke.PRECONDITIONS) + "INSTRUMENTATION_CODE: 0\n"]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                smoke.verify_results(output, {smoke.PRECONDITIONS: 1})

    def test_unexpected_duplicate_and_extra_completions_fail(self):
        for output in [result("other.Test"), result(smoke.PRECONDITIONS) * 2,
                       result(smoke.PRECONDITIONS) + result(smoke.PRECONDITIONS, "extra")]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", {smoke.PRECONDITIONS: 1})

    def test_accessibility_is_selected_only_when_source_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(smoke.selected_tests(root), {smoke.PRECONDITIONS: 1})
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/GatewayAccessibilityDeviceTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            self.assertEqual(smoke.selected_tests(root), {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 5})

    def test_manifest_authority_is_selected_only_when_source_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/ManifestAuthorityDeviceTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            self.assertEqual(smoke.selected_tests(root), {smoke.PRECONDITIONS: 1, smoke.MANIFEST_AUTHORITY: 12})

    def test_missing_skipped_or_unselected_manifest_corpus_fails(self):
        expected = {smoke.PRECONDITIONS: 1, smoke.MANIFEST_AUTHORITY: 12}
        partial = result(smoke.PRECONDITIONS)
        for index in range(11):
            partial += result(smoke.MANIFEST_AUTHORITY, f"example{index}")
        for output in [partial, partial + result(smoke.MANIFEST_AUTHORITY, "last", -3),
                       partial + result(smoke.MANIFEST_AUTHORITY, "example0")]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", expected)
        with self.assertRaises(ValueError):
            smoke.verify_results(result(smoke.MANIFEST_AUTHORITY) + "INSTRUMENTATION_CODE: -1\n",
                                 {smoke.PRECONDITIONS: 1})

    def test_network_service_requires_one_actual_completed_test(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/NetworkServiceDeviceTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            expected = {smoke.PRECONDITIONS: 1, smoke.NETWORK_SERVICE: 1}
            self.assertEqual(smoke.selected_tests(root), expected)
            complete = result(smoke.PRECONDITIONS) + result(smoke.NETWORK_SERVICE)
            smoke.verify_results(complete + "INSTRUMENTATION_CODE: -1\n", expected)
            for incomplete in (result(smoke.PRECONDITIONS), result(smoke.PRECONDITIONS) + result(smoke.NETWORK_SERVICE, code=-3)):
                with self.assertRaises(ValueError):
                    smoke.verify_results(incomplete + "INSTRUMENTATION_CODE: -1\n", expected)
