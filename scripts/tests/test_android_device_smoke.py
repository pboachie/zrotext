# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import io
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("android_device_smoke", Path(__file__).resolve().parents[1] / "android_device_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def result(class_name, name="sample", code=0):
    return f"INSTRUMENTATION_STATUS: class={class_name}\nINSTRUMENTATION_STATUS: test={name}\nINSTRUMENTATION_STATUS_CODE: {code}\n"


class DeviceSmokeTests(unittest.TestCase):
    def test_failed_identity_is_public_only_and_preserves_nonpassing_status(self):
        expected = {smoke.PRECONDITIONS: 1}
        for code in (-1, -2, -3, -4):
            with self.subTest(code=code), mock.patch.object(smoke, "public_test_methods", return_value={"sample"}):
                output = result(smoke.PRECONDITIONS, code=code).replace(
                    "INSTRUMENTATION_STATUS_CODE", "INSTRUMENTATION_STATUS: stack=synthetic-private-diagnostic\nINSTRUMENTATION_STATUS_CODE")
                with self.assertRaises(ValueError) as failure:
                    smoke.verify_results(output, expected)
                self.assertIn(smoke.PRECONDITIONS, str(failure.exception))
                self.assertIn("test=sample", str(failure.exception))
                self.assertIn(f"status={code}", str(failure.exception))
                self.assertNotIn("synthetic-private-diagnostic", str(failure.exception))
        with mock.patch.object(smoke, "public_test_methods", return_value=set()):
            with self.assertRaises(ValueError) as failure:
                smoke.verify_results(result("unpublished.Class", "unpublishedMethod", -2), expected)
            self.assertNotIn("unpublished", str(failure.exception))
        with self.assertRaisesRegex(ValueError, "Malformed instrumentation status code") as failure:
            smoke.verify_results("INSTRUMENTATION_STATUS_CODE: synthetic-private-diagnostic", expected)
        self.assertNotIn("synthetic-private-diagnostic", str(failure.exception))

    def test_failure_retains_only_bounded_private_output_and_success_retains_nothing(self):
        expected = {smoke.PRECONDITIONS: 1}
        output = result(smoke.PRECONDITIONS, code=-2) + "x" * (smoke.MAX_PRIVATE_EVIDENCE_BYTES + 100)
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(smoke.tempfile, "mkdtemp", return_value=directory), contextlib.redirect_stdout(io.StringIO()) as printed:
                with self.assertRaises(ValueError):
                    smoke.verify_with_private_evidence(output, expected)
            evidence = Path(directory, "instrumentation.txt").read_bytes()
            self.assertEqual(len(evidence), smoke.MAX_PRIVATE_EVIDENCE_BYTES)
            self.assertNotIn("INSTRUMENTATION_STATUS", printed.getvalue())
        with mock.patch.object(smoke.tempfile, "mkdtemp") as temporary:
            smoke.verify_with_private_evidence(result(smoke.PRECONDITIONS) + "INSTRUMENTATION_CODE: -1\n", expected)
            temporary.assert_not_called()

    def test_outbound_corpus_requires_exact_ten_successful_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/OutboundEnvelopeDeviceTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            expected = {smoke.PRECONDITIONS: 1, smoke.OUTBOUND_ENVELOPE: 10}
            self.assertEqual(smoke.selected_tests(root), expected)
            output = result(smoke.PRECONDITIONS)
            for index in range(10):
                output += result(smoke.OUTBOUND_ENVELOPE, f"case{index}")
            smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", expected)
            for bad in [output.replace(result(smoke.OUTBOUND_ENVELOPE, "case9"), ""),
                        output.replace(result(smoke.OUTBOUND_ENVELOPE, "case9"), result(smoke.OUTBOUND_ENVELOPE, "case9", -3)),
                        output + result(smoke.OUTBOUND_ENVELOPE, "case9")]:
                with self.assertRaises(ValueError):
                    smoke.verify_results(bad + "INSTRUMENTATION_CODE: -1\n", expected)

    def test_root_storage_requires_all_three_cases_with_no_skips(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/Draft02RootStorageDeviceTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            expected = {smoke.PRECONDITIONS: 1, smoke.ROOT_STORAGE: 3}
            self.assertEqual(smoke.selected_tests(root), expected)
            output = result(smoke.PRECONDITIONS)
            for index in range(3):
                output += result(smoke.ROOT_STORAGE, f"case{index}")
            custody = "INSTRUMENTATION_RESULT: rootStorageCustody=unsupported\n"
            self.assertEqual(smoke.verify_results(output + custody + "INSTRUMENTATION_CODE: -1\n", expected), "unsupported")
            for bad_custody in ["", custody * 2, custody.replace("unsupported", "unknown")]:
                with self.assertRaises(ValueError):
                    smoke.verify_results(output + bad_custody + "INSTRUMENTATION_CODE: -1\n", expected)
            for bad in [output.replace(result(smoke.ROOT_STORAGE, "case2"), ""),
                        output.replace(result(smoke.ROOT_STORAGE, "case2"), result(smoke.ROOT_STORAGE, "case2", -3))]:
                with self.assertRaises(ValueError):
                    smoke.verify_results(bad + custody + "INSTRUMENTATION_CODE: -1\n", expected)
    def test_sealed_preparation_exact_counts_and_custody_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ["SealedBodyDeviceTest", "SealedPreparationDeviceTest"]:
                source = root / f"android/app/src/androidTest/java/org/zrotext/gateway/{name}.kt"
                source.parent.mkdir(parents=True, exist_ok=True)
                source.touch()
            expected = {smoke.PRECONDITIONS: 1, smoke.SEALED_BODY: 5, smoke.SEALED_PREPARATION: 2}
            self.assertEqual(smoke.selected_tests(root), expected)
            output = "".join(result(cls, f"case{i}") for cls, count in expected.items() for i in range(count))
            suffix = "INSTRUMENTATION_RESULT: preparationCustody=unsupported\nINSTRUMENTATION_CODE: -1\n"
            smoke.verify_results(output + suffix, expected)
            for bad in [suffix.replace("unsupported", "unknown"), "INSTRUMENTATION_CODE: -1\n",
                        suffix.replace("INSTRUMENTATION_CODE", "INSTRUMENTATION_RESULT: preparationCustody=unsupported\nINSTRUMENTATION_CODE")]:
                with self.assertRaises(ValueError):
                    smoke.verify_results(output + bad, expected)
            for bad in [output.replace(result(smoke.SEALED_BODY, "case4"), ""),
                        output.replace(result(smoke.SEALED_BODY, "case4"), result(smoke.SEALED_BODY, "case4", -3))]:
                with self.assertRaises(ValueError):
                    smoke.verify_results(bad + suffix, expected)

    def test_exact_selected_counts_pass(self):
        output = result(smoke.PRECONDITIONS, code=1) + result(smoke.PRECONDITIONS)
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", {smoke.PRECONDITIONS: 1})
        for name in sorted(smoke.ACCESSIBILITY_METHODS):
            output += result(smoke.ACCESSIBILITY, name)
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 6})
        for index in range(12):
            output += result(smoke.MANIFEST_AUTHORITY, f"example{index}")
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n",
                             {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 6, smoke.MANIFEST_AUTHORITY: 12})

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
            expected = {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 6}
            self.assertEqual(smoke.selected_tests(root), expected)
            partial = result(smoke.PRECONDITIONS) + ''.join(
                result(smoke.ACCESSIBILITY, name) for name in sorted(smoke.ACCESSIBILITY_METHODS)
                if name != 'homeObservationsKeepReadOnlyLabelsAndReadingOrderAtCurrentTextScale')
            with self.assertRaises(ValueError):
                smoke.verify_results(partial + 'INSTRUMENTATION_CODE: -1\n', expected)
            smoke.verify_results(partial + result(smoke.ACCESSIBILITY, 'homeObservationsKeepReadOnlyLabelsAndReadingOrderAtCurrentTextScale')
                                 + 'INSTRUMENTATION_CODE: -1\n', expected)

    def test_same_count_cannot_replace_home_acceptance_with_another_test(self):
        expected = {smoke.ACCESSIBILITY: 6}
        home = "homeObservationsKeepReadOnlyLabelsAndReadingOrderAtCurrentTextScale"
        output = "".join(result(smoke.ACCESSIBILITY, name) for name in smoke.ACCESSIBILITY_METHODS)
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", expected)
        substituted = output.replace(result(smoke.ACCESSIBILITY, home),
                                     result(smoke.ACCESSIBILITY, "unrelatedPassingTest"))
        with self.assertRaisesRegex(ValueError, "exact Home acceptance corpus"):
            smoke.verify_results(substituted + "INSTRUMENTATION_CODE: -1\n", expected)

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

    def test_conversation_entry_is_selected_and_opted_in_only_when_present(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            absent = smoke.selected_tests(root)
            self.assertNotIn("entryOptInIsolatedEmulator", smoke.instrumentation_arguments(absent))
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/ConversationEntryOptInDeviceTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            expected = {smoke.PRECONDITIONS: 1, smoke.ENTRY_OPT_IN: 1}
            self.assertEqual(smoke.selected_tests(root), expected)
            arguments = smoke.instrumentation_arguments(expected)
            self.assertIn(smoke.ENTRY_OPT_IN, arguments[arguments.index("class") + 1].split(","))
            position = arguments.index("entryOptInIsolatedEmulator")
            self.assertEqual(arguments[position - 1:position + 2], ["-e", "entryOptInIsolatedEmulator", "true"])

    def test_missing_skipped_or_substituted_conversation_entry_never_passes(self):
        expected = {smoke.PRECONDITIONS: 1, smoke.ENTRY_OPT_IN: 1}
        prefix = result(smoke.PRECONDITIONS)
        suffix = "INSTRUMENTATION_CODE: -1\n"
        smoke.verify_results(prefix + result(smoke.ENTRY_OPT_IN, smoke.ENTRY_OPT_IN_METHOD) + suffix, expected)
        for entry in ("", result(smoke.ENTRY_OPT_IN, smoke.ENTRY_OPT_IN_METHOD, -3),
                      result(smoke.ENTRY_OPT_IN, "unrelatedPassingTest")):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                smoke.verify_results(prefix + entry + suffix, expected)

    def test_enrollment_consent_is_selected_with_explicit_emulator_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/EnrollmentConsentBoundaryDeviceTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            name = smoke.PACKAGE + "EnrollmentConsentBoundaryDeviceTest"
            expected = {smoke.PRECONDITIONS: 1, name: 1}
            self.assertEqual(smoke.selected_tests(root), expected)
            arguments = smoke.instrumentation_arguments(expected)
            self.assertIn(name, arguments[arguments.index("class") + 1].split(","))
            self.assertIn("entryOptInIsolatedEmulator", arguments)

    def test_enrollment_consent_requires_its_exact_successful_method(self):
        name = smoke.PACKAGE + "EnrollmentConsentBoundaryDeviceTest"
        method = "enrollmentAndIndependentChoicesRefuseWithoutCreatingAuthority"
        expected = {smoke.PRECONDITIONS: 1, name: 1}
        prefix = result(smoke.PRECONDITIONS)
        suffix = "INSTRUMENTATION_CODE: -1\n"
        smoke.verify_results(prefix + result(name, method) + suffix, expected)
        for entry in ("", result(name, method, -3), result(name, "unrelatedPassingTest")):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                smoke.verify_results(prefix + entry + suffix, expected)
