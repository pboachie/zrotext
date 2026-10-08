# SPDX-License-Identifier: AGPL-3.0-only
import contextlib
import io
import importlib.util
import json
import re
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
    def test_shared_compiled_accessibility_corpus_matches_explicit_device_inventory(self):
        source = smoke.ROOT / "android/app/src/sharedTest/java/org/zrotext/gateway/GatewayAccessibilityChecks.kt"
        methods = re.findall(r"@Test\s+fun\s+([A-Za-z_][A-Za-z0-9_]*)", source.read_text(encoding="utf-8"))
        device = smoke.ROOT / "android/app/src/androidTest/java/org/zrotext/gateway/GatewayAccessibilityDeviceTest.kt"
        self.assertRegex(device.read_text(encoding="utf-8"), r"class GatewayAccessibilityDeviceTest\s*:\s*GatewayAccessibilityChecks\(\)")
        self.assertEqual(len(methods), 7)
        self.assertEqual(frozenset(methods), smoke.ACCESSIBILITY_METHODS)
        self.assertEqual(smoke.selected_tests()[smoke.ACCESSIBILITY], len(methods))

    def test_manual_pairing_success_is_required_in_addition_to_all_six_previous_accessibility_cases(self):
        expected = {smoke.ACCESSIBILITY: 7}
        manual = "explicitManualPairingKeepsLabelsAndTokenPasswordSemantics"
        self.assertIn(manual, smoke.ACCESSIBILITY_METHODS)
        previous = "".join(result(smoke.ACCESSIBILITY, name) for name in sorted(smoke.ACCESSIBILITY_METHODS - {manual}))
        final = "INSTRUMENTATION_CODE: -1\n"
        smoke.verify_results(previous + result(smoke.ACCESSIBILITY, manual) + final, expected)
        with self.assertRaisesRegex(ValueError, "exact expected test counts"):
            smoke.verify_results(previous + final, expected)
        for code in (-1, -2, -3, -4):
            with self.subTest(code=code), self.assertRaises(ValueError):
                smoke.verify_results(previous + result(smoke.ACCESSIBILITY, manual, code) + final, expected)
        with self.assertRaisesRegex(ValueError, "exact Home acceptance corpus"):
            smoke.verify_results(previous + result(smoke.ACCESSIBILITY, "unrelatedPassingTest") + final, expected)

    def test_incomplete_runner_reports_selected_public_identity_without_accepting_it(self):
        expected = {smoke.PRECONDITIONS: 2}
        output = result(smoke.PRECONDITIONS, "finished") + result(smoke.PRECONDITIONS, "interrupted", 1)
        output += "INSTRUMENTATION_RESULT: shortMsg=Process crashed.\n"
        with mock.patch.object(smoke, "public_test_methods", return_value={"finished", "interrupted"}):
            report = smoke.public_failure_diagnostic(output, expected)
        self.assertEqual(report["classes"], [{"class": smoke.PRECONDITIONS, "expected": 2, "completed": 1}])
        self.assertEqual(report["status_events"][-1], {"class": smoke.PRECONDITIONS, "test": "interrupted", "status": 1})
        self.assertEqual(report["final_code_count"], 0)
        self.assertTrue(report["process_crash_marker"])
        with self.assertRaisesRegex(ValueError, "exact expected test counts"):
            smoke.verify_results(output, expected)

    def test_public_failure_protocol_never_exposes_unknown_names_stacks_or_runner_messages(self):
        expected = {smoke.PRECONDITIONS: 1}
        private = "synthetic-private-diagnostic"
        output = result(private, private, -2) + result(smoke.PRECONDITIONS, private, 1)
        output += f"INSTRUMENTATION_STATUS: stack={private}\nINSTRUMENTATION_RESULT: shortMsg={private}\n"
        output += f"INSTRUMENTATION_CODE: {private}\n"
        with mock.patch.object(smoke, "public_test_methods", return_value={"sample"}):
            report = smoke.public_failure_diagnostic(output, expected)
        self.assertNotIn(private, json.dumps(report))
        self.assertEqual(report["status_events"][0], {"class": "unselected", "test": "unavailable", "status": -2})
        self.assertEqual(report["status_events"][1]["test"], "unavailable")
        self.assertEqual(report["final_codes"], ["unsupported"])
        self.assertTrue(report["runner_message_present"])
        self.assertFalse(report["process_crash_marker"])

    def test_public_failure_protocol_bounds_events_and_keeps_strict_refusal(self):
        expected = {smoke.PRECONDITIONS: 1}
        output = result(smoke.PRECONDITIONS, code=1) * (smoke.MAX_PUBLIC_STATUS_EVENTS + 3)
        output += "INSTRUMENTATION_CODE: 0\n" * 7
        report = smoke.public_failure_diagnostic(output, expected)
        self.assertEqual(len(report["status_events"]), smoke.MAX_PUBLIC_STATUS_EVENTS)
        self.assertEqual(report["omitted_status_events"], 3)
        self.assertEqual(report["final_codes"], [0] * 4)
        self.assertEqual(report["final_code_count"], 7)
        with self.assertRaises(ValueError):
            smoke.verify_results(output, expected)

    def test_journal_upgrade_is_selected_with_only_its_explicit_emulator_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            absent = smoke.selected_tests(root)
            self.assertNotIn(smoke.JOURNAL_UPGRADE, absent)
            self.assertNotIn("journalUpgradeIsolatedEmulator", smoke.instrumentation_arguments(absent))
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/JournalDeviceUpgradeTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            expected = {smoke.PRECONDITIONS: 1, smoke.JOURNAL_UPGRADE: 2}
            self.assertEqual(smoke.selected_tests(root), expected)
            arguments = smoke.instrumentation_arguments(expected)
            self.assertIn(smoke.JOURNAL_UPGRADE, arguments[arguments.index("class") + 1].split(","))
            position = arguments.index("journalUpgradeIsolatedEmulator")
            self.assertEqual(arguments[position - 1:position + 2], ["-e", "journalUpgradeIsolatedEmulator", "true"])
            self.assertEqual(arguments.count("journalUpgradeIsolatedEmulator"), 1)
            self.assertNotIn("entryOptInIsolatedEmulator", arguments)

    def test_journal_upgrade_requires_both_named_successes_and_retains_custody_results(self):
        expected = {smoke.PRECONDITIONS: 1, smoke.JOURNAL_UPGRADE: 2, smoke.ROOT_STORAGE: 3}
        output = result(smoke.PRECONDITIONS)
        output += "".join(result(smoke.JOURNAL_UPGRADE, name) for name in sorted(smoke.JOURNAL_UPGRADE_METHODS))
        output += "".join(result(smoke.ROOT_STORAGE, f"case{index}") for index in range(3))
        for custody in ("unsupported", "platform-reported-hardware"):
            suffix = f"INSTRUMENTATION_RESULT: rootStorageCustody={custody}\nINSTRUMENTATION_CODE: -1\n"
            self.assertEqual(smoke.verify_results(output + suffix, expected), custody)
        with self.assertRaises(ValueError):
            smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", expected)

    def test_journal_upgrade_missing_old_duplicate_substituted_and_skipped_results_refuse(self):
        expected = {smoke.PRECONDITIONS: 1, smoke.JOURNAL_UPGRADE: 2}
        names = sorted(smoke.JOURNAL_UPGRADE_METHODS)
        cases = [result(smoke.JOURNAL_UPGRADE, name) for name in names]
        prefix, suffix = result(smoke.PRECONDITIONS), "INSTRUMENTATION_CODE: -1\n"
        smoke.verify_results(prefix + "".join(cases) + suffix, expected)
        refused = ["", cases[0], cases[1],
                   result(smoke.JOURNAL_UPGRADE, "installedJournalOpensAtVersionTwelveWithIdentityBoundOutbox"),
                   cases[0] * 2, "".join(cases) + cases[0],
                   cases[0] + result(smoke.JOURNAL_UPGRADE, "unrelatedPassingTest")]
        refused += [cases[0] + result(smoke.JOURNAL_UPGRADE, names[1], code) for code in (-1, -2, -3, -4)]
        for output in refused:
            with self.subTest(output=output), self.assertRaises(ValueError):
                smoke.verify_results(prefix + output + suffix, expected)
        with self.assertRaises(ValueError):
            smoke.verify_results(prefix + "".join(cases) + suffix, {smoke.PRECONDITIONS: 1})
        for ending in ("", "INSTRUMENTATION_CODE: 0\n", suffix * 2,
                       "INSTRUMENTATION_CODE: unsupported\n", suffix + "INSTRUMENTATION_FAILED\n"):
            with self.subTest(ending=ending), self.assertRaises(ValueError):
                smoke.verify_results(prefix + "".join(cases) + ending, expected)
        with self.assertRaises(ValueError):
            smoke.verify_results(prefix + cases[0] + "INSTRUMENTATION_STATUS_CODE: unsupported\n" + suffix, expected)

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
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 7})
        for index in range(12):
            output += result(smoke.MANIFEST_AUTHORITY, f"example{index}")
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n",
                             {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 7, smoke.MANIFEST_AUTHORITY: 12})

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
            expected = {smoke.PRECONDITIONS: 1, smoke.ACCESSIBILITY: 7}
            self.assertEqual(smoke.selected_tests(root), expected)
            partial = result(smoke.PRECONDITIONS) + ''.join(
                result(smoke.ACCESSIBILITY, name) for name in sorted(smoke.ACCESSIBILITY_METHODS)
                if name != 'homeObservationsKeepReadOnlyLabelsAndReadingOrderAtCurrentTextScale')
            with self.assertRaises(ValueError):
                smoke.verify_results(partial + 'INSTRUMENTATION_CODE: -1\n', expected)
            smoke.verify_results(partial + result(smoke.ACCESSIBILITY, 'homeObservationsKeepReadOnlyLabelsAndReadingOrderAtCurrentTextScale')
                                 + 'INSTRUMENTATION_CODE: -1\n', expected)

    def test_same_count_cannot_replace_home_acceptance_with_another_test(self):
        expected = {smoke.ACCESSIBILITY: 7}
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

    def test_hpke_bridge_is_selected_only_when_source_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(smoke.selected_tests(root), {smoke.PRECONDITIONS: 1})
            source = root / "android/app/src/androidTest/java/org/zrotext/gateway/WolfHpkeKeystoreBridgeDeviceTest.kt"
            source.parent.mkdir(parents=True)
            source.touch()
            expected = {smoke.PRECONDITIONS: 1, smoke.HPKE_BRIDGE: 4}
            self.assertEqual(smoke.selected_tests(root), expected)
            self.assertIn(smoke.HPKE_BRIDGE,
                          smoke.instrumentation_arguments(expected)[
                              smoke.instrumentation_arguments(expected).index("class") + 1].split(","))

    def test_hpke_bridge_requires_all_four_completed_cases(self):
        expected = {smoke.PRECONDITIONS: 1, smoke.HPKE_BRIDGE: 4}
        output = result(smoke.PRECONDITIONS)
        for index in range(4):
            output += result(smoke.HPKE_BRIDGE, f"bridgeCase{index}")
        smoke.verify_results(output + "INSTRUMENTATION_CODE: -1\n", expected)
        for bad in [output.replace(result(smoke.HPKE_BRIDGE, "bridgeCase3"), ""),
                    output.replace(result(smoke.HPKE_BRIDGE, "bridgeCase3"),
                                   result(smoke.HPKE_BRIDGE, "bridgeCase3", -2)),
                    output + result(smoke.HPKE_BRIDGE, "bridgeCase3")]:
            with self.subTest(output=bad), self.assertRaises(ValueError):
                smoke.verify_results(bad + "INSTRUMENTATION_CODE: -1\n", expected)
