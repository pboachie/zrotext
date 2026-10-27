#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exact complete-class protocol tests; these never invoke a device or provider."""

import ast
from pathlib import Path
import re
import unittest

import android_preparation_probe as probe


METHODS = frozenset({
    "enrolledRecipientExposesNonExportableAgreeKeyClaims",
    "crossClientSealOpensThroughNativeBridgeAndRejectsTampering",
    "maintainedPublicSenderOpensThroughExistingKeystoreWithoutChangingCallerKey",
    "maintainedSenderWithdrawalRefusesEveryWaitAndClearsTheScopedCallback",
    "lostRecipientKeyRefusesWithoutRegeneration",
    "currentAdmissionRefusesAtEveryHardwareWaitAndCannotLeakTheGuardIntoAnotherOpen",
    "revokedRecipientKeyRefusesLaterOpens",
})


def protocol(methods, *, completion=0, test_class=probe.HPKE_TEST):
    records = []
    for method in methods:
        for code in (1, completion):
            records.extend([
                f"INSTRUMENTATION_STATUS: class={test_class}",
                f"INSTRUMENTATION_STATUS: test={method}",
                f"INSTRUMENTATION_STATUS_CODE: {code}",
            ])
    return "\n".join(records + ["INSTRUMENTATION_CODE: -1", ""])


class MaintainedProviderMethodsTest(unittest.TestCase):
    def test_accepts_exact_seven_distinct_successful_completions(self):
        probe.validate_maintained_provider(protocol(sorted(METHODS)))

    def test_manifest_matches_every_actual_annotated_class_method(self):
        root = Path(__file__).resolve().parents[1]
        source = root / "android/app/src/androidTest/java/org/zrotext/gateway/WolfHpkeKeystoreBridgeDeviceTest.kt"
        methods = re.findall(r"@Test\s+fun\s+(\w+)\s*\(", source.read_text(encoding="utf-8"))
        self.assertEqual(len(methods), len(set(methods)))
        self.assertEqual(set(methods), METHODS)
        self.assertEqual(probe.HPKE_METHODS, METHODS)

    def test_rejects_each_missing_completion_including_both_sender_controls(self):
        for missing in METHODS:
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                probe.validate_maintained_provider(protocol(sorted(METHODS - {missing})))

    def test_rejects_duplicate_completion_even_with_all_expected_names(self):
        for duplicate in METHODS:
            with self.subTest(duplicate=duplicate), self.assertRaises(ValueError):
                probe.validate_maintained_provider(protocol(sorted(METHODS) + [duplicate]))

    def test_rejects_skipped_or_failed_status_without_treating_it_as_a_completion(self):
        for code in (-2, -3, -4):
            with self.subTest(code=code), self.assertRaises(ValueError):
                probe.validate_maintained_provider(protocol(sorted(METHODS), completion=code))

    def test_rejects_same_count_unknown_method_and_additional_unknown_method(self):
        names = sorted(METHODS)
        for bad in (names[:-1] + ["unselectedProviderMethod"], names + ["unselectedProviderMethod"]):
            with self.subTest(methods=bad), self.assertRaises(ValueError):
                probe.validate_maintained_provider(protocol(bad))

    def test_rejects_an_unrelated_class_even_if_method_names_and_count_match(self):
        with self.assertRaises(ValueError):
            probe.validate_maintained_provider(protocol(sorted(METHODS), test_class="unselected.ProviderClass"))

    def test_actual_invocation_keeps_the_closed_complete_class_selector(self):
        source = Path(probe.__file__).read_text(encoding="utf-8")
        calls = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == "device"
                 and any(isinstance(arg, ast.Name) and arg.id == "HPKE_TEST" for arg in node.args)]
        self.assertEqual(len(calls), 1)
        args = calls[0].args
        self.assertEqual([arg.value for arg in args[:10]],
                         ["shell", "am", "instrument", "-w", "-r", "-e", "isolatedPreparationProbe", "true", "-e", "class"])
        self.assertIsInstance(args[10], ast.Name)
        self.assertEqual(args[10].id, "HPKE_TEST")
        self.assertEqual(len(args), 12)


if __name__ == "__main__":
    unittest.main()
