#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run an explicit no-radio test allowlist on CI's disposable emulator only."""

from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "org.zrotext.gateway."
PRECONDITIONS = PACKAGE + "DevicePreconditionsDeviceTest"
RCS_RISK = PACKAGE + "DefaultSmsAppRcsRiskDeviceTest"
ACCESSIBILITY = PACKAGE + "GatewayAccessibilityDeviceTest"
ACCESSIBILITY_METHODS = frozenset({
    "sectionsAreHeadingsInReadingOrder",
    "statusRegionsExcludeRoutineHeartbeatCounters",
    "homeObservationsKeepReadOnlyLabelsAndReadingOrderAtCurrentTextScale",
    "platformNodesExposeHeadingsAndVisibleStatusRegions",
    "fieldsKeepLabelsAndTokensRemainPasswordFields",
    "explicitManualPairingKeepsLabelsAndTokenPasswordSemantics",
    "actionsRetainNamesAndMinimumTouchTargetsAtCurrentTextScale",
})
MANIFEST_AUTHORITY = PACKAGE + "ManifestAuthorityDeviceTest"
NETWORK_SERVICE = PACKAGE + "NetworkServiceDeviceTest"
OUTBOUND_ENVELOPE = PACKAGE + "OutboundEnvelopeDeviceTest"
ROOT_STORAGE = PACKAGE + "Draft02RootStorageDeviceTest"
SEALED_BODY = PACKAGE + "SealedBodyDeviceTest"
SEALED_PREPARATION = PACKAGE + "SealedPreparationDeviceTest"
ENTRY_OPT_IN = PACKAGE + "ConversationEntryOptInDeviceTest"
ENTRY_OPT_IN_METHOD = "explicitOptInReachesOrdinarySetupAndRejectsMissingCustodyWithoutApproval"
ENROLLMENT_CONSENT = PACKAGE + "EnrollmentConsentBoundaryDeviceTest"
ENROLLMENT_CONSENT_METHOD = "enrollmentAndIndependentChoicesRefuseWithoutCreatingAuthority"
JOURNAL_UPGRADE = PACKAGE + "JournalDeviceUpgradeTest"
JOURNAL_UPGRADE_METHODS = frozenset({
    "versionOnePlatformMigrationRetainsUnknownAttemptAcrossReopen",
    "versionElevenPlatformMigrationRetainsBoundEvidenceAndStopAcrossReopen",
})
HPKE_BRIDGE = PACKAGE + "WolfHpkeKeystoreBridgeDeviceTest"
SERIAL = "emulator-5562"


def selected_tests(root=ROOT):
    expected = {PRECONDITIONS: 1}
    source = root / "android/app/src/androidTest/java/org/zrotext/gateway/DefaultSmsAppRcsRiskDeviceTest.kt"
    if source.is_file():
        expected[RCS_RISK] = 1
    source = root / "android/app/src/androidTest/java/org/zrotext/gateway/GatewayAccessibilityDeviceTest.kt"
    if source.is_file():
        expected[ACCESSIBILITY] = 7
    source = root / "android/app/src/androidTest/java/org/zrotext/gateway/ManifestAuthorityDeviceTest.kt"
    if source.is_file():
        expected[MANIFEST_AUTHORITY] = 12
    source = root / "android/app/src/androidTest/java/org/zrotext/gateway/NetworkServiceDeviceTest.kt"
    if source.is_file():
        expected[NETWORK_SERVICE] = 1
    source = root / "android/app/src/androidTest/java/org/zrotext/gateway/OutboundEnvelopeDeviceTest.kt"
    if source.is_file():
        expected[OUTBOUND_ENVELOPE] = 10
    source = root / "android/app/src/androidTest/java/org/zrotext/gateway/Draft02RootStorageDeviceTest.kt"
    if source.is_file():
        expected[ROOT_STORAGE] = 3
    for name, count in [("SealedBodyDeviceTest", 5), ("SealedPreparationDeviceTest", 2)]:
        if (root / f"android/app/src/androidTest/java/org/zrotext/gateway/{name}.kt").is_file():
            expected[PACKAGE + name] = count
    if (root / "android/app/src/androidTest/java/org/zrotext/gateway/ConversationEntryOptInDeviceTest.kt").is_file():
        expected[ENTRY_OPT_IN] = 1
    if (root / "android/app/src/androidTest/java/org/zrotext/gateway/EnrollmentConsentBoundaryDeviceTest.kt").is_file():
        expected[ENROLLMENT_CONSENT] = 1
    if (root / "android/app/src/androidTest/java/org/zrotext/gateway/JournalDeviceUpgradeTest.kt").is_file():
        expected[JOURNAL_UPGRADE] = 2
    if (root / "android/app/src/androidTest/java/org/zrotext/gateway/WolfHpkeKeystoreBridgeDeviceTest.kt").is_file():
        expected[HPKE_BRIDGE] = 4
    return expected


def instrumentation_arguments(expected):
    args = ["shell", "am", "instrument", "-w", "-r", "-e", "class", ",".join(expected),
            "-e", "a11yIsolatedEmulator", "true",
            "-e", "networkServiceIsolatedEmulator", "true"]
    if ENTRY_OPT_IN in expected or ENROLLMENT_CONSENT in expected:
        args.extend(["-e", "entryOptInIsolatedEmulator", "true"])
    if JOURNAL_UPGRADE in expected:
        args.extend(["-e", "journalUpgradeIsolatedEmulator", "true"])
    return [*args, "org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner"]


MAX_PRIVATE_EVIDENCE_BYTES = 256 * 1024
MAX_PUBLIC_STATUS_EVENTS = 128
MAX_PUBLIC_FAILURE_LOCATIONS = 8
MAX_PUBLIC_SOURCE_POSITIONS = 4
MAX_PUBLIC_SOURCE_LINE = 4096
PUBLIC_FAILURE_SOURCE_FILES = frozenset({
    "ConversationEntryOptInDeviceTest.kt",
    "MainActivity.kt",
    "ConversationUserSetupProvider.kt",
    "ConversationSetupEntrySession.kt",
})
PUBLIC_SOURCE_FRAME = re.compile(
    r"[ \t]*at org\.zrotext\.gateway\.([A-Za-z0-9_$]+)\."
    r"[A-Za-z0-9_$<>]+\(([A-Za-z0-9]+\.kt):([1-9][0-9]{0,3})\)"
)


def public_test_methods(root=ROOT):
    """Only published test method names may appear in a hosted failure message."""
    names = set()
    for source_set in ("androidTest", "sharedTest"):
        directory = root / f"android/app/src/{source_set}/java"
        for source in directory.rglob("*.kt"):
            names.update(re.findall(r"@Test(?:\s*\([^)]*\))?\s+fun\s+([A-Za-z_][A-Za-z0-9_]*)", source.read_text(encoding="utf-8")))
    return names


def failure_identity(status, expected, code):
    class_name = status.get("class")
    if class_name not in expected:
        class_name = "unselected"
    method = status.get("test")
    if class_name == "unselected" or method not in public_test_methods():
        method = "unavailable"
    reported_code = str(code) if code in (-1, -2, -3, -4) else "unsupported"
    return f"class={class_name}; test={method}; status={reported_code}"


def public_failure_diagnostic(output, expected):
    """Report bounded public test identities and protocol state, never raw diagnostics.

    This report is diagnostic only. Exact completion and custody checks below still
    decide acceptance, including after a runner exits without completing a test.
    """
    methods = public_test_methods()
    status = {}
    events = []
    completed = set()
    final_codes = []
    event_count = 0
    final_count = 0
    stack_open = False
    source_positions = []
    failure_locations = []
    for line in output.splitlines():
        if line.startswith("INSTRUMENTATION_STATUS: "):
            key, separator, value = line.removeprefix("INSTRUMENTATION_STATUS: ").partition("=")
            stack_open = bool(separator and key == "stack")
            if separator and key in {"class", "test"}:
                status[key] = value
        elif line.startswith("INSTRUMENTATION_STATUS_CODE: "):
            raw_code = line.removeprefix("INSTRUMENTATION_STATUS_CODE: ")
            code = int(raw_code) if raw_code in {"-4", "-3", "-2", "-1", "0", "1"} else "unsupported"
            class_name = status.get("class")
            method = status.get("test")
            if code == 0 and class_name in expected and method:
                completed.add((class_name, method))
            public_class = class_name if class_name in expected else "unselected"
            public_method = method if public_class != "unselected" and method in methods else "unavailable"
            events.append({"class": public_class, "test": public_method, "status": code})
            events = events[-MAX_PUBLIC_STATUS_EVENTS:]
            # Only this hardcoded test is approved for source-location diagnosis.
            # Runtime messages, exception types and class/method strings stay private.
            if code in (-4, -3, -2, -1) and class_name == ENTRY_OPT_IN and \
                    ENTRY_OPT_IN in expected and method == ENTRY_OPT_IN_METHOD:
                failure_locations.append({"class": ENTRY_OPT_IN, "test": ENTRY_OPT_IN_METHOD,
                                          "source_positions": source_positions or "UNKNOWN"})
                failure_locations = failure_locations[-MAX_PUBLIC_FAILURE_LOCATIONS:]
            event_count += 1
            status = {}
            stack_open = False
            source_positions = []
        elif line.startswith("INSTRUMENTATION_CODE: "):
            stack_open = False
            raw_code = line.removeprefix("INSTRUMENTATION_CODE: ").strip()
            final_codes.append(int(raw_code) if raw_code in {"-1", "0", "1"} else "unsupported")
            final_codes = final_codes[-4:]
            final_count += 1
        elif line.startswith("INSTRUMENTATION_"):
            stack_open = False
        elif stack_open and len(source_positions) < MAX_PUBLIC_SOURCE_POSITIONS:
            frame = PUBLIC_SOURCE_FRAME.fullmatch(line)
            if frame:
                class_name, filename, raw_line = frame.groups()
                if filename in PUBLIC_FAILURE_SOURCE_FILES and \
                        class_name.split("$", 1)[0] == filename.removesuffix(".kt") and \
                        int(raw_line) <= MAX_PUBLIC_SOURCE_LINE:
                    position = {"file": filename, "line": int(raw_line)}
                    if position not in source_positions:
                        source_positions.append(position)
    counts = Counter(cls for cls, _ in completed)
    return {
        "version": 1,
        "classes": [{"class": cls, "expected": count, "completed": counts[cls]}
                    for cls, count in sorted(expected.items())],
        "status_events": events,
        "failure_locations": failure_locations,
        "omitted_status_events": event_count - len(events),
        "final_codes": final_codes,
        "final_code_count": final_count,
        "runner_failure_marker": "INSTRUMENTATION_FAILED" in output,
        "test_failure_marker": "FAILURES!!!" in output,
        "process_crash_marker": "INSTRUMENTATION_RESULT: shortMsg=Process crashed." in output,
        "runner_message_present": "INSTRUMENTATION_RESULT: shortMsg=" in output,
    }


def verify_with_private_evidence(output, expected):
    """Keep bounded raw diagnostics only in owner-created private temporary storage."""
    try:
        return verify_results(output, expected)
    except ValueError:
        # Never upload or print raw platform output: stacks can contain private state.
        directory = Path(tempfile.mkdtemp(prefix="zrotext-device-smoke-failure-"))
        os.chmod(directory, 0o700)
        path = directory / "instrumentation.txt"
        bounded = output[-MAX_PRIVATE_EVIDENCE_BYTES:].encode("utf-8")[-MAX_PRIVATE_EVIDENCE_BYTES:]
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(bounded)
        print("Bounded private instrumentation evidence retained in runner temporary storage")
        print("Public no-radio failure protocol: " + json.dumps(public_failure_diagnostic(output, expected), sort_keys=True))
        raise


def verify_results(output, expected):
    """Require distinct successful test completions, not an adb exit code alone."""
    status = {}
    completed = set()
    counts = Counter()
    for line in output.splitlines():
        if line.startswith("INSTRUMENTATION_STATUS: "):
            key, separator, value = line.removeprefix("INSTRUMENTATION_STATUS: ").partition("=")
            if separator:
                status[key] = value
        elif line.startswith("INSTRUMENTATION_STATUS_CODE: "):
            try:
                code = int(line.removeprefix("INSTRUMENTATION_STATUS_CODE: "))
            except ValueError:
                raise ValueError("Malformed instrumentation status code") from None
            if code not in (0, 1):
                raise ValueError("Instrumentation reported a failed or skipped test: " + failure_identity(status, expected, code))
            identity = (status.get("class"), status.get("test"))
            if identity[0] not in expected or not identity[1]:
                raise ValueError("Instrumentation ran an unexpected test class")
            if code == 0:
                if identity in completed:
                    raise ValueError("Instrumentation duplicated a test completion")
                completed.add(identity)
                counts[identity[0]] += 1
            status = {}
    final_codes = re.findall(r"^INSTRUMENTATION_CODE: (-?\d+)\s*$", output, re.MULTILINE)
    if final_codes != ["-1"] or counts != Counter(expected):
        raise ValueError("Instrumentation did not complete the exact expected test counts")
    if ACCESSIBILITY in expected:
        observed = {name for cls, name in completed if cls == ACCESSIBILITY}
        if observed != ACCESSIBILITY_METHODS:
            raise ValueError("Accessibility did not exercise the exact Home acceptance corpus")
    if ENTRY_OPT_IN in expected:
        observed = {name for cls, name in completed if cls == ENTRY_OPT_IN}
        if observed != {ENTRY_OPT_IN_METHOD}:
            raise ValueError("Conversation entry did not exercise the exact opt-in acceptance test")
    if ENROLLMENT_CONSENT in expected:
        observed = {name for cls, name in completed if cls == ENROLLMENT_CONSENT}
        if observed != {ENROLLMENT_CONSENT_METHOD}:
            raise ValueError("Enrollment did not exercise the exact consent acceptance test")
    if JOURNAL_UPGRADE in expected:
        observed = {name for cls, name in completed if cls == JOURNAL_UPGRADE}
        if observed != JOURNAL_UPGRADE_METHODS:
            raise ValueError("Journal upgrade did not exercise the exact migration and reopen corpus")
    if SEALED_PREPARATION in expected:
        custody = re.findall(r"^INSTRUMENTATION_RESULT: preparationCustody=(.*)$", output, re.MULTILINE)
        if len(custody) != 1 or custody[0].strip() not in ("unsupported", "platform-reported-hardware"):
            raise ValueError("Preparation custody result missing or ambiguous")
    if "INSTRUMENTATION_FAILED" in output or "FAILURES!!!" in output:
        raise ValueError("Instrumentation failed")
    if ROOT_STORAGE in expected:
        custody = re.findall(r"^INSTRUMENTATION_RESULT: rootStorageCustody=([^\r\n]+)", output, re.MULTILINE)
        if len(custody) != 1 or custody[0] not in {"unsupported", "platform-reported-hardware"}:
            raise ValueError("Root storage did not report its exercised custody branch")
        return custody[0]
    return None


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("This runner is restricted to the disposable GitHub Actions emulator")

    def command(*args, timeout=60):
        result = subprocess.run(["adb", "-s", SERIAL, *args], capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("Selected emulator command failed")
        return result.stdout

    if command("shell", "getprop", "ro.kernel.qemu").strip() != "1":
        raise RuntimeError("Refusing a target that is not an emulator")
    expected = selected_tests()
    command("install", "-r", "-t", str(ROOT / "android/app/build/outputs/apk/debug/app-debug.apk"))
    command("install", "-r", "-t", str(ROOT / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"))
    # Only the opted-in disposable emulator receives the existing phone-state grant.
    # Never grant location or SMS permission. No stored gateway selection is changed.
    if NETWORK_SERVICE in expected:
        command("shell", "pm", "grant", "org.zrotext.gateway", "android.permission.READ_PHONE_STATE")
    output = command(*instrumentation_arguments(expected), timeout=420)
    custody = verify_with_private_evidence(output, expected)
    print(f"Selected no-radio device tests passed: {sum(expected.values())}; zero failures or skips")
    if custody:
        print(f"Root storage custody branch exercised: {custody}")


if __name__ == "__main__":
    main()
