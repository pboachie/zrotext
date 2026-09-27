#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run an explicit no-radio test allowlist on CI's disposable emulator only."""

from collections import Counter
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "org.zrotext.gateway."
PRECONDITIONS = PACKAGE + "DevicePreconditionsDeviceTest"
ACCESSIBILITY = PACKAGE + "GatewayAccessibilityDeviceTest"
MANIFEST_AUTHORITY = PACKAGE + "ManifestAuthorityDeviceTest"
NETWORK_SERVICE = PACKAGE + "NetworkServiceDeviceTest"
OUTBOUND_ENVELOPE = PACKAGE + "OutboundEnvelopeDeviceTest"
ROOT_STORAGE = PACKAGE + "Draft02RootStorageDeviceTest"
SEALED_BODY = PACKAGE + "SealedBodyDeviceTest"
SEALED_PREPARATION = PACKAGE + "SealedPreparationDeviceTest"
SERIAL = "emulator-5562"


def selected_tests(root=ROOT):
    expected = {PRECONDITIONS: 1}
    source = root / "android/app/src/androidTest/java/org/zrotext/gateway/GatewayAccessibilityDeviceTest.kt"
    if source.is_file():
        expected[ACCESSIBILITY] = 5
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
    return expected


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
            code = int(line.removeprefix("INSTRUMENTATION_STATUS_CODE: "))
            if code not in (0, 1):
                raise ValueError("Instrumentation reported a failed or skipped test")
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
    output = command("shell", "am", "instrument", "-w", "-r", "-e", "class", ",".join(expected),
                     "-e", "a11yIsolatedEmulator", "true",
                     "-e", "networkServiceIsolatedEmulator", "true",
                     "org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner", timeout=420)
    # Raw platform output stays temporary, never in a public artifact or repository.
    with tempfile.TemporaryDirectory(prefix="zrotext-device-smoke-") as temporary:
        Path(temporary, "instrumentation.txt").write_text(output, encoding="utf-8")
        custody = verify_results(output, expected)
    print(f"Selected no-radio device tests passed: {sum(expected.values())}; zero failures or skips")
    if custody:
        print(f"Root storage custody branch exercised: {custody}")


if __name__ == "__main__":
    main()
