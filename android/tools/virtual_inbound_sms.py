#!/usr/bin/env python3
"""Inject one synthetic emulator SMS and verify the M1 receiver/outbox path.

This intentionally refuses physical devices and preinstalled app packages. It
never calls SmsManager or a carrier, and it uninstalls only APKs it installed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADB = "adb.exe" if os.name == "nt" else "adb"
APP_APK = ROOT / "app/build/outputs/apk/debug/app-debug.apk"
TEST_APK = ROOT / "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
APP = "org.zrotext.gateway"
TEST_APP = "org.zrotext.gateway.test"
# Canonical, literal serials prevent arbitrary user input from entering an ADB command.
EMULATOR_SERIALS = tuple(f"emulator-{port}" for port in range(5554, 5594, 2))
TEST = (
    "org.zrotext.gateway.M1VirtualInboundSmsDeviceTest"
    "#emulatorSmsBroadcastCreatesOneEncryptedUpload"
)
RUNNER = f"{TEST_APP}/androidx.test.runner.AndroidJUnitRunner"


def canonical_serial(raw: str) -> str:
    for known in EMULATOR_SERIALS:
        if raw == known:
            return known
    raise RuntimeError("--serial must identify a known emulator, never a physical device")


def call(serial: str, *args: str, timeout: int = 30) -> str:
    result = subprocess.run(
        [ADB, "-s", serial, *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"ADB command failed ({' '.join(args[:3])}): {result.stderr.strip()}")
    return result.stdout.strip()


def preflight(serial: str) -> None:
    if serial not in EMULATOR_SERIALS:
        raise RuntimeError("target is not a known emulator")
    if call(serial, "shell", "getprop", "ro.kernel.qemu") != "1":
        raise RuntimeError("target is not an Android emulator")
    fingerprint = call(serial, "shell", "getprop", "ro.build.fingerprint")
    if "sdk_gphone" not in fingerprint.lower():
        raise RuntimeError("this test requires an sdk_gphone emulator")
    if call(serial, "shell", "getprop", "sys.boot_completed") != "1":
        raise RuntimeError("emulator has not finished booting")
    for package in (APP, TEST_APP):
        listed = call(serial, "shell", "pm", "list", "packages", package)
        if f"package:{package}" in listed.splitlines():
            raise RuntimeError(f"{package} is already installed; use a fresh test AVD")
    for apk in (APP_APK, TEST_APK):
        if not apk.is_file():
            raise RuntimeError(f"missing APK: {apk}; build both debug APKs first")


def run(serial: str) -> None:
    preflight(serial)
    installed: list[str] = []
    process: subprocess.Popen[str] | None = None
    try:
        call(serial, "install", str(APP_APK), timeout=90)
        installed.append(APP)
        call(serial, "install", str(TEST_APK), timeout=90)
        installed.append(TEST_APP)
        call(serial, "shell", "pm", "grant", APP, "android.permission.RECEIVE_SMS")
        call(serial, "shell", "pm", "grant", APP, "android.permission.READ_PHONE_STATE")
        call(serial, "shell", "pm", "revoke", APP, "android.permission.SEND_SMS")
        run_id = uuid.uuid4().hex
        process = subprocess.Popen(
            [ADB, "-s", serial, "shell", "am", "instrument", "-w",
             "-e", "class", TEST, "-e", "m1VirtualInbound", "true",
             "-e", "m1VirtualRunId", run_id, RUNNER],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace",
        )
        ready = f"READY {run_id}"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=5)
                raise RuntimeError(f"instrumentation stopped before ready: {stdout.strip()} {stderr.strip()}")
            log = call(serial, "logcat", "-d", "-s", "M1VirtualInbound:I", "*:S")
            if ready in log:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("instrumentation did not announce readiness")

        # Emulator console injection enters Android's SMS stack without a carrier send.
        call(serial, "emu", "sms", "send", "+12025550199", "ZT VIRTUAL INBOUND 1")
        stdout, stderr = process.communicate(timeout=110)
        log = call(serial, "logcat", "-d", "-s", "M1VirtualInbound:I", "*:S")
        if process.returncode or "OK (1 test)" not in stdout or f"PASS {run_id}" not in log:
            raise RuntimeError(f"inbound test failed: {stdout.strip()} {stderr.strip()}")
        print("PASS: one synthetic emulator SMS became an encrypted local event and pending upload")
        print("SEND_SMS remained denied; no carrier SMS or server upload was attempted")
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        for package in reversed(installed):
            try:
                call(serial, "uninstall", package)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                print(f"Cleanup needed for {package}: {error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, help="explicit ADB emulator serial")
    args = parser.parse_args()
    try:
        run(canonical_serial(args.serial))
        return 0
    except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
