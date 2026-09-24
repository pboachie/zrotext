#!/usr/bin/env python3
"""Inject one synthetic emulator SMS and verify the M1 receiver/outbox path.

This intentionally refuses physical devices and preinstalled app packages. It
never calls SmsManager or a carrier, and it uninstalls only APKs it installed.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = "org.zrotext.gateway"
TEST_APP = "org.zrotext.gateway.test"
TEST = (
    "org.zrotext.gateway.M1VirtualInboundSmsDeviceTest"
    "#emulatorSmsBroadcastCreatesOneEncryptedUpload"
)
RUNNER = f"{TEST_APP}/androidx.test.runner.AndroidJUnitRunner"


def adb_path(explicit: str | None) -> str:
    if explicit:
        return explicit
    executable = "adb.exe" if os.name == "nt" else "adb"
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        base = os.environ.get(variable)
        if base and (Path(base) / "platform-tools" / executable).is_file():
            return str(Path(base) / "platform-tools" / executable)
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        candidate = Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk" / "platform-tools" / executable
        if candidate.is_file():
            return str(candidate)
    found = shutil.which(executable)
    if found:
        return found
    raise RuntimeError("ADB not found; set ANDROID_HOME or pass --adb")


def call(adb: str, serial: str, *args: str, timeout: int = 30) -> str:
    result = subprocess.run(
        [adb, "-s", serial, *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"ADB command failed ({' '.join(args[:3])}): {result.stderr.strip()}")
    return result.stdout.strip()


def preflight(adb: str, serial: str, app_apk: Path, test_apk: Path) -> None:
    if not re.fullmatch(r"emulator-[0-9]+", serial):
        raise RuntimeError("--serial must identify an emulator, never a physical device")
    if call(adb, serial, "shell", "getprop", "ro.kernel.qemu") != "1":
        raise RuntimeError("target is not an Android emulator")
    fingerprint = call(adb, serial, "shell", "getprop", "ro.build.fingerprint")
    if "sdk_gphone" not in fingerprint.lower():
        raise RuntimeError("this test requires an sdk_gphone emulator")
    if call(adb, serial, "shell", "getprop", "sys.boot_completed") != "1":
        raise RuntimeError("emulator has not finished booting")
    for package in (APP, TEST_APP):
        listed = call(adb, serial, "shell", "pm", "list", "packages", package)
        if f"package:{package}" in listed.splitlines():
            raise RuntimeError(f"{package} is already installed; use a fresh test AVD")
    for apk in (app_apk, test_apk):
        if not apk.is_file():
            raise RuntimeError(f"missing APK: {apk}; build both debug APKs first")


def run(adb: str, serial: str, app_apk: Path, test_apk: Path) -> None:
    preflight(adb, serial, app_apk, test_apk)
    installed: list[str] = []
    process: subprocess.Popen[str] | None = None
    try:
        call(adb, serial, "install", str(app_apk), timeout=90)
        installed.append(APP)
        call(adb, serial, "install", str(test_apk), timeout=90)
        installed.append(TEST_APP)
        call(adb, serial, "shell", "pm", "grant", APP, "android.permission.RECEIVE_SMS")
        call(adb, serial, "shell", "pm", "grant", APP, "android.permission.READ_PHONE_STATE")
        call(adb, serial, "shell", "pm", "revoke", APP, "android.permission.SEND_SMS")
        run_id = uuid.uuid4().hex
        process = subprocess.Popen(
            [adb, "-s", serial, "shell", "am", "instrument", "-w",
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
            log = call(adb, serial, "logcat", "-d", "-s", "M1VirtualInbound:I", "*:S")
            if ready in log:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("instrumentation did not announce readiness")

        # Emulator console injection enters Android's SMS stack without a carrier send.
        call(adb, serial, "emu", "sms", "send", "+12025550199", "ZT VIRTUAL INBOUND 1")
        stdout, stderr = process.communicate(timeout=110)
        log = call(adb, serial, "logcat", "-d", "-s", "M1VirtualInbound:I", "*:S")
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
                call(adb, serial, "uninstall", package)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                print(f"Cleanup needed for {package}: {error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, help="explicit ADB emulator serial")
    parser.add_argument("--adb", help="path to adb")
    parser.add_argument("--app-apk", type=Path, default=ROOT / "app/build/outputs/apk/debug/app-debug.apk")
    parser.add_argument("--test-apk", type=Path,
                        default=ROOT / "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")
    args = parser.parse_args()
    try:
        run(adb_path(args.adb), args.serial, args.app_apk, args.test_apk)
        return 0
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
