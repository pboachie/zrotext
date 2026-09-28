#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate isolated APKs; installation requires explicit selection and absent packages."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from android_device_smoke import verify_results

ROOT = Path(__file__).resolve().parents[1]
APP = "org.zrotext.gateway.preparationprobe"
TEST_APP = APP + ".test"
RUNNER = "org.zrotext.gateway.PreparationProbeRunner"
TEST = "org.zrotext.gateway.PreparationProbeDeviceTest"
ANDROID = "{http://schemas.android.com/apk/res/android}"
WINDOWS = os.name == "nt"
# Fixed program names only; each must exist in its expected SDK directory before use.
TOOLS = {
    "adb": ("platform-tools", "adb.exe" if WINDOWS else "adb"),
    "apkanalyzer": ("cmdline-tools/latest/bin", "apkanalyzer.bat" if WINDOWS else "apkanalyzer"),
    "apksigner": ("build-tools/37.0.0", "apksigner.bat" if WINDOWS else "apksigner"),
}


# adb serials are device IDs, emulator-NNNN or host:port transports; never options or shell syntax.
SERIAL_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")


def validated_serial(serial):
    """Return the serial only when it cannot smuggle argument or shell separators."""
    match = SERIAL_PATTERN.fullmatch(serial) if isinstance(serial, str) else None
    if serial is not None and match is None:
        raise ValueError("Device serial may contain only letters, digits, dots, dashes, underscores and colons")
    return match.group(0) if match else serial


def tool_environment(sdk_home, serial=None, base=None):
    """Return an environment whose PATH resolves the fixed tool names to the verified SDK copies.

    Commands never carry a path or serial from the caller: programs are constant names and the
    validated serial reaches adb only through ANDROID_SERIAL.
    """
    if not isinstance(sdk_home, str) or not os.path.isabs(sdk_home):
        raise ValueError("ANDROID_HOME must be an absolute SDK directory")
    sdk = os.path.normpath(sdk_home)
    directories = []
    for directory, name in TOOLS.values():
        # Normalize, then confirm the fixed relative tool path stays inside the SDK before any access.
        tool = os.path.normpath(os.path.join(sdk, directory, name))
        if not tool.startswith(os.path.join(sdk, "")):
            raise ValueError("Android SDK tool path escapes ANDROID_HOME")
        if not os.path.isfile(tool):
            raise ValueError("Required Android SDK tool is missing")
        directories.append(os.path.dirname(tool))
    environment = dict(os.environ if base is None else base)
    environment["PATH"] = os.pathsep.join(directories + [environment.get("PATH", "")])
    environment.pop("ANDROID_SERIAL", None)
    if serial is not None:
        environment["ANDROID_SERIAL"] = validated_serial(serial)
    return environment


class ProbeCommandError(RuntimeError):
    """A failed tool command. Only a fixed failure class is kept, never raw output."""

    def __init__(self, kind):
        super().__init__(f"Probe command failed ({kind}); no raw device output published")
        self.kind = kind


# Fixed classes for adb failures; the matched text itself is never reported.
FAILURE_CLASSES = (
    ("device-offline", ("device offline", "device not found", "no devices/emulators", "device unauthorized")),
    ("missing", ("does not exist", "no such file")),
    ("permission", ("permission denied",)),
    ("transport", ("protocol fault", "connection reset", "closed", "broken pipe")),
    ("service", ("can't find service", "failure calling service", "deadobject", "system has crashed")),
)


def failure_class(output):
    """Map raw tool output to one fixed class so logs never carry device text."""
    text = (output or "").lower()
    if not text.strip():
        return "silent"
    for kind, needles in FAILURE_CLASSES:
        if any(needle in text for needle in needles):
            return kind
    return "other"


# An installed APK path from `pm path`: under /data/app, safe characters only,
# no relative segments, ending in base.apk.
INSTALLED_PATH = re.compile(r"package:(/data/app/(?:[A-Za-z0-9._~=+-]+/){1,3}base\.apk)")


class PathNotReady(Exception):
    """`pm path` has no entry for the package yet; worth retrying."""


def installed_apk_path(output):
    """Return the one installed APK path, or refuse anything but an absent entry."""
    lines = [line.strip() for line in output.strip().splitlines()]
    if not lines:
        raise PathNotReady()
    match = INSTALLED_PATH.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None or "/../" in match.group(1) or "/./" in match.group(1):
        raise ValueError("Unexpected installed package shape")
    return match.group(1)


# Right after `adb install` the package manager can still be publishing the
# new code directory (relabel/rename), so an immediate pull intermittently
# failed. Each attempt re-resolves the path and requires two identical reads.
PULL_ATTEMPTS = 6
PULL_BACKOFF_SECONDS = (1, 2, 3, 5, 8)


def pull_installed(read_path_output, pull, sleep, attempts=PULL_ATTEMPTS, backoff=PULL_BACKOFF_SECONDS):
    """Pull the installed APK, retrying bounded transient failures.

    Returns (attempts used, failure classes seen). Malformed `pm path` output is
    never retried; it raises immediately.
    """
    seen = []
    for attempt in range(attempts):
        stage = "path"
        try:
            first = installed_apk_path(read_path_output())
            if installed_apk_path(read_path_output()) != first:
                seen.append("path-moving")
            else:
                stage = "pull"
                pull(first)
                return attempt + 1, seen
        except PathNotReady:
            seen.append("path-not-ready")
        except ProbeCommandError as error:
            seen.append(f"{stage}-{error.kind}")
        if attempt + 1 < attempts:
            sleep(backoff[min(attempt, len(backoff) - 1)])
    raise RuntimeError("Installed APK pull failed after bounded retries (" + ",".join(seen) +
                       "); no raw device output published")


def validate_manifest(xml, package, test=False):
    root = ET.fromstring(xml)
    if root.tag != "manifest" or root.get("package") != package:
        raise ValueError("Wrong probe package")
    if root.get(ANDROID + "sharedUserId") is not None:
        raise ValueError("Shared UID forbidden")
    allowed = {"uses-sdk", "application", "instrumentation"} if test else {"uses-sdk", "application"}
    if any(child.tag not in allowed for child in root):
        raise ValueError("Permissions, features and queries forbidden")
    apps = root.findall("application")
    if len(apps) != 1:
        raise ValueError("One plain application required")
    app = apps[0]
    app_attributes = {ANDROID + name for name in ("name", "label", "debuggable", "testOnly", "allowBackup",
                                                  "extractNativeLibs", "networkSecurityConfig")}
    if (app.get(ANDROID + "name") != "android.app.Application" or
            app.get(ANDROID + "allowBackup") != "false" or
            app.get(ANDROID + "testOnly") != "true" or list(app) or
            not set(app.attrib) <= app_attributes):
        raise ValueError("Application startup components or unsafe attributes")
    instrumentation = root.findall("instrumentation")
    if test:
        if (len(instrumentation) != 1 or instrumentation[0].get(ANDROID + "name") != RUNNER or
                instrumentation[0].get(ANDROID + "targetPackage") != APP or
                instrumentation[0].get(ANDROID + "targetProcesses") is not None):
            raise ValueError("Wrong instrumentation target or runner")
    elif instrumentation:
        raise ValueError("Unexpected instrumentation")


def validate_results(output):
    verify_results(output, {TEST: 2})
    completed = set(re.findall(r"^INSTRUMENTATION_STATUS: test=(.+)$", output, re.MULTILINE))
    if completed != {"independentTinkWrapOpensThroughExistingKeystoreAndLostKeyCannotBeRecreated",
                     "preparationRequiresActualReportedHardwareAndNeverProducesAlphaState"}:
        raise ValueError("Wrong probe methods")
    reports = re.findall(r"^INSTRUMENTATION_RESULT: preparationCustody=(.+)$", output, re.MULTILINE)
    if reports not in (["unsupported"], ["platform-reported-hardware"]):
        raise ValueError("Missing or ambiguous hardware result")
    return reports[0]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_rejection(output):
    if ("INSTRUMENTATION_RESULT: probeRejected=selector" not in output or
            "INSTRUMENTATION_STATUS:" in output or
            re.findall(r"^INSTRUMENTATION_CODE: (-?\d+)\s*$", output, re.MULTILINE) != ["0"]):
        raise ValueError("Runner did not reject an unsafe selector before discovery")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", help="Explicit target; omit for build-only APK validation")
    parser.add_argument("--allow-physical", action="store_true", help="Requires separately reviewed device authorization")
    parser.add_argument("--apk-dir", type=Path, help="Directory containing reviewed isolated-preparation-app.apk and isolated-preparation-tests.apk")
    parser.add_argument("--expected-sha256", nargs=2, metavar=("APP", "TEST"), help="Reviewed artifact hashes; required for physical installation")
    args = parser.parse_args()
    if args.allow_physical and (not args.serial or not args.expected_sha256):
        parser.error("Physical execution requires a target and both reviewed artifact hashes")
    if args.expected_sha256 and any(not re.fullmatch(r"[0-9a-f]{64}", h) for h in args.expected_sha256):
        parser.error("Expected hashes must be lowercase SHA-256 hex")
    try:
        environment = tool_environment(os.environ.get("ANDROID_HOME"), args.serial)
    except ValueError as error:
        parser.error(str(error))
    # Windows CreateProcess resolves program names through this process's PATH, not the child's.
    os.environ["PATH"] = environment["PATH"]

    def run(tool, *arguments, timeout=90):
        program = TOOLS[tool][1]
        result = subprocess.run([program, *arguments], capture_output=True, text=True, timeout=timeout,
                                env=environment)
        if result.returncode:
            raise ProbeCommandError(failure_class(f"{result.stdout}\n{result.stderr}"))
        return result.stdout

    def device(*command, timeout=90):
        return run("adb", *command, timeout=timeout)

    with tempfile.TemporaryDirectory(prefix="zrotext-isolated-probe-") as temporary:
        directory = Path(temporary)
        artifacts = {}
        certificates = set()
        for package, relative in [(APP, "debug/app-debug.apk"), (TEST_APP, "androidTest/debug/app-debug-androidTest.apk")]:
            artifact = directory / (package + ".apk")
            source = (args.apk_dir / ("isolated-preparation-tests.apk" if package == TEST_APP else "isolated-preparation-app.apk")
                      if args.apk_dir else ROOT / "android/app/build/outputs/apk" / relative)
            shutil.copyfile(source, artifact)
            if args.expected_sha256 and digest(artifact) != args.expected_sha256[int(package == TEST_APP)]:
                raise ValueError("Artifact differs from reviewed hash; refusing device access")
            validate_manifest(run("apkanalyzer", "manifest", "print", str(artifact)), package, package == TEST_APP)
            certs = set(re.findall(r"^(?:V[234](?:\.1)? Signer:|Signer #\d+) certificate SHA-256 digest: ([0-9a-f]{64})$",
                                  run("apksigner", "verify", "--print-certs", str(artifact)), re.MULTILINE))
            if len(certs) != 1:
                raise ValueError("One verified signing identity required")
            certificates.update(certs)
            artifacts[package] = artifact
        if len(certificates) != 1:
            raise ValueError("Probe APK signatures differ")
        print(json.dumps({"apkSha256": {p: digest(a) for p, a in artifacts.items()},
                          "signerSha256": next(iter(certificates))}))
        if not args.serial:
            return
        if not args.allow_physical and device("shell", "getprop", "ro.kernel.qemu").strip() != "1":
            raise ValueError("Physical installation requires separate authorization")
        if int(device("shell", "getprop", "ro.build.version.sdk").strip()) < 31:
            raise ValueError("API 31 required")
        for package in artifacts:
            if device("shell", "pm", "list", "packages", package).strip():
                raise ValueError("Probe package already exists; refusing replacement or clearing")
        installed = []

        def verify_installed(package):
            copy = directory / "installed.apk"
            copy.unlink(missing_ok=True)
            used, seen = pull_installed(lambda: device("shell", "pm", "path", package),
                                        lambda path: device("pull", path, str(copy)), time.sleep)
            if used > 1:
                # Fixed counts and classes only, to track the post-install race.
                print(f"Installed APK pull needed {used} attempts ({','.join(seen)})")
            if digest(copy) != digest(artifacts[package]):
                raise ValueError("Installed artifact changed; refusing access or cleanup")

        try:
            for package, artifact in artifacts.items():
                output = device("install", "-t", str(artifact)) # Never -r, -g or an ordinary gateway APK.
                if output.strip() != "Success" and not output.rstrip().endswith("\nSuccess"):
                    raise RuntimeError("Installation did not report success")
                installed.append(package)
                verify_installed(package)
            for selector in [("-e", "isolatedPreparationProbe", "true", "-e", "class",
                              "org.zrotext.gateway.JournalDeviceUpgradeTest"),
                             ("-e", "class", TEST),
                             ("-e", "isolatedPreparationProbe", "true", "-e", "package", "org.zrotext.gateway")]:
                rejected = device("shell", "am", "instrument", "-w", "-r", *selector, TEST_APP + "/" + RUNNER)
                validate_rejection(rejected)
            output = device("shell", "am", "instrument", "-w", "-r", "-e", "isolatedPreparationProbe", "true",
                            "-e", "class", TEST, TEST_APP + "/" + RUNNER, timeout=420)
            (directory / "instrumentation.txt").write_text(output, encoding="utf-8")
            custody = validate_results(output)
            print(f"Isolated probe: 2 tests; zero failures/skips; custody={custody}")
        finally:
            for package in reversed(installed):
                verify_installed(package)
                if device("uninstall", package).strip() != "Success":
                    raise RuntimeError("Owned probe package cleanup failed")


if __name__ == "__main__":
    main()
