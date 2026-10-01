# SPDX-License-Identifier: AGPL-3.0-only
"""Hash-pinned isolated compiled probes; no server, keys, carrier or production dispatch."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

APP = "org.zrotext.gateway.conversationprobe"
CLASSES = (
    "org.zrotext.gateway.ConversationCompiledAcceptanceDeviceTest",
    "org.zrotext.gateway.ConversationIntentAckAcceptanceTest",
)


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True,
                          encoding="utf-8", timeout=180).stdout


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def preflight(root, aapt, commit, app_hash, test_hash):
    if not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("Full candidate commit required")
    if run(["git", "-C", str(root), "rev-parse", "HEAD"]).strip() != commit:
        raise ValueError("Candidate commit changed")
    if run(["git", "-C", str(root), "status", "--porcelain"]).strip():
        raise ValueError("Candidate working tree must be frozen and clean")
    artifacts = (root / "android/app/build/outputs/apk/debug/app-debug.apk",
                 root / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")
    for artifact, expected_hash, package, permissions in zip(
            artifacts, (app_hash, test_hash), (APP, APP + ".test"),
            ({"android.permission.INTERNET"}, set())):
        if not re.fullmatch("[0-9a-f]{64}", expected_hash) or digest(artifact) != expected_hash:
            raise ValueError("Candidate APK hash changed")
        badging = run([aapt, "dump", "badging", str(artifact)])
        tree = run([aapt, "dump", "xmltree", str(artifact), "AndroidManifest.xml"])
        identity = re.search(r"package: name='([^']+)'", badging)
        requested = set(re.findall(r"uses-permission: name='([^']+)'", badging))
        if (not identity or identity.group(1) != package or requested != permissions or
                "android:testOnly(0x01010272)=(type 0x12)0xffffffff" not in tree):
            raise ValueError("APK isolation failed")
        if package.endswith(".test") and ('android:targetPackage' not in tree or '"' + APP + '"' not in tree):
            raise ValueError("Instrumentation targets another application")
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--commit", required=True)
    parser.add_argument("--app-sha256", required=True)
    parser.add_argument("--test-sha256", required=True)
    parser.add_argument("--aapt", required=True)
    parser.add_argument("--adb")
    parser.add_argument("--serial", default="emulator-5596", choices=["emulator-5596"])
    parser.add_argument("--execute", action="store_true", help="Otherwise host-only preflight; no ADB call")
    parser.add_argument("--handoff-reference", help="Actual exclusive release evidence, required for execution")
    args = parser.parse_args()
    artifacts = preflight(args.root, args.aapt, args.commit, args.app_sha256, args.test_sha256)
    if not args.execute:
        print("PASS-PREFLIGHT: commit, hashes, isolated test-only artifacts; emulator untouched")
        return
    if not args.adb or not args.handoff_reference:
        parser.error("Execution requires ADB and an actual exclusive handoff reference")
    adb = [args.adb, "-s", args.serial]
    if run(adb + ["emu", "avd", "name"]).splitlines()[0].strip() != "ZROtext_Conversation_API28":
        raise ValueError("Only the explicitly released conversation profile may be used")
    if run(adb + ["shell", "getprop", "ro.kernel.qemu"]).strip() != "1":
        raise ValueError("Physical target refused")
    # Recheck the immutable files immediately before the first install.
    preflight(args.root, args.aapt, args.commit, args.app_sha256, args.test_sha256)
    for artifact in artifacts:
        run(adb + ["install", "-t", "-r", str(artifact)])
    permissions = run(adb + ["shell", "dumpsys", "package", APP])
    if any(permission in permissions for permission in ("android.permission.SEND_SMS", "android.permission.RECEIVE_SMS")):
        raise ValueError("Installed artifact has radio permissions")
    results = []
    for name, count in zip(CLASSES, (13, 6)):
        output = run(adb + ["shell", "am", "instrument", "-w", "-r", "-e", "class", name,
                            APP + ".test/androidx.test.runner.AndroidJUnitRunner"])
        if (f"OK ({count} tests)" not in output or "FAILURES!!!" in output or "INSTRUMENTATION_FAILED" in output):
            raise RuntimeError("Compiled probe failure:\n" + output[-8000:])
        results.append({"class": name, "tests": count})
    print(json.dumps({"result": "PASS-COMPILED-PROBES", "commit": args.commit,
                      "app_sha256": args.app_sha256, "test_sha256": args.test_sha256,
                      "handoff": args.handoff_reference, "results": results,
                      "limits": "Lifecycle/holder/metadata/Room only; no positive Factory crypto/radio roundtrip"}))


if __name__ == "__main__":
    main()
