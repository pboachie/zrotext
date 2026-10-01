# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit isolated emulator probe. No physical target, SMS permission or radio API."""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from conversation_simulator import read_ready

APP = "org.zrotext.gateway.conversationprobe"
TEST = "org.zrotext.gateway.ConversationProbeDeviceTest"


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8", timeout=210, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--toolchain")
    parser.add_argument("--aapt", required=True, help="Installed aapt for pre-install APK isolation verification")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--scenario", choices=("roundtrip", "stop-install", "loss-install"), default="roundtrip")
    args = parser.parse_args()
    if not args.serial.startswith("emulator-") or not args.serial[9:].isdigit():
        parser.error("Only an explicitly selected emulator is allowed")
    root = Path(__file__).resolve().parents[1]
    adb = [args.adb, "-s", args.serial]
    profile = run(adb + ["emu", "avd", "name"]).stdout.splitlines()[0].strip()
    if not profile.startswith("ZROtext_Conversation_"):
        parser.error("An isolated conversation profile is required")
    if run(adb + ["shell", "getprop", "ro.kernel.qemu"]).stdout.strip() != "1":
        parser.error("Target is not an emulator")
    gradle = str(root / "android/gradlew.bat") if os.name == "nt" else "./gradlew"
    if not args.skip_build:
        run([gradle, "-PisolatedConversationProbe=true", ":app:assembleDebug", ":app:assembleDebugAndroidTest", "--no-daemon"], cwd=root / "android")
    app = root / "android/app/build/outputs/apk/debug/app-debug.apk"
    tests = root / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
    # Verify artifacts BEFORE any install, including --skip-build. A stale gateway APK is refused.
    for artifact, expected, allowed in ((app, APP, {"android.permission.INTERNET"}), (tests, APP + ".test", set())):
        badging = run([args.aapt, "dump", "badging", str(artifact)]).stdout
        tree = run([args.aapt, "dump", "xmltree", str(artifact), "AndroidManifest.xml"]).stdout
        package = re.search(r"package: name='([^']+)'", badging)
        requested = set(re.findall(r"uses-permission: name='([^']+)'", badging))
        if not package or package.group(1) != expected or requested != allowed or "android:testOnly(0x01010272)=(type 0x12)0xffffffff" not in tree:
            raise RuntimeError("APK identity, testOnly or exact permission set failed isolation preflight")
        if artifact == tests and ('android:targetPackage' not in tree or '"' + APP + '"' not in tree):
            raise RuntimeError("Instrumentation target failed isolation preflight")
    run(adb + ["install", "-t", "-r", str(app)])
    run(adb + ["install", "-t", "-r", str(tests)])
    permissions = run(adb + ["shell", "dumpsys", "package", APP]).stdout
    if "android.permission.SEND_SMS" in permissions or "android.permission.RECEIVE_SMS" in permissions:
        raise RuntimeError("Isolated probe must not request SMS permissions")
    cargo = ["cargo"] + (["+" + args.toolchain] if args.toolchain else [])
    with tempfile.TemporaryDirectory(prefix="conversation-emulator-") as directory:
        folder = Path(directory)
        env = dict(os.environ, ZT_CONVERSATION_SIM_DIR=directory, ZT_CONVERSATION_SIM_MODE="pause")
        reverse = []
        host = None
        device_path = "/data/local/tmp/conversation-" + folder.name + ".json"
        with (folder / "server.log").open("w", encoding="utf-8") as stream:
            server = subprocess.Popen(cargo + ["test", "--locked", "-p", "zrotext-server", "--lib", "--features", "conversation-simulator-tests",
                "http_owner_conversations::activation::simulator::loopback_journal_bridge", "--", "--ignored", "--exact", "--nocapture"], cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 180
                server_ready = None
                while server_ready is None:
                    server_ready = read_ready(folder / "server.log")
                    if server_ready is not None:
                        break
                    if server.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("Fixture server did not become ready")
                    time.sleep(0.1)
                ready = dict(server_ready)
                ready["browserTool"] = str(root / "sdk/typescript/test/conversation-browser-emulator.mjs")
                tools = {"conversation-simulator-envelope.mjs": Path(ready["sdkTool"]),
                    "conversation-browser-emulator.mjs": Path(ready["browserTool"]),
                    "conversation-phone-send-verifier.mjs": Path(ready["browserTool"]).parent / "conversation-phone-send-verifier.mjs"}

                class Bridge(BaseHTTPRequestHandler):
                    def log_message(self, *unused):
                        pass

                    def do_POST(self):
                        try:
                            length = int(self.headers.get("Content-Length", "0"))
                            if self.path != "/sdk" or not 0 < length <= 100000:
                                raise ValueError("Bounded fixture request required")
                            request = json.loads(self.rfile.read(length))
                            if not hmac.compare_digest(str(request.get("token", "")), ready["token"]):
                                raise ValueError("Fixture authorization required")
                            tool = tools[request["tool"]]
                            value = request["input"]
                            value["ready"] = ready
                            result = run(["node", str(tool)], input=json.dumps(value), cwd=root)
                            json.loads(result.stdout)
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(result.stdout.encode("utf-8"))
                        except Exception as error:
                            if isinstance(error, subprocess.CalledProcessError):
                                print(error.stderr[-3000:], file=sys.stderr)
                            self.send_error(400, "Synthetic bridge refused")

                host = ThreadingHTTPServer(("localhost", 0), Bridge)
                threading.Thread(target=host.serve_forever, daemon=True).start()
                ready["hostBridgePort"] = host.server_port
                for port in (ready["port"], host.server_port):
                    run(adb + ["reverse", "tcp:" + str(port), "tcp:" + str(port)])
                    reverse.append(port)
                prepared = folder / "device.json"
                prepared.write_text(json.dumps(ready), encoding="utf-8")
                run(adb + ["push", str(prepared), device_path])
                result = run(adb + ["shell", "am", "instrument", "-w", "-r", "-e", "class", TEST, "-e", "fixturePath", device_path, "-e", "scenario", args.scenario,
                    APP + ".test/androidx.test.runner.AndroidJUnitRunner"])
                if "OK (1 test)" not in result.stdout or "FAILURES!!!" in result.stdout or "INSTRUMENTATION_FAILED" in result.stdout:
                    raise RuntimeError("Emulator probe failed:\n" + result.stdout[-6000:])
                if server.wait(timeout=20) != 0:
                    raise RuntimeError("Fixture server assertions failed")
                if read_ready(folder / "server.log") != server_ready:
                    raise RuntimeError("Fixture readiness changed")
            finally:
                failure_pending = sys.exc_info()[0] is not None
                cleanup_errors = []
                for command in [adb + ["reverse", "--remove", "tcp:" + str(port)] for port in reverse] + [adb + ["shell", "rm", "-f", device_path]]:
                    try:
                        run(command)
                    except Exception:
                        cleanup_errors.append("device cleanup")
                try:
                    if host:
                        host.shutdown();host.server_close()
                except Exception:
                    cleanup_errors.append("host bridge cleanup")
                if server.poll() is None:
                    try:
                        payload = json.dumps({"token": ready["token"], "op": "finish"}).encode()
                        request = urllib.request.Request("http://localhost:" + str(ready["port"]) + "/fixture", data=payload, headers={"Content-Type": "application/json"})
                        with urllib.request.urlopen(request, timeout=5):
                            pass
                        server.wait(timeout=20)
                    except Exception:
                        # Stop only the spawned fixture process tree, never a shared emulator/server.
                        if os.name == "nt":
                            subprocess.run(["taskkill", "/PID", str(server.pid), "/T", "/F"], capture_output=True, timeout=10)
                        else:
                            server.terminate()
                        server.wait(timeout=20)
                if cleanup_errors:
                    if failure_pending:
                        print("Fixture cleanup incomplete: " + ", ".join(cleanup_errors), file=sys.stderr)
                    else:
                        raise RuntimeError("Fixture cleanup incomplete")
        evidence = ("compiled isolated APK, actual consent UI, bound service/synthetic receiver, production content-channel capture ACK and confirmed-packet delivery with fixture crypto, real Chromium incoming text/exact review/cancel, one synthetic reply, UNKNOWN replay fence, Stop/withdrawal; hardware content crypto and connection factory not exercised"
            if args.scenario == "roundtrip" else
            "compiled isolated APK, authenticated installation ACK held until " + args.scenario + ", no late activation or content capture")
        print("PASS-EMULATOR " + profile + " [" + args.scenario + "]: " + evidence)


if __name__ == "__main__":
    main()
