# SPDX-License-Identifier: AGPL-3.0-only
"""Run synthetic phone journal / sealed SDK / server contracts over loopback only.

Requires disposable PostgreSQL, installed Android SDK/Java, built TypeScript SDK,
and precompiled Rust/Android tests. Never uses a phone, carrier or owner credentials.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET


READY_MARKER = b"ZT_CONVERSATION_SIM_READY_V1 "
MAX_READY_BYTES = 16_384
MAX_STARTUP_LOG_BYTES = 1_048_576


def read_ready(log):
    """Read one complete, bounded readiness record from the captured child log."""
    with log.open("rb") as stream:
        captured = stream.read(MAX_STARTUP_LOG_BYTES + 1)
    if len(captured) > MAX_STARTUP_LOG_BYTES:
        raise RuntimeError("Synthetic server startup log exceeded its bound")
    ready = None
    for line in captured.splitlines(keepends=True):
        if not line.startswith(READY_MARKER):
            continue
        payload = line[len(READY_MARKER):].rstrip(b"\r\n")
        if len(payload) > MAX_READY_BYTES:
            raise RuntimeError("Synthetic server readiness exceeded its bound")
        if ready is not None:
            raise RuntimeError("Synthetic server emitted duplicate readiness")
        if not line.endswith(b"\n"):
            continue
        try:
            ready = json.loads(payload)
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError("Synthetic server emitted malformed readiness") from error
        if not isinstance(ready, dict):
            raise RuntimeError("Synthetic server readiness must be an object")
    return ready


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", help="Optional installed Cargo toolchain override")
    parser.add_argument("--mode", choices=("pause", "logout", "close_failure", "send_close", "send_verify_close"), action="append")
    parser.add_argument("--assembly", action="store_true", help="Verify authenticated dormant runtime assembly")
    parser.add_argument("--gradle-init", help="Optional local Gradle test resource configuration")
    args = parser.parse_args()
    test_class = "ConversationAuthenticatedServerSimulatorTest" if args.assembly else "ConversationServerSimulatorTest"
    if args.assembly and args.mode not in (None, ["pause"]):
        parser.error("Authenticated assembly implements only the pause scenario")
    modes = (["pause"] if args.assembly else (args.mode or ("pause", "logout", "close_failure", "send_close", "send_verify_close")))
    root = Path(__file__).resolve().parents[1]
    cargo = ["cargo"] + (["+" + args.toolchain] if args.toolchain else [])
    gradle = str(root / "android" / "gradlew.bat") if os.name == "nt" else "./gradlew"
    for mode in modes:
        with tempfile.TemporaryDirectory(prefix="conversation-simulator-") as directory:
            env = dict(os.environ, ZT_CONVERSATION_SIM_DIR=directory, ZT_CONVERSATION_SIM_MODE=mode)
            log = Path(directory) / "server.log"
            with log.open("w", encoding="utf-8") as stream:
                server = subprocess.Popen(cargo + ["test", "--locked", "-p", "zrotext-server",
                    "--lib", "--features", "conversation-simulator-tests",
                    "http_owner_conversations::activation::simulator::loopback_journal_bridge",
                    "--", "--ignored", "--exact", "--nocapture"], cwd=root, env=env,
                    stdout=stream, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 180
                    ready = None
                    while ready is None:
                        ready = read_ready(log)
                        if ready is not None:
                            break
                        if server.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Synthetic server startup failed: " + log.read_text()[-4000:])
                        time.sleep(0.1)
                    (Path(directory) / "ready.json").write_text(json.dumps(ready), encoding="utf-8")
                    android = subprocess.run([gradle] + (["-I", str(Path(args.gradle_init).resolve())] if args.gradle_init else []) + [":app:testDebugUnitTest", "--tests",
                        "org.zrotext.gateway." + test_class, "--rerun-tasks", "--no-daemon"],
                        cwd=root / "android", env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, timeout=210)
                    if android.returncode:
                        report = root / ("android/app/build/test-results/testDebugUnitTest/TEST-org.zrotext.gateway." + test_class + ".xml")
                        details = report.read_text(encoding="utf-8")[-8000:] if report.exists() else "No test report"
                        raise RuntimeError("Synthetic Android contract failed:\n" + android.stdout[-3000:] + "\n" + details)
                    suite = ET.parse(root / ("android/app/build/test-results/testDebugUnitTest/TEST-org.zrotext.gateway." + test_class + ".xml")).getroot()
                    assert suite.get("tests") == "1" and suite.get("failures") == "0" and suite.get("skipped") == "0", "Simulator must actually execute"
                    assert server.wait(timeout=20) == 0, "Synthetic server assertions failed"
                    assert read_ready(log) == ready, "Synthetic server readiness changed"
                    if args.assembly:
                        print("PASS-SIMULATOR authenticated assembly: phone decision/install, authenticated time/channel, protected inbound, readable browser history/renewal, exact-confirmed synthetic reply, UNKNOWN instance-recreation replay fence, durable lifecycle closure")
                    else:
                        print("PASS " + mode + ": journal, encrypted browser history, exact-confirmed reply, durable confirmed send/restart fence, shared phone gate, closure")
                finally:
                    if server.poll() is None:
                        try:
                            server.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            pass
                    if server.poll() is None:
                        server.terminate()
                        try:
                            server.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait(timeout=10)


if __name__ == "__main__":
    main()
