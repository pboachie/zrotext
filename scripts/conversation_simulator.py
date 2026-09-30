# SPDX-License-Identifier: AGPL-3.0-only
"""Run synthetic phone journal / sealed SDK / server contracts over loopback only.

Requires disposable PostgreSQL, installed Android SDK/Java, built TypeScript SDK,
and precompiled Rust/Android tests. Never uses a phone, carrier or owner credentials.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", help="Optional installed Cargo toolchain override")
    parser.add_argument("--mode", choices=("pause", "logout", "close_failure", "send_close", "send_verify_close"), action="append")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    cargo = ["cargo"] + (["+" + args.toolchain] if args.toolchain else [])
    gradle = str(root / "android" / "gradlew.bat") if os.name == "nt" else "./gradlew"
    for mode in args.mode or ("pause", "logout", "close_failure", "send_close", "send_verify_close"):
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
                    while not (Path(directory) / "ready.json").exists():
                        if server.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Synthetic server startup failed: " + log.read_text()[-4000:])
                        time.sleep(0.1)
                    android = subprocess.run([gradle, ":app:testDebugUnitTest", "--tests",
                        "org.zrotext.gateway.ConversationServerSimulatorTest", "--rerun-tasks", "--no-daemon"],
                        cwd=root / "android", env=env, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, timeout=210)
                    if android.returncode:
                        report = root / "android/app/build/test-results/testDebugUnitTest/TEST-org.zrotext.gateway.ConversationServerSimulatorTest.xml"
                        details = report.read_text(encoding="utf-8")[-8000:] if report.exists() else "No test report"
                        raise RuntimeError("Synthetic Android contract failed:\n" + android.stdout[-3000:] + "\n" + details)
                    suite = ET.parse(root / "android/app/build/test-results/testDebugUnitTest/TEST-org.zrotext.gateway.ConversationServerSimulatorTest.xml").getroot()
                    assert suite.get("tests") == "1" and suite.get("failures") == "0" and suite.get("skipped") == "0", "Simulator must actually execute"
                    assert server.wait(timeout=20) == 0, "Synthetic server assertions failed"
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
