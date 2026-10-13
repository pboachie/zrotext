"""Qualify native outbound03 timing with shared signed authority and actual PCP.

Missing native capability is unqualified. Any failure after key creation is fatal.
The maintained TypeScript consumer independently verifies and opens every success.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parent
REVISION = "034ccd0a7390a5451745e885e5ffca94f9bbb633"


def run(*args, **kwargs):
    if kwargs.get("text"):
        kwargs["encoding"] = "utf-8"
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def exercise(binary, producer):
    env = {k: v for k, v in os.environ.items() if k not in ("NODE_PATH", "NODE_OPTIONS")}
    cli = producer / "sdk/typescript/test/fixtures/profile03-time-cli.mjs"
    probe = subprocess.run([str(binary), "--probe"], capture_output=True, timeout=30)
    if probe.returncode == 77:
        print("UNQUALIFIED: native signing capability unavailable")
        return
    if probe.returncode:
        raise ValueError("Native signing probe failed")
    process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env)
    ready = queue.Queue()
    threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
    try:
        first = json.loads(ready.get(timeout=45))
        if set(first) != {"public"} or len(first["public"]) != 130:
            raise ValueError("Native public point expected")
        fixture = run(shutil.which("node"), cli, "--signer-point", first["public"],
                      capture_output=True, text=True, timeout=60, env=env).stdout
        cases = json.loads(fixture)["cases"]
        if len(cases) != 14 or any("signerScalar" in c for c in cases):
            raise ValueError("Shared policy fixture shape")
        output, errors = process.communicate(fixture, timeout=120)
        if process.returncode:
            raise ValueError("Native policy failed: " + errors)
        results = json.loads(output)["results"]
        if len(results) != len(cases):
            raise ValueError("Missing native case results")
        opened = 0
        for case, result in zip(cases, results, strict=True):
            if result["name"] != case["name"] or bool(result["envelope"]) != case["accept"]:
                raise ValueError("Native policy result mismatch")
            if not case["accept"]:
                continue
            payload = json.dumps({"fixture": case, "envelope": result["envelope"], "expectedText": case["bodyText"]})
            verification = run(shutil.which("node"), cli, "--consume", input=payload,
                               capture_output=True, text=True, timeout=45, env=env)
            if json.loads(verification.stdout) != {"verified": True, "name": case["name"], "recipients": 3}:
                raise ValueError("Independent native output refused")
            opened += 1
        if opened != 6:
            raise ValueError("Positive case count")
        print("QUALIFIED: 14 signed policy cases; 6 native PCP outputs independently opened by all 3 recipients")
    finally:
        if process.poll() is None:
            try:
                process.communicate("", timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError("Cleanup timed out; retain private exact-owned pending receipt")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--language", choices=("rust", "go"), required=True)
    args = parser.parse_args()
    producer = args.producer.resolve()
    if run("git", "-C", producer, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip() != REVISION:
        raise ValueError("Unexpected shared fixture revision")
    run("git", "-C", producer, "diff", "--quiet", "HEAD", "--")
    if os.name != "nt":
        raise SystemExit("Windows native custody required; no protected acceptance")
    with tempfile.TemporaryDirectory(prefix="zrotext-time-policy-") as directory:
        target = Path(directory)
        if args.language == "go":
            binary = target / "compose.exe"
            run("go", "build", "-o", binary, "./cmd/compose", cwd=ROOT / "go")
        else:
            run("cargo", "build", "--locked", "--example", "compose", "--target-dir", target, cwd=ROOT / "rust")
            binary = target / "debug/examples/compose.exe"
        exercise(binary, producer)


if __name__ == "__main__":
    main()
