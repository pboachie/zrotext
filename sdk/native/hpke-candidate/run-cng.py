"""Build native Windows examples; qualify PCP only when capability probe succeeds.

Any failure after key creation is a test failure, never a skipped hardware gate.
Durable exact-alias receipts live in the user's temp directory, never this tree.
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
PRODUCER_REVISION = "93a65d737dfb0de603c732241c667f90771f60dd"


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def exercise(binary, producer, profile=2):
    probe = subprocess.run([str(binary), "--probe"], capture_output=True, text=True, timeout=30)
    if probe.returncode == 77:
        print("Native PCP capability unavailable; protected reader NOT qualified")
        return False
    if probe.returncode:
        raise RuntimeError("Native capability probe failed")
    process = subprocess.Popen([str(binary)] + (["--elected"] if profile == 3 else []), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    ready = queue.Queue()
    threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
    try:
        first = ready.get(timeout=45)
        if not first:
            raise RuntimeError("Native hardware creation/qualification failed")
        record = json.loads(first)
        if set(record) != {"public"} or len(record["public"]) != 130:
            raise ValueError("Unexpected native public-point record")
        env = {key: value for key, value in os.environ.items() if key not in ("NODE_PATH", "NODE_OPTIONS")}
        fixture = run(shutil.which("node"), producer / ("sdk/native/sealed-candidate/python/produce-election03.mjs" if profile == 3 else "sdk/native/sealed-candidate/python/produce-fixture.mjs"),
                      "--recipient-point", record["public"], capture_output=True, text=True, timeout=45, env=env).stdout
        output, errors = process.communicate(fixture, timeout=45)
        if process.returncode:
            raise RuntimeError("Native protected reader failed: " + errors)
        print(output.strip())
        return True
    finally:
        if process.poll() is None:
            # EOF triggers the example's exact-key cleanup even after producer failure.
            try:
                process.communicate("", timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError("Native cleanup timed out; preserve the private pending-alias receipt for exact recovery")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--language", choices=("rust", "go"), required=True)
    parser.add_argument("--profile", type=int, choices=(2, 3), default=2)
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("Windows native execution required; no protected acceptance")
    producer = args.producer.resolve()
    revision = run("git", "-C", producer, "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    expected_revision = "304d512b7a420a3102278f32baed095f3e778989" if args.profile == 3 else PRODUCER_REVISION
    if revision != expected_revision:
        raise ValueError("Unexpected producer revision")
    run("git", "-C", producer, "diff", "--quiet", "HEAD", "--")
    with tempfile.TemporaryDirectory(prefix="zrotext-native-cng-build-") as folder:
        temp = Path(folder)
        if args.language == "go":
            binary = temp / "cng.exe"
            run("go", "build", "-o", binary, "./cmd/cng", cwd=ROOT / "go")
        else:
            run("cargo", "build", "--locked", "--example", "cng", "--target-dir", temp, cwd=ROOT / "rust")
            binary = temp / "debug/examples/cng.exe"
        exercise(binary, producer, args.profile)


if __name__ == "__main__":
    main()
