# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded boot readiness for an already-started, job-owned emulator."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time


def wait_for_boot(pid, query, *, budget, clock=time.monotonic, sleep=time.sleep,
                  alive=None):
    if not 1 <= budget <= 300 or pid <= 0:
        raise ValueError("Invalid owned process or boot budget")
    if alive is None:
        def alive():
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                return False
    started = clock()
    probes = 0
    last = "not-probed"
    while True:
        elapsed = clock() - started
        if not alive():
            return dict(result="process-exited", elapsed_seconds=round(elapsed, 3),
                        probes=probes, last_probe=last, budget_seconds=budget)
        remaining = budget - elapsed
        if remaining <= 0:
            return dict(result="deadline", elapsed_seconds=round(elapsed, 3),
                        probes=probes, last_probe=last, budget_seconds=budget)
        probes += 1
        try:
            value = query(min(5, remaining)).strip()
            last = value if value in ("0", "1") else "empty" if not value else "other"
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            last = "query-failed"
        # A completed query after the deadline, or from a dead process, is not readiness.
        elapsed = clock() - started
        if last == "1" and elapsed < budget and alive():
            return dict(result="ready", elapsed_seconds=round(elapsed, 3),
                        probes=probes, last_probe=last, budget_seconds=budget)
        sleep(max(0, min(1, budget - elapsed)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--budget", type=int, default=300)
    args = parser.parse_args()
    if not re.fullmatch(r"emulator-[0-9]+", args.serial):
        parser.error("An explicit emulator selector is required")

    def query(timeout):
        return subprocess.run(
            [args.adb, "-s", args.serial, "shell", "getprop", "sys.boot_completed"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", timeout=timeout,
        ).stdout

    receipt = wait_for_boot(args.pid, query, budget=args.budget)
    args.receipt.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    print(json.dumps(receipt))
    return 0 if receipt["result"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
