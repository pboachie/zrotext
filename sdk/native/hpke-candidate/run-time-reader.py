"""Verify native reader timing refusals using genuine signed/encrypted fixtures."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
REVISION = "3cda99572eafb0dbc2504f88e228f5481234e33f"


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def exercise(binary, producer):
    env = {k: v for k, v in os.environ.items() if k not in ("NODE_PATH", "NODE_OPTIONS")}
    fixture = run("node", producer / "sdk/typescript/test/fixtures/profile03-time-cli.mjs",
                  "--reader-cases", capture_output=True, timeout=60, env=env).stdout
    run(binary, input=fixture, timeout=45)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--language", choices=("rust", "go"), required=True)
    args = parser.parse_args()
    producer = args.producer.resolve()
    if run("git", "-C", producer, "rev-parse", "HEAD", capture_output=True).stdout.decode().strip() != REVISION:
        raise ValueError("Unexpected authenticated reader fixture pin")
    run("git", "-C", producer, "diff", "--quiet", "HEAD", "--")
    with tempfile.TemporaryDirectory(prefix="zrotext-reader-time-") as directory:
        target = Path(directory)
        if args.language == "go":
            binary = target / ("reader.exe" if os.name == "nt" else "reader")
            run("go", "build", "-o", binary, "./cmd/time-reader", cwd=ROOT / "go")
        else:
            run("cargo", "build", "--locked", "--example", "time_reader", "--target-dir", target, cwd=ROOT / "rust")
            binary = target / "debug/examples" / ("time_reader.exe" if os.name == "nt" else "time_reader")
        exercise(binary, producer)


if __name__ == "__main__":
    main()
