"""Native durable original-reply history with pinned maintained ciphertext."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
REVISION = "72124e1a3ff28e782f870eeddbdc33cacf8ca3b4"


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--language", choices=("rust", "go"), required=True)
    args = parser.parse_args()
    producer = args.producer.resolve()
    if run("git", "-C", producer, "rev-parse", "HEAD", capture_output=True).stdout.decode().strip() != REVISION:
        raise ValueError("Unexpected selected ciphertext producer")
    run("git", "-C", producer, "diff", "--quiet", "HEAD", "--")
    env = {k: v for k, v in os.environ.items() if k not in ("NODE_PATH", "NODE_OPTIONS")}
    fixture = run("node", producer / "sdk/native/sealed-candidate/python/produce-selected-reply02.mjs",
                  capture_output=True, timeout=45, env=env).stdout
    with tempfile.TemporaryDirectory(prefix="zrotext-reply-checkpoint-") as directory:
        target = Path(directory)
        if args.language == "go":
            binary = target / ("checkpoint.exe" if os.name == "nt" else "checkpoint")
            run("go", "build", "-o", binary, "./cmd/reply-checkpoint", cwd=ROOT / "go")
        else:
            run("cargo", "build", "--locked", "--example", "reply_checkpoint", "--target-dir", target, cwd=ROOT / "rust")
            binary = target / "debug/examples" / ("reply_checkpoint.exe" if os.name == "nt" else "reply_checkpoint")
        run(binary, input=fixture, timeout=90)


if __name__ == "__main__":
    main()
