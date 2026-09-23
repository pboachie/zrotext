#!/usr/bin/env python3
"""Write the immutable image reference for a reviewed source release."""

import argparse
import json
from pathlib import Path
import re

from check_release_tag import VERSION


IMAGE = "ghcr.io/pboachie/zrotext"
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def image_receipt(tag: str, commit: str, digest: str,
                  run_id: int, run_attempt: int) -> dict[str, object]:
    if not VERSION.fullmatch(tag):
        raise ValueError("Invalid source release tag")
    if not COMMIT.fullmatch(commit):
        raise ValueError("Source commit must be a full lowercase SHA")
    if not SHA256.fullmatch(digest):
        raise ValueError("Image digest must be a full lowercase SHA-256")
    if run_id < 1 or run_attempt < 1:
        raise ValueError("Workflow run ID and attempt must be positive")
    return {
        "schema_version": 1,
        "source_tag": tag,
        "source_commit": commit,
        "image": IMAGE,
        "build_tag": f"{tag}-run{run_id}-{run_attempt}",
        "image_digest": digest,
        "image_ref": f"{IMAGE}@{digest}",
        "workflow_run_id": run_id,
        "workflow_run_attempt": run_attempt,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    receipt = image_receipt(args.tag, args.commit, args.digest,
                            args.run_id, args.run_attempt)
    args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(receipt["image_ref"])


if __name__ == "__main__":
    main()
