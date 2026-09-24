#!/usr/bin/env python3
"""Read the BuildKit SPDX SBOM attached to an exact published image digest."""

import argparse
import json
from pathlib import Path
import re
import subprocess


IMAGE_REF = re.compile(r"ghcr\.io/pboachie/zrotext@sha256:[0-9a-f]{64}\Z")
MAX_SBOM_BYTES = 16 * 1024 * 1024
SPDX_PREDICATES = {
    "SPDX-2.2": "https://spdx.dev/Document/v2.2",
    "SPDX-2.3": "https://spdx.dev/Document/v2.3",
}


class SbomError(Exception):
    pass


def checked_spdx(raw: str) -> dict[str, object]:
    if not raw or len(raw.encode("utf-8")) > MAX_SBOM_BYTES:
        raise SbomError("published image SBOM is empty or exceeds the size limit")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise SbomError("published image SBOM is not JSON") from exc
    if (not isinstance(document, dict)
            or document.get("spdxVersion") not in SPDX_PREDICATES
            or document.get("SPDXID") != "SPDXRef-DOCUMENT"
            or not isinstance(document.get("packages"), list)
            or not document["packages"]
            or not all(isinstance(package, dict)
                       and isinstance(package.get("name"), str)
                       and package["name"].strip()
                       for package in document["packages"])):
        raise SbomError("published image has no usable SPDX package inventory")
    return document


def spdx_predicate(document: dict[str, object]) -> str:
    try:
        return SPDX_PREDICATES[document["spdxVersion"]]
    except (KeyError, TypeError) as exc:
        raise SbomError("published image SPDX version is unsupported") from exc


def published_sbom(image_ref: str) -> dict[str, object]:
    if not IMAGE_REF.fullmatch(image_ref):
        raise SbomError("SBOM lookup requires the selected immutable image digest")
    try:
        result = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", image_ref,
             "--format", "{{ json .SBOM.SPDX }}"],
            capture_output=True, text=True, encoding="utf-8", timeout=180,
            check=False, shell=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise SbomError("published image SBOM lookup could not finish") from exc
    if result.returncode:
        raise SbomError("published image SBOM lookup failed")
    return checked_spdx(result.stdout.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    document = published_sbom(args.image_ref)
    with args.output.open("x", encoding="utf-8") as destination:
        json.dump(document, destination, separators=(",", ":"), sort_keys=True)
        destination.write("\n")


if __name__ == "__main__":
    try:
        main()
    except (SbomError, OSError) as exc:
        raise SystemExit(f"published image SBOM verification failed: {exc}")
