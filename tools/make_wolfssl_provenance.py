#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Regenerate the vendored wolfSSL PROVENANCE digests.

Run against a checkout of the pinned upstream tag to verify the vendored
subset is byte-identical to unmodified upstream sources:

    git clone --filter=blob:none --no-checkout --depth 1 \
        --branch v5.9.4-stable https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl
    git -C /tmp/wolfssl checkout 3c5eead44904df64e6a5a1f4ebdce377d35a849a
    python3 tools/make_wolfssl_provenance.py /tmp/wolfssl

The vendored subset lives in android/app/src/main/cpp/wolfssl. The wolfssl/
directory is vendored as the complete wolfssl/ include tree minus the
OpenSSL-compat layer (headers and the upstream build files that ship inside
it); sources are the minimal set that builds the cryptocb-only HPKE receiver
(see CMakeLists.txt for the compiled list). Everything is copied unmodified
from the pinned tag; this build never patches upstream files.

The comparison is set-complete in both directions: every expected file must
exist in the vendored tree with an identical digest (otherwise MODIFIED or
MISSING), and every file present under the vendored prefix must belong to
the expected selection (otherwise EXTRA).
"""
import sys
from pathlib import Path

UPSTREAM_COMMIT = "3c5eead44904df64e6a5a1f4ebdce377d35a849a"
UPSTREAM_TAG = "v5.9.4-stable"

INCLUDE_EXCLUDE = ("wolfssl/openssl/",)
SOURCE_FILES = (
    "wolfcrypt/src/asn.c",
    "wolfcrypt/src/asn_orig.c",
    "wolfcrypt/src/asn_tsp.c",
    "wolfcrypt/src/aes.c",
    "wolfcrypt/src/coding.c",
    "wolfcrypt/src/cryptocb.c",
    "wolfcrypt/src/ecc.c",
    "wolfcrypt/src/error.c",
    "wolfcrypt/src/hash.c",
    "wolfcrypt/src/hmac.c",
    "wolfcrypt/src/hpke.c",
    "wolfcrypt/src/kdf.c",
    "wolfcrypt/src/logging.c",
    "wolfcrypt/src/memory.c",
    "wolfcrypt/src/misc.c",
    "wolfcrypt/src/random.c",
    "wolfcrypt/src/sha256.c",
    "wolfcrypt/src/sp_int.c",
    "wolfcrypt/src/wc_port.c",
    "wolfcrypt/src/wolfmath.c",
)
ROOT_FILES = ("LICENSING", "ChangeLog.md")
VENDORED = Path(__file__).resolve().parents[1] / "android/app/src/main/cpp/wolfssl"
MANIFEST_NAME = "PROVENANCE"


def digest(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_selection(upstream: Path) -> dict[str, Path]:
    expected: dict[str, Path] = {}
    for relative in ROOT_FILES:
        expected[relative] = upstream / relative
    for path in sorted((upstream / "wolfssl").rglob("*")):  # lgtm [py/path-injection] developer-supplied local checkout; contents are digested, never executed
        if not path.is_file():
            continue
        relative = path.relative_to(upstream).as_posix()
        if any(relative.startswith(prefix) for prefix in INCLUDE_EXCLUDE):
            continue
        expected[relative] = path
    for relative in SOURCE_FILES:
        expected[relative] = upstream / relative
    return expected


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    upstream = Path(sys.argv[1])
    expected = expected_selection(upstream)
    vendored_files = {
        path.relative_to(VENDORED).as_posix()
        for path in VENDORED.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    }
    lines = [
        "Vendored wolfSSL subset for the ZROtext AndroidKeyStore HPKE bridge.",
        f"Upstream: https://github.com/wolfSSL/wolfssl tag {UPSTREAM_TAG}",
        f"Commit: {UPSTREAM_COMMIT}",
        "License: GPLv3-or-later (see LICENSING); unmodified copies.",
        "",
    ]
    problems: list[str] = []
    for relative in sorted(expected):
        entry = f"{digest(expected[relative])}  {relative}"
        target = VENDORED / relative
        if not target.is_file():
            entry += "  MISSING"
            problems.append(f"missing vendored file: {relative}")
        elif digest(target) != digest(expected[relative]):
            entry += "  MODIFIED"
            problems.append(f"vendored file differs from upstream: {relative}")
        lines.append(entry)
    for relative in sorted(vendored_files - set(expected)):
        problems.append(f"unlisted vendored file: {relative}")
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"{len(problems)} vendored-tree problem(s) against upstream", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
