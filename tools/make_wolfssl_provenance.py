#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Regenerate the vendored wolfSSL PROVENANCE digests.

Run against a checkout of the pinned upstream tag to verify the vendored
subset is byte-identical to unmodified upstream sources:

    git clone --depth 1 --branch v5.9.4-stable \
        https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl
    python3 tools/make_wolfssl_provenance.py /tmp/wolfssl

The vendored subset lives in android/app/src/main/cpp/wolfssl. Headers are
vendored as the complete wolfssl/ include tree minus the OpenSSL-compat
layer; sources are the minimal set that builds the cryptocb-only HPKE
receiver (see CMakeLists.txt for the compiled list). Everything is copied
unmodified from the pinned tag; this build never patches upstream files.
"""
import hashlib
import sys
from pathlib import Path

UPSTREAM_COMMIT = "3c5eead44904df64e6a5a1f4ebdce377d35a849a"
UPSTREAM_TAG = "v5.9.4-stable"

HEADERS_EXCLUDE = ("wolfssl/openssl/",)
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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    upstream = Path(sys.argv[1])
    lines = [
        "Vendored wolfSSL subset for the ZROtext AndroidKeyStore HPKE bridge.",
        f"Upstream: https://github.com/wolfSSL/wolfssl tag {UPSTREAM_TAG}",
        f"Commit: {UPSTREAM_COMMIT}",
        "License: GPLv3-or-later (see LICENSING); unmodified copies.",
        "",
    ]
    mismatch = 0
    vendored = Path(__file__).resolve().parents[1] / "android/app/src/main/cpp/wolfssl"
    for relative in ROOT_FILES:
        source = upstream / relative
        target = vendored / relative
        entry = f"{digest(source)}  {relative}"
        if target.is_file() and digest(target) != digest(source):
            entry += "  MODIFIED"
            mismatch += 1
        lines.append(entry)
    for path in sorted((upstream / "wolfssl").rglob("*.h")):
        relative = path.relative_to(upstream).as_posix()
        if any(relative.startswith(prefix) for prefix in HEADERS_EXCLUDE):
            continue
        entry = f"{digest(path)}  {relative}"
        target = vendored / relative
        if target.is_file() and digest(target) != digest(path):
            entry += "  MODIFIED"
            mismatch += 1
        lines.append(entry)
    for relative in SOURCE_FILES:
        source = upstream / relative
        entry = f"{digest(source)}  {relative}"
        target = vendored / relative
        if target.is_file() and digest(target) != digest(source):
            entry += "  MODIFIED"
            mismatch += 1
        lines.append(entry)
    if mismatch:
        print(f"{mismatch} vendored file(s) differ from upstream", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
