# SPDX-License-Identifier: AGPL-3.0-only
"""Build the owner custodian from source for Android, with 16 KiB ELF alignment.

This is build-host tooling; the Android owner flow requires no desktop or CLI.
No signing credentials, app data, recovery kits or deployment flags are read.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ABIS = {
    "arm64-v8a": ("aarch64-linux-android", "aarch64-linux-android"),
    "armeabi-v7a": ("armv7-linux-androideabi", "armv7a-linux-androideabi"),
    "x86_64": ("x86_64-linux-android", "x86_64-linux-android"),
    "x86": ("i686-linux-android", "i686-linux-android"),
}
LIBRARY = "libzrotext_android_owner_custody.so"


def verify_load_alignment(readelf, library):
    result = subprocess.run(
        [str(readelf), "--program-headers", "--wide", str(library)],
        check=True, capture_output=True, text=True,
    )
    alignments = []
    for line in result.stdout.splitlines():
        if re.match(r"\s*LOAD\s", line):
            alignments.append(int(line.split()[-1], 16))
    if not alignments or any(value < 16384 for value in alignments):
        raise RuntimeError("Native library does not have 16 KiB LOAD alignment")


TYPED_JNI_METHODS = ("nativeOpenTyped", "nativeReviewTyped", "nativeSignTyped", "nativeArchiveRecoveryCheck")


def verify_typed_exports(nm, library):
    result = subprocess.run([str(nm), "--dynamic", "--defined-only", str(library)],
                            check=True, capture_output=True, text=True)
    symbols = {line.split()[-1] for line in result.stdout.splitlines() if line.split()}
    prefix = "Java_org_zrotext_gateway_AndroidOwnerCustodyNativeBridge_"
    if any(prefix + method not in symbols for method in TYPED_JNI_METHODS):
        raise RuntimeError("Native library is missing a typed owner-custody JNI export")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True,
                        help="Official Android NDK directory (r28 or newer)")
    parser.add_argument("--abis", nargs="+", choices=tuple(ABIS), default=list(ABIS))
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    properties = args.ndk / "source.properties"
    if not properties.is_file():
        parser.error("An installed official Android NDK is required")
    revision = re.search(r"Pkg.Revision\s*=\s*(\d+)\.", properties.read_text())
    if not revision or int(revision.group(1)) < 28:
        parser.error("Android NDK r28 or newer is required")
    prebuilt = args.ndk / "toolchains" / "llvm" / "prebuilt"
    host = "windows-x86_64" if sys.platform == "win32" else (
        "darwin-x86_64" if sys.platform == "darwin" else "linux-x86_64")
    toolbin = prebuilt / host / "bin"
    executable = ".exe" if sys.platform == "win32" else ""
    readelf = toolbin / ("llvm-readelf" + executable)
    if not readelf.is_file():
        parser.error("NDK tools for this build host are unavailable")
    target_dir = (args.target_dir or repo / "target" / "android-owner-custody").resolve()
    output = (args.output or repo / "android" / "app" / "build" /
              "generated" / "ownerCustodyJniLibs").resolve()
    for abi in args.abis:
        target, clang_target = ABIS[abi]
        linker = toolbin / (clang_target + "28-clang" +
                            (".cmd" if sys.platform == "win32" else ""))
        if not linker.is_file():
            parser.error("NDK Android API 28 linker unavailable for " + abi)
        env = os.environ.copy()
        cargo_target = target.upper().replace("-", "_")
        env["CARGO_TARGET_" + cargo_target + "_LINKER"] = str(linker)
        env["CARGO_TARGET_" + cargo_target + "_RUSTFLAGS"] = (
            "-C link-arg=-Wl,-z,max-page-size=16384 "
            "-C link-arg=-Wl,-z,common-page-size=16384")
        subprocess.run([
            args.cargo, "build", "--locked", "--release", "--package",
            "zrotext-android-owner-custody", "--target", target,
            "--target-dir", str(target_dir),
        ], cwd=repo, env=env, check=True)
        library = target_dir / target / "release" / LIBRARY
        verify_load_alignment(readelf, library)
        verify_typed_exports(toolbin / ("llvm-nm" + executable), library)
        destination = output / abi
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(library, destination / LIBRARY)
        print("Built and checked Android owner custody:", abi)


if __name__ == "__main__":
    main()
