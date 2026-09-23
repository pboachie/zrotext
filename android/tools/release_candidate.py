#!/usr/bin/env python3
"""Build and verify a signed, non-published Android release candidate."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]
ANDROID = ROOT / "android"
ASSET = "assets/zrotext-source-commit.txt"
EXPECTED_PACKAGE = "org.zrotext.gateway"
SIGNING_ALIAS = "zrotext-release"
ARTIFACT_ROOT = Path(tempfile.gettempdir()) / "zrotext-android-release"
STORE_PASSWORD = "ZROTEXT_ANDROID_KEYSTORE_PASSWORD"
KEY_PASSWORD = "ZROTEXT_ANDROID_KEY_PASSWORD"


def unsigned_build_env(environment: dict[str, str] | None = None) -> dict[str, str]:
    values = os.environ if environment is None else environment
    return {key: value for key, value in values.items()
            if not key.startswith("ZROTEXT_ANDROID_")}


def signing_env(environment: dict[str, str] | None = None) -> dict[str, str]:
    values = os.environ if environment is None else environment
    scoped = unsigned_build_env(values)
    for key in (STORE_PASSWORD, KEY_PASSWORD):
        if not values.get(key):
            raise ValueError(f"{key} is required for signing")
        scoped[key] = values[key]
    return scoped


def run(*args: object, cwd: Path = ROOT, capture: bool = False,
        env: dict[str, str] | None = None) -> str:
    command = [str(arg) for arg in args]
    result = subprocess.run(command, cwd=cwd, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None, env=env)
    return result.stdout.strip() if capture else ""


def sdk_tool(name: str) -> Path:
    if name not in {"zipalign", "apksigner", "aapt"}:
        raise ValueError("Unsupported Android SDK tool")
    found = shutil.which(name)
    if not found:
        raise ValueError(f"{name} is missing from PATH")
    return Path(found)


def source_commit(expected: str | None) -> str:
    safe_env = unsigned_build_env()
    commit = run("git", "rev-parse", "HEAD", capture=True, env=safe_env)
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or (expected and commit != expected):
        raise ValueError("Checkout does not match the expected full source commit")
    if run("git", "status", "--porcelain", "--untracked-files=all",
           capture=True, env=safe_env):
        raise ValueError("Source checkout must be clean, including untracked files")
    return commit


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def external_artifact_path(path: Path, description: str) -> Path:
    resolved = path.resolve()
    if resolved.is_relative_to(ROOT):
        raise ValueError(f"{description} must be outside the source checkout")
    return resolved


def verify_source_asset(apk: Path, commit: str) -> None:
    with zipfile.ZipFile(apk) as archive:
        if archive.namelist().count(ASSET) != 1 or archive.read(ASSET) != f"{commit}\n".encode("ascii"):
            raise ValueError("APK source asset does not match the clean checkout")


def parse_apk_identity(badging: str) -> dict[str, str | int]:
    package = re.search(
        r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'",
        badging, re.MULTILINE,
    )
    min_sdk = re.search(r"^sdkVersion:'([0-9]+)'$", badging, re.MULTILINE)
    target_sdk = re.search(r"^targetSdkVersion:'([0-9]+)'$", badging, re.MULTILINE)
    if not package or not min_sdk or not target_sdk:
        raise ValueError("APK package or SDK metadata is missing")
    if package.group(1) != EXPECTED_PACKAGE:
        raise ValueError("APK package name is not the ZROtext gateway")
    if int(min_sdk.group(1)) != 28:
        raise ValueError("APK minimum SDK differs from the supported release floor")
    return {
        "package": package.group(1),
        "version_code": int(package.group(2)),
        "version_name": package.group(3),
        "min_sdk": int(min_sdk.group(1)),
        "target_sdk": int(target_sdk.group(1)),
    }


def apk_identity(apk: Path) -> dict[str, str | int]:
    badging = run(sdk_tool("aapt"), "dump", "badging", apk,
                  capture=True, env=unsigned_build_env())
    return parse_apk_identity(badging)


def build_unsigned(commit: str, out: Path) -> None:
    if out.exists():
        raise ValueError("Output directory already exists; use a new directory")
    gradle = ANDROID / ("gradlew.bat" if os.name == "nt" else "gradlew")
    run(gradle, ":app:lintRelease", ":app:testDebugUnitTest", ":app:assembleRelease",
        "--no-daemon", "--console=plain", f"-PzrotextSourceCommit={commit}",
        cwd=ANDROID, env=unsigned_build_env())
    source_commit(commit)  # Gradle must leave the tracked checkout clean.
    unsigned = ANDROID / "app/build/outputs/apk/release/app-release-unsigned.apk"
    if not unsigned.is_file():
        raise ValueError("Gradle did not produce the expected unsigned release APK")
    verify_source_asset(unsigned, commit)
    identity = apk_identity(unsigned)
    out.mkdir(parents=True)
    copy = out / "unsigned.apk"
    shutil.copyfile(unsigned, copy)
    digest = sha256(copy)
    (out / "unsigned.json").write_text(json.dumps({
        "source_commit": commit,
        "unsigned_apk": copy.name,
        "unsigned_apk_sha256": digest,
        "embedded_asset": ASSET,
        "apk_identity": identity,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Unsigned candidate: {copy}")
    print(f"Source commit: {commit}")
    print(f"Unsigned APK SHA-256: {digest}")


def checked_unsigned(build_dir: Path, commit: str) -> tuple[Path, str, dict[str, str | int]]:
    receipt = json.loads((build_dir / "unsigned.json").read_text(encoding="utf-8"))
    unsigned = build_dir / "unsigned.apk"
    digest = sha256(unsigned)
    if receipt.get("source_commit") != commit or receipt.get("unsigned_apk") != unsigned.name or (
        receipt.get("unsigned_apk_sha256") != digest
    ):
        raise ValueError("Unsigned APK receipt does not match the clean checkout and artifact")
    verify_source_asset(unsigned, commit)
    identity = apk_identity(unsigned)
    if receipt.get("apk_identity") != identity:
        raise ValueError("Unsigned APK identity does not match its receipt")
    return unsigned, digest, identity


def sign_candidate(commit: str, build_dir: Path, keystore_path: Path,
                   alias: str, out: Path) -> None:
    if not keystore_path.is_file():
        raise ValueError("Keystore file does not exist")
    keystore = external_artifact_path(keystore_path, "Keystore")
    if not alias.strip() or any(c.isspace() for c in alias):
        raise ValueError("A nonempty keystore alias without whitespace is required")
    if not os.environ.get(STORE_PASSWORD) or not os.environ.get(KEY_PASSWORD):
        raise ValueError(f"{STORE_PASSWORD} and {KEY_PASSWORD} are required in the environment")
    if out.exists():
        raise ValueError("Output directory already exists; use a new directory")
    unsigned, unsigned_hash, identity = checked_unsigned(build_dir, commit)
    out.mkdir(parents=True)
    apk = out / f"zrotext-android-{commit[:12]}-candidate.apk"
    aligned = out / "aligned-unsigned.apk"
    zipalign = sdk_tool("zipalign")
    apksigner = sdk_tool("apksigner")
    no_secrets = unsigned_build_env()
    signer_env = signing_env()
    try:
        run(zipalign, "-p", "-f", "4", unsigned, aligned, env=no_secrets)
        run(apksigner, "sign", "--ks", keystore, "--ks-key-alias", alias,
            "--ks-pass", f"env:{STORE_PASSWORD}", "--key-pass", f"env:{KEY_PASSWORD}",
            "--v1-signing-enabled", "false", "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
            "--out", apk, aligned, env=signer_env)
        verify = run(apksigner, "verify", "--verbose", "--print-certs",
                     "--min-sdk-version", "28", apk, capture=True, env=no_secrets)
        run(zipalign, "-c", "4", apk, capture=True, env=no_secrets)
        verify_source_asset(apk, commit)
        if apk_identity(apk) != identity:
            raise ValueError("Signed APK identity differs from the unsigned build")
        certificates = set(re.findall(r"certificate SHA-256 digest: ([0-9a-fA-F]{64})", verify))
        if len(certificates) != 1:
            raise ValueError("Expected exactly one verifiable APK signing certificate")
        certificate_hash = certificates.pop().lower()
        artifact_hash = sha256(apk)
        (out / "SHA256SUMS").write_text(f"{artifact_hash}  {apk.name}\n", encoding="ascii")
        (out / "candidate.json").write_text(json.dumps({
            "source_commit": commit,
            "embedded_asset": ASSET,
            "unsigned_apk_sha256": unsigned_hash,
            "apk": apk.name,
            "apk_sha256": artifact_hash,
            "signing_certificate_sha256": certificate_hash,
            "apk_identity": identity,
            "min_sdk_verified": 28,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Verified candidate: {apk}")
        print(f"Source commit: {commit}")
        print(f"APK SHA-256: {artifact_hash}")
        print(f"Signing certificate SHA-256: {certificate_hash}")
    except Exception:
        apk.unlink(missing_ok=True)
        (out / "SHA256SUMS").unlink(missing_ok=True)
        (out / "candidate.json").unlink(missing_ok=True)
        raise
    finally:
        aligned.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="phase", required=True)
    build = commands.add_parser("build", help="Lint, test and assemble without signing secrets")
    sign = commands.add_parser("sign", help="Sign and verify a prior unsigned build")
    args = parser.parse_args()
    commit = source_commit(os.environ.get("GITHUB_SHA"))
    if args.phase == "build":
        out = external_artifact_path(ARTIFACT_ROOT / "unsigned", "Output directory")
        build_unsigned(commit, out)
    else:
        build_dir = external_artifact_path(ARTIFACT_ROOT / "unsigned", "Unsigned build directory")
        out = external_artifact_path(ARTIFACT_ROOT / "candidate", "Output directory")
        sign_candidate(commit, build_dir, ARTIFACT_ROOT / "keystore.p12", SIGNING_ALIAS, out)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValueError) as error:
        print(f"Release candidate failed: {error}", file=sys.stderr)
        sys.exit(1)
