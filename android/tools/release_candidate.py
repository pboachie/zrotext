#!/usr/bin/env python3
"""Build an unsigned APK; sign and verify locally outside public Actions."""

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
MAX_APK_BYTES = 512 * 1024 * 1024
MAX_RECEIPT_BYTES = 16 * 1024
MAX_CHECKSUM_BYTES = 256
SOURCE_TAG = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?\Z"
)


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


def reviewed_tag_commit(tag: str) -> str:
    """Resolve an independently selected annotated release tag on main."""
    if not SOURCE_TAG.fullmatch(tag):
        raise ValueError("A valid independently selected release tag is required")
    ref = f"refs/tags/{tag}"
    # Git environment overrides can redirect the repository, object store, or
    # remote even with cwd pinned to ROOT. Keep this stricter scope local to
    # independent verification; build/sign retain their existing environment.
    safe_env = {key: value for key, value in unsigned_build_env().items()
                if not key.upper().startswith("GIT_")}
    safe_env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    })

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(["git", *args], cwd=ROOT, env=safe_env,
                                  capture_output=True, text=True, timeout=30,
                                  check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Release tag lookup could not finish") from exc

    kind = git("cat-file", "-t", ref)
    if kind.returncode or kind.stdout.strip() != "tag":
        raise ValueError("Release tag must be annotated")
    object_lookup = git("rev-parse", ref)
    tag_object = object_lookup.stdout.strip()
    if object_lookup.returncode or not re.fullmatch(r"[0-9a-f]{40}", tag_object):
        raise ValueError("Release tag object is invalid")
    remote = git("ls-remote", "--refs", "--tags", "origin", ref)
    if remote.returncode or remote.stdout.strip() != f"{tag_object}\t{ref}":
        raise ValueError("Local release tag differs from the published origin tag")
    resolved = git("rev-parse", f"{ref}^{{commit}}")
    commit = resolved.stdout.strip()
    if resolved.returncode or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Release tag does not resolve to a commit")
    local_main = git("rev-parse", "refs/remotes/origin/main")
    published_main = git("ls-remote", "--refs", "origin", "refs/heads/main")
    main_commit = local_main.stdout.strip()
    if (local_main.returncode or published_main.returncode
            or not re.fullmatch(r"[0-9a-f]{40}", main_commit)
            or published_main.stdout.strip() != f"{main_commit}\trefs/heads/main"):
        raise ValueError("Fetched origin/main differs from published main; fetch again")
    if git("merge-base", "--is-ancestor", commit,
           "refs/remotes/origin/main").returncode:
        raise ValueError("Release tag commit is not on fetched main")
    return commit


def verify_reviewed_candidate(tag: str, expected_certificate: str) -> None:
    verify_candidate(reviewed_tag_commit(tag), expected_certificate)


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


def checked_artifact_file(path: Path, max_bytes: int) -> Path:
    if path.is_symlink() or not path.is_file() or path.resolve().parent != path.parent.resolve():
        raise ValueError(f"{path.name} must be a regular file without a symlink")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path.name} exceeds the review size limit")
    return path


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


def checked_unsigned(commit: str) -> tuple[Path, str, dict[str, str | int]]:
    build_dir = ARTIFACT_ROOT / "unsigned"
    if ARTIFACT_ROOT.is_symlink() or build_dir.is_symlink() or not build_dir.is_dir():
        raise ValueError("Unsigned artifact directory must be a regular directory")
    receipt_path = checked_artifact_file(build_dir / "unsigned.json", MAX_RECEIPT_BYTES)
    unsigned = checked_artifact_file(build_dir / "unsigned.apk", MAX_APK_BYTES)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    digest = sha256(unsigned)
    if receipt.get("source_commit") != commit or receipt.get("unsigned_apk") != unsigned.name or (
        receipt.get("unsigned_apk_sha256") != digest
    ) or receipt.get("embedded_asset") != ASSET:
        raise ValueError("Unsigned APK receipt does not match the clean checkout and artifact")
    verify_source_asset(unsigned, commit)
    identity = apk_identity(unsigned)
    if receipt.get("apk_identity") != identity:
        raise ValueError("Unsigned APK identity does not match its receipt")
    return unsigned, digest, identity


def apk_entry_digests(apk: Path) -> dict[str, str]:
    contents = {}
    with zipfile.ZipFile(apk) as archive:
        for entry in archive.infolist():
            if entry.filename in contents:
                raise ValueError("APK contains duplicate ZIP entry names")
            digest = hashlib.sha256()
            with archive.open(entry) as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
            contents[entry.filename] = digest.hexdigest()
    return contents


def verify_apk_contents(unsigned: Path, signed: Path) -> None:
    if apk_entry_digests(unsigned) != apk_entry_digests(signed):
        raise ValueError("Signed APK entries differ from the unsigned build")


def sign_candidate(commit: str, keystore_path: Path,
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
    unsigned, unsigned_hash, identity = checked_unsigned(commit)
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
        verify_apk_contents(unsigned, apk)
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


def verify_candidate(commit: str, expected_certificate: str) -> None:
    """Independently verify transferred artifacts without signing credentials."""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("A full expected source commit is required")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_certificate):
        raise ValueError("An independently approved certificate SHA-256 is required")
    expected_certificate = expected_certificate.lower()
    candidate_dir = ARTIFACT_ROOT / "candidate"
    if (ARTIFACT_ROOT.is_symlink() or candidate_dir.is_symlink()
            or not candidate_dir.is_dir()):
        raise ValueError("Artifact directories must not be symlinks")
    external_artifact_path(ARTIFACT_ROOT, "Artifact root")
    unsigned, unsigned_hash, identity = checked_unsigned(commit)
    candidates = list(candidate_dir.glob("zrotext-android-*-candidate.apk"))
    expected_name = f"zrotext-android-{commit[:12]}-candidate.apk"
    if len(candidates) != 1 or candidates[0].name != expected_name:
        raise ValueError("Expected exactly one signed APK for the source commit")
    apk = checked_artifact_file(candidates[0], MAX_APK_BYTES)
    receipt_path = checked_artifact_file(candidate_dir / "candidate.json", MAX_RECEIPT_BYTES)
    checksums = checked_artifact_file(candidate_dir / "SHA256SUMS", MAX_CHECKSUM_BYTES)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    artifact_hash = sha256(apk)
    expected = {
        "source_commit": commit,
        "embedded_asset": ASSET,
        "unsigned_apk_sha256": unsigned_hash,
        "apk": apk.name,
        "apk_sha256": artifact_hash,
        "signing_certificate_sha256": expected_certificate,
        "apk_identity": identity,
        "min_sdk_verified": 28,
    }
    if receipt != expected:
        raise ValueError("Signed APK receipt differs from artifacts or approved certificate")
    if checksums.read_text(encoding="ascii") != (
        f"{artifact_hash}  {apk.name}\n"
    ):
        raise ValueError("Signed APK checksum file differs from the artifact")
    verify_source_asset(apk, commit)
    verify_apk_contents(unsigned, apk)
    if apk_identity(apk) != identity:
        raise ValueError("Signed APK identity differs from the unsigned build")
    apksigner = sdk_tool("apksigner")
    zipalign = sdk_tool("zipalign")
    output = run(apksigner, "verify", "--verbose", "--print-certs",
                 "--min-sdk-version", "28", apk, capture=True,
                 env=unsigned_build_env())
    for scheme in ("v2", "v3"):
        if not re.search(rf"^Verified using {scheme} scheme .*: true$",
                         output, re.MULTILINE):
            raise ValueError(f"Signed APK did not verify with {scheme}")
    certificates = set(re.findall(r"certificate SHA-256 digest: ([0-9a-fA-F]{64})", output))
    if len(certificates) != 1 or certificates.pop().lower() != expected_certificate:
        raise ValueError("APK signing certificate differs from approved fingerprint")
    run(zipalign, "-c", "4", apk, capture=True, env=unsigned_build_env())
    print(f"Verified signed candidate: {apk}")
    print(f"Source commit: {commit}")
    print(f"Unsigned APK SHA-256: {unsigned_hash}")
    print(f"Signed APK SHA-256: {artifact_hash}")
    print(f"Signing certificate SHA-256: {expected_certificate}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="phase", required=True)
    build = commands.add_parser("build", help="Lint, test and assemble without signing secrets")
    sign = commands.add_parser("sign", help="Sign and verify a prior unsigned build")
    verify = commands.add_parser("verify", help="Independently check transferred unsigned and signed APKs")
    verify.add_argument("--source-tag", required=True,
                        help="independently selected annotated release tag on fetched main")
    verify.add_argument("--certificate-sha256", required=True,
                        help="approved fingerprint obtained independently of candidate.json")
    args = parser.parse_args()
    if args.phase == "verify":
        verify_reviewed_candidate(args.source_tag, args.certificate_sha256)
        return
    commit = source_commit(os.environ.get("GITHUB_SHA"))
    if args.phase == "build":
        out = external_artifact_path(ARTIFACT_ROOT / "unsigned", "Output directory")
        build_unsigned(commit, out)
    else:
        out = external_artifact_path(ARTIFACT_ROOT / "candidate", "Output directory")
        sign_candidate(commit, ARTIFACT_ROOT / "keystore.p12", SIGNING_ALIAS, out)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValueError, OSError, UnicodeError,
            zipfile.BadZipFile) as error:
        print(f"Release candidate failed: {error}", file=sys.stderr)
        sys.exit(1)
