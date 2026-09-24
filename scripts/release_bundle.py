#!/usr/bin/env python3
"""Bind independently verified release receipts to one immutable source tag.

This writes metadata only. It does not sign, publish, deploy, or retag artifacts.
Verify the signed APK and published image with their dedicated verifiers first.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from check_release_tag import VERSION


ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_DIR = Path.home() / ".zrotext" / "release-bundle"
CANDIDATE_RECEIPT = ARTIFACT_DIR / "candidate.json"
IMAGE_RECEIPT = ARTIFACT_DIR / "image-receipt.json"
MANIFEST = ARTIFACT_DIR / "release-bundle.json"
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
ENVIRONMENTS = {"test", "staging", "production", "self-hosted"}
WEB_FILES = (
    "web/owner/devices.html",
    "web/owner/devices.js",
    "web/owner/devices.css",
    "crates/server/static/billing-dashboard.html",
    "crates/server/static/billing-dashboard.js",
)
DEVICE_STREAM_SCHEMA = "protocol/v1/device-stream.schema.json"
MAX_RECEIPT_BYTES = 16_384


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> tuple[dict[str, object], str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECEIPT_BYTES:
        raise ValueError(f"Missing, linked, or oversized JSON receipt: {path}")
    raw = path.read_bytes()

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        pairs_seen: set[str] = set()
        result = {}
        for key, value in pairs:
            if key in pairs_seen:
                raise ValueError(f"Duplicate JSON field: {key}")
            pairs_seen.add(key)
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    if not isinstance(value, dict):
        raise ValueError("Receipt must be a JSON object")
    return value, sha256(raw)


def checked_artifact_dir() -> None:
    parent = ARTIFACT_DIR.parent
    if parent.is_symlink() or ARTIFACT_DIR.is_symlink() or not ARTIFACT_DIR.is_dir():
        raise ValueError("Private release artifact directory is missing or linked")
    if os.name != "nt" and ARTIFACT_DIR.stat().st_mode & 0o077:
        raise ValueError("Private release artifact directory must be owner-only")


def file_set_digest(root: Path, paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        parts = Path(relative).parts
        if any(root.joinpath(*parts[:index]).is_symlink()
               for index in range(1, len(parts) + 1)) or not path.is_file():
            raise ValueError(f"Release source file missing or linked: {relative}")
        data = path.read_bytes()
        digest.update(relative.encode("ascii") + b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def migrations(root: Path) -> tuple[int, str]:
    directory = root / "deploy/compose/migrations"
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Migration directory is missing or linked")
    files = sorted(directory.glob("*.sql"))
    versions = []
    for path in files:
        if not re.fullmatch(r"[0-9]{3,}_[a-z0-9_]+\.sql", path.name):
            raise ValueError(f"Invalid migration filename: {path.name}")
        versions.append(int(path.name.split("_", 1)[0]))
    versions.sort()
    if not versions or versions != list(range(1, len(versions) + 1)):
        raise ValueError("Migration versions must be consecutive from 001")
    paths = tuple(path.relative_to(root).as_posix() for path in files)
    return versions[-1], file_set_digest(root, paths)


def validated_candidate(value: dict[str, object], commit: str) -> dict[str, object]:
    if set(value) != {
        "source_commit", "embedded_asset", "unsigned_apk_sha256", "sbom_sha256",
        "apk", "apk_sha256", "signing_certificate_sha256", "apk_identity",
        "min_sdk_verified",
    } or value["source_commit"] != commit:
        raise ValueError("Signed Android receipt source or shape differs")
    identity = value["apk_identity"]
    if not isinstance(identity, dict) or set(identity) != {
        "package", "version_code", "version_name", "min_sdk", "target_sdk",
    }:
        raise ValueError("Android identity is incomplete")
    if identity["package"] != "org.zrotext.gateway" or type(identity["version_code"]) is not int \
            or identity["version_code"] < 1 or type(identity["min_sdk"]) is not int \
            or identity["min_sdk"] != 28 or type(identity["target_sdk"]) is not int \
            or identity["target_sdk"] < 28 or value["min_sdk_verified"] != 28:
        raise ValueError("Android package, version, or SDK floor differs")
    if not isinstance(identity["version_name"], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", identity["version_name"]):
        raise ValueError("Android version name is invalid")
    for key in ("unsigned_apk_sha256", "sbom_sha256", "apk_sha256",
                "signing_certificate_sha256"):
        if not isinstance(value[key], str) or not HEX.fullmatch(value[key]):
            raise ValueError(f"Android {key} is invalid")
    if value["embedded_asset"] != "assets/zrotext-source-commit.txt" or \
            value["apk"] != f"zrotext-android-{commit[:12]}-candidate.apk":
        raise ValueError("Android APK or embedded source stamp differs")
    return identity


def validated_image(value: dict[str, object], tag: str, commit: str) -> None:
    if set(value) != {
        "schema_version", "source_tag", "source_commit", "image", "build_tag",
        "image_digest", "image_ref", "workflow_run_id", "workflow_run_attempt",
    } or type(value["schema_version"]) is not int or value["schema_version"] != 1 \
            or value["source_tag"] != tag \
            or value["source_commit"] != commit or value["image"] != "ghcr.io/pboachie/zrotext":
        raise ValueError("Server image receipt source or shape differs")
    digest = value["image_digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Server image digest is invalid")
    if type(value["workflow_run_id"]) is not int or value["workflow_run_id"] < 1 \
            or type(value["workflow_run_attempt"]) is not int \
            or value["workflow_run_attempt"] < 1:
        raise ValueError("Server workflow identity is invalid")
    if value["image_ref"] != f"ghcr.io/pboachie/zrotext@{digest}" or value["build_tag"] != (
            f"{tag}-run{value['workflow_run_id']}-{value['workflow_run_attempt']}"):
        raise ValueError("Server image reference or run tag differs")


def release_bundle(root: Path, tag: str, commit: str, environment: str,
                   candidate: dict[str, object], candidate_sha: str,
                   image: dict[str, object], image_sha: str) -> dict[str, object]:
    if not VERSION.fullmatch(tag) or not COMMIT.fullmatch(commit):
        raise ValueError("A versioned tag and full source commit are required")
    if environment not in ENVIRONMENTS:
        raise ValueError("Deployment environment must be explicit")
    identity = validated_candidate(candidate, commit)
    version_core = tag[1:].split("-rc.", 1)[0]
    if not (identity["version_name"] == version_core or
            identity["version_name"].startswith(version_core + "-")):
        raise ValueError("Android version name differs from bundle version core")
    validated_image(image, tag, commit)
    for digest in (candidate_sha, image_sha):
        if not HEX.fullmatch(digest):
            raise ValueError("Receipt digest is invalid")
    migration_last, migration_digest = migrations(root)
    web_digest = file_set_digest(root, WEB_FILES)
    schema_file = root / DEVICE_STREAM_SCHEMA
    if schema_file.is_symlink() or not schema_file.is_file():
        raise ValueError("Device stream schema is missing or linked")
    return {
        "schema_version": 1,
        "bundle_version": tag,
        "source_commit": commit,
        "deployment_environment": environment,
        "android": {
            "apk_sha256": candidate["apk_sha256"],
            "apk_name": candidate["apk"],
            "version_code": identity["version_code"],
            "version_name": identity["version_name"],
            "signing_certificate_sha256": candidate["signing_certificate_sha256"],
            "candidate_receipt_sha256": candidate_sha,
        },
        "server": {
            "image_ref": image["image_ref"],
            "image_digest": image["image_digest"],
            "image_receipt_sha256": image_sha,
        },
        "web": {
            "artifact_type": "static-embedded-in-server-image",
            "static_sha256": web_digest,
            "source_paths": list(WEB_FILES),
        },
        "protocol": {
            "device_stream_version": "v1",
            "device_stream_schema_sha256": sha256(schema_file.read_bytes()),
            "sealed_content": "disabled",
        },
        "database": {
            "migration_first": 1,
            "migration_last": migration_last,
            "migration_source_sha256": migration_digest,
        },
    }


def verify_tag(root: Path, tag: str, commit: str) -> None:
    if not VERSION.fullmatch(tag) or not COMMIT.fullmatch(commit):
        raise ValueError("A versioned tag and full source commit are required")

    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=root, text=True,
                                       encoding="utf-8").strip()

    ref = f"refs/tags/{tag}"
    if git("cat-file", "-t", ref) != "tag" or git("rev-parse", f"{ref}^{{commit}}") != commit:
        raise ValueError("Source tag must be annotated and resolve to the expected commit")
    if git("rev-parse", "HEAD") != commit or git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Release bundle requires a clean exact-tag checkout")
    if subprocess.run(["git", "merge-base", "--is-ancestor", commit, "origin/main"],
                      cwd=root, check=False).returncode:
        raise ValueError("Release tag must be on the main branch")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--environment", required=True, choices=sorted(ENVIRONMENTS))
    args = parser.parse_args()
    verify_tag(ROOT, args.tag, args.commit)
    checked_artifact_dir()
    candidate, candidate_sha = read_json(CANDIDATE_RECEIPT)
    image, image_sha = read_json(IMAGE_RECEIPT)
    expected = release_bundle(ROOT, args.tag, args.commit, args.environment,
                              candidate, candidate_sha, image, image_sha)
    serialized = json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    target = MANIFEST
    if target.is_symlink():
        raise ValueError("Bundle manifest must not be a link")
    if args.mode == "create":
        with target.open("x", encoding="utf-8", newline="\n") as output:
            output.write(serialized)
            output.flush()
            os.fsync(output.fileno())
    elif target.read_text(encoding="utf-8") != serialized:
        raise ValueError("Bundle manifest differs from source and provided receipts")
    verb = "created" if args.mode == "create" else "verified"
    print(f"{verb} bundle {args.tag} sha256:{sha256(serialized.encode('utf-8'))}")


if __name__ == "__main__":
    main()
