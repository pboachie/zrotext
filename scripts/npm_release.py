#!/usr/bin/env python3
"""Fail-closed checks and receipts for the public alpha npm preview.

This script reads GitHub/npm and writes local receipts; it never publishes or
changes settings. Publication remains a separate protected workflow step.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

from check_release_tag import VERSION

ROOT = Path(__file__).resolve().parent.parent
REPO = "pboachie/zrotext"
PACKAGE = "zrotext"
OWNER = "pboachie"
OWNER_ID = 9089767
ENVIRONMENT = "npm-publication"
PREVIEW = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-rc\.([1-9]\d*)\Z")
HEX = re.compile(r"[0-9a-f]{40}\Z")
CHECKS = {"rust", "android", "quality", "owner-browser", "npm-package"}
RECEIPT_FIELDS = {
    "schema_version", "name", "version", "tag", "source_commit", "run_id",
    "run_attempt", "environment_id", "filename", "sha256", "integrity",
    "files", "build_lock_sha256", "public_manifest_sha256", "public_lock_sha256",
}


class ReleaseError(Exception):
    pass


def read_json(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1_048_576:
        raise ReleaseError("Missing, linked or oversized JSON input.")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ReleaseError("Invalid JSON input.") from exc


def digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ReleaseError("Missing or linked digest input.")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gh(path: str, *, pages: bool = False):
    command = ["gh", "api"]
    if pages:
        command += ["--paginate", "--slurp"]
    command += [path]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ReleaseError("GitHub read failed; reconcile access before retrying.")
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise ReleaseError("GitHub returned invalid JSON.") from exc


def registry(opener=urllib.request.urlopen):
    request = urllib.request.Request(
        "https://registry.npmjs.org/zrotext", headers={"Accept": "application/json"}
    )
    try:
        with opener(request, timeout=30) as response:
            if response.status != 200:
                raise ReleaseError("Unexpected registry response.")
            body = response.read(10_000_001)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ReleaseError("Registry read failed; absence is not established.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ReleaseError("Registry unavailable; absence is not established.") from exc
    if len(body) > 10_000_000:
        raise ReleaseError("Registry response is oversized.")
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise ReleaseError("Registry returned invalid JSON.") from exc
    if not isinstance(value, dict) or value.get("name") != PACKAGE:
        raise ReleaseError("Registry package identity differs.")
    return value


def preview_version(version: str) -> tuple[int, ...]:
    match = PREVIEW.fullmatch(version)
    if not match:
        raise ReleaseError("Only an owner-versioned rc preview may publish to next.")
    return tuple(int(n) for n in match.groups())


def validate_metadata(package: dict, lock: dict, changelog: str, tag: str) -> str:
    if not VERSION.fullmatch(tag):
        raise ReleaseError("Invalid release tag.")
    version = tag[1:]
    preview_version(version)
    if package.get("name") != PACKAGE or package.get("version") != version:
        raise ReleaseError("Public package name/version differs from the release tag.")
    if package.get("private") is not False:
        raise ReleaseError("The public package still requires owner release preparation.")
    root = lock.get("packages", {}).get("", {})
    if (lock.get("name"), lock.get("version"), root.get("name"), root.get("version")) != (
        PACKAGE, version, PACKAGE, version
    ):
        raise ReleaseError("Public lock identity differs.")
    if f"## {version}\n" not in changelog:
        raise ReleaseError("The SDK changelog lacks this exact preview version.")
    if package.get("license") != "AGPL-3.0-only" or package.get("dependencies"):
        raise ReleaseError("Public alpha license/dependency contract differs.")
    if package.get("publishConfig") != {"access": "public", "registry": "https://registry.npmjs.org/", "provenance": True}:
        raise ReleaseError("Public registry/access configuration differs.")
    return version


def validate_registry(value: dict | None, version: str, *, require_existing: bool = True):
    proposed = preview_version(version)
    if value is None:
        if require_existing:
            raise ReleaseError("Owner bootstrap is required before CI trusted publishing.")
        return
    versions = value.get("versions")
    if not isinstance(versions, dict) or not versions:
        raise ReleaseError("Registry versions are missing.")
    if version in versions:
        raise ReleaseError("This immutable npm version already exists; reconcile its receipt.")
    # Keep the selected npm account separate from the GitHub reviewer.
    if "elysra" not in {u.get("name") for u in value.get("maintainers", []) if isinstance(u, dict)}:
        raise ReleaseError("The expected npm account does not own this package.")
    for published in versions:
        if PREVIEW.fullmatch(published) and preview_version(published) >= proposed:
            raise ReleaseError("Preview version is not increasing.")
        stable = re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", published)
        if stable and tuple(map(int, stable.groups())) >= proposed[:3]:
            raise ReleaseError("A stable release already supersedes this preview.")
    next_version = value.get("dist-tags", {}).get("next")
    if next_version is not None and next_version not in versions:
        raise ReleaseError("Registry next tag references an unknown version.")


def validate_environment(value: dict, policies: list[dict]) -> int:
    if value.get("name") != ENVIRONMENT or type(value.get("id")) is not int:
        raise ReleaseError("The configured approval environment is absent or differs.")
    rules = [r for r in value.get("protection_rules", []) if r.get("type") == "required_reviewers"]
    if len(rules) != 1:
        raise ReleaseError("A required maintainer reviewer is missing.")
    reviewers = rules[0].get("reviewers", [])
    if len(reviewers) != 1 or reviewers[0].get("type") != "User" or (
        reviewers[0].get("reviewer", {}).get("login"), reviewers[0].get("reviewer", {}).get("id")
    ) != (OWNER, OWNER_ID):
        raise ReleaseError("The sole required reviewer must be the verified maintainer.")
    # The owner initiates releases and is also the sole reviewer.
    if rules[0].get("prevent_self_review") is not False:
        raise ReleaseError("The sole owner reviewer cannot approve an owner-triggered release.")
    if value.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
        raise ReleaseError("Explicit release-tag deployment policy is required.")
    if len(policies) != 1 or policies[0].get("type") != "tag" or policies[0].get("name") != "v*-rc.*":
        raise ReleaseError("The environment must permit only preview release tags.")
    return value["id"]


def environment(api=gh) -> int:
    value = api(f"repos/{REPO}/environments/{ENVIRONMENT}")
    pages = api(f"repos/{REPO}/environments/{ENVIRONMENT}/deployment-branch-policies?per_page=100", pages=True)
    policies = [p for page in pages for p in page.get("branch_policies", [])]
    return validate_environment(value, policies)


def validate_checks(pages: list[dict], commit: str):
    successful = set()
    for page in pages:
        for check in page.get("check_runs", []):
            if check.get("head_sha") != commit or check.get("app", {}).get("slug") != "github-actions":
                continue
            if check.get("name") in CHECKS:
                if check.get("status") != "completed" or check.get("conclusion") != "success":
                    raise ReleaseError("An exact-source required check has not succeeded.")
                successful.add(check["name"])
    if successful != CHECKS:
        raise ReleaseError("Exact-source required check evidence is incomplete.")


def validate_approval(history: list[dict], environment_id: int):
    matches = [r for r in history if any(e.get("id") == environment_id and e.get("name") == ENVIRONMENT
               for e in r.get("environments", []))]
    if not matches or any(r.get("state") != "approved" or (
        r.get("user", {}).get("login"), r.get("user", {}).get("id")
    ) != (OWNER, OWNER_ID) for r in matches):
        raise ReleaseError("No unambiguous approval from the verified maintainer exists for this run.")


def dependency_review(commit: str, api=gh):
    # Dependency review runs only on PR heads, never the main merge commit.
    pages = api(f"repos/{REPO}/commits/{commit}/pulls?per_page=100", pages=True)
    prs = [p for page in pages for p in page if p.get("merged_at")
           and p.get("merge_commit_sha") == commit and p.get("base", {}).get("ref") == "main"]
    if len(prs) != 1:
        raise ReleaseError("The release source must be a reviewed main merge commit.")
    head = prs[0].get("head", {}).get("sha", "")
    if not HEX.fullmatch(head):
        raise ReleaseError("The merged PR head identity is invalid.")
    checks = api(f"repos/{REPO}/commits/{head}/check-runs?filter=latest&per_page=100", pages=True)
    relevant = [c for page in checks for c in page.get("check_runs", [])
                if c.get("head_sha") == head and c.get("name") == "dependency-review"
                and c.get("app", {}).get("slug") == "github-actions"]
    if not relevant or any(c.get("status") != "completed" or c.get("conclusion") != "success" for c in relevant):
        raise ReleaseError("The merged PR dependency review has not succeeded.")


def context(env=os.environ) -> tuple[str, str, int, int]:
    tag, commit = env.get("GITHUB_REF_NAME", ""), env.get("GITHUB_SHA", "")
    if env.get("GITHUB_REPOSITORY") != REPO or env.get("GITHUB_REF_TYPE") != "tag" or not HEX.fullmatch(commit):
        raise ReleaseError("Only the exact repository release tag can enter publication.")
    if env.get("GITHUB_EVENT_NAME") not in {"release", "workflow_dispatch"}:
        raise ReleaseError("Unsupported publication event.")
    preview_version(tag[1:] if tag.startswith("v") else "")
    try:
        run_id, attempt = int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])
    except (KeyError, ValueError) as exc:
        raise ReleaseError("Invalid workflow run identity.") from exc
    if run_id <= 0 or attempt != 1:
        raise ReleaseError("Use a fresh tag-scoped dispatch for recovery; historical approvals cannot be reused.")
    return tag, commit, run_id, attempt


def exact_source(tag: str, commit: str, api=gh):
    # Annotated/main ancestry/event checks are shared with the existing pipeline.
    result = subprocess.run(["python3", "scripts/check_release_tag.py"], check=False)
    if result.returncode:
        raise ReleaseError("Annotated main-branch source validation failed.")
    release = api(f"repos/{REPO}/releases/tags/{tag}")
    if release.get("tag_name") != tag or release.get("draft") is not False or release.get("prerelease") is not True:
        raise ReleaseError("A published GitHub preview release is required.")
    pages = api(f"repos/{REPO}/commits/{commit}/check-runs?filter=latest&per_page=100", pages=True)
    validate_checks(pages, commit)
    dependency_review(commit, api)


def validate_receipt(receipt: dict, package_info: dict, env=os.environ):
    tag, commit, run_id, attempt = context(env)
    if set(receipt) != RECEIPT_FIELDS or receipt.get("schema_version") != 1:
        raise ReleaseError("Receipt shape differs.")
    expected = {"name": PACKAGE, "tag": tag, "version": tag[1:], "source_commit": commit,
                "run_id": run_id, "run_attempt": attempt}
    if any(receipt.get(k) != v for k, v in expected.items()):
        raise ReleaseError("Receipt source/run identity differs.")
    for key in ("filename", "sha256", "integrity", "files"):
        if receipt.get(key) != package_info.get(key):
            raise ReleaseError("The reviewed package bytes or contents differ.")
    if type(receipt.get("environment_id")) is not int or receipt["environment_id"] <= 0:
        raise ReleaseError("Invalid approval environment identity.")
    for key in ("build_lock_sha256", "public_manifest_sha256", "public_lock_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", receipt.get(key, "")):
            raise ReleaseError("Invalid source digest.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "receipt", "approved", "verify-published"))
    parser.add_argument("--tarball", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    try:
        tag, commit, run_id, attempt = context()
        manifest = ROOT / "sdk/npm/package.json"
        public_lock = ROOT / "sdk/npm/package-lock.json"
        build_lock = ROOT / "sdk/typescript/package-lock.json"
        version = validate_metadata(read_json(manifest), read_json(public_lock),
                                    (ROOT / "sdk/npm/CHANGELOG.md").read_text(encoding="utf-8"), tag)
        if args.mode in {"preflight", "receipt", "approved"}:
            exact_source(tag, commit)
            environment_id = environment()
            validate_registry(registry(), version)
        if args.mode == "preflight":
            print("Owner-versioned preview, exact source checks and approval environment verified.")
            return 0
        if not args.tarball or not args.receipt:
            raise ReleaseError("A tarball and receipt path are required.")
        from package_npm import verify_tarball
        info = verify_tarball(args.tarball)
        if args.mode == "receipt":
            receipt = {
                "schema_version": 1, "name": PACKAGE, "version": version, "tag": tag,
                "source_commit": commit, "run_id": run_id, "run_attempt": attempt,
                "environment_id": environment_id,
                **{key: info[key] for key in ("filename", "sha256", "integrity", "files")},
                "build_lock_sha256": digest(build_lock), "public_manifest_sha256": digest(manifest),
                "public_lock_sha256": digest(public_lock),
            }
            with args.receipt.open("x", encoding="utf-8", newline="\n") as out:
                out.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        else:
            receipt = read_json(args.receipt)
            validate_receipt(receipt, info)
            if any(receipt[key] != digest(path) for key, path in (
                ("build_lock_sha256", build_lock), ("public_manifest_sha256", manifest),
                ("public_lock_sha256", public_lock)
            )):
                raise ReleaseError("Reviewed package/build source metadata differs.")
            if args.mode == "approved":
                if environment_id != receipt["environment_id"]:
                    raise ReleaseError("The approval environment was replaced.")
                validate_approval(gh(f"repos/{REPO}/actions/runs/{run_id}/approvals"), environment_id)
            else:
                value = registry()
                published = (value or {}).get("versions", {}).get(version, {})
                distribution = published.get("dist", {})
                if distribution.get("integrity") != receipt["integrity"] or not distribution.get("attestations"):
                    raise ReleaseError("Published integrity/provenance differs or is absent.")
                if (value or {}).get("dist-tags", {}).get("next") != version:
                    raise ReleaseError("Published next channel differs.")
        print("Exact npm preview receipt verified.")
        return 0
    except (ReleaseError, ValueError, OSError, subprocess.SubprocessError) as exc:
        # Package inspection errors are generic; never reflect API bodies or credentials.
        print(f"Npm preview stopped: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
