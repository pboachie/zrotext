#!/usr/bin/env python3
"""Verify a published server image against a receipt and annotated source tag."""

import argparse
import json
import os
import subprocess
import sys

from write_image_receipt import IMAGE, image_receipt
from verify_published_sbom import SbomError, published_sbom, spdx_predicate


REPOSITORY = "pboachie/zrotext"
WORKFLOW = "pboachie/zrotext/.github/workflows/release-image.yml"
SOURCE = "https://github.com/pboachie/zrotext"
MAX_RECEIPT_BYTES = 16 * 1024


class VerificationError(Exception):
    pass


def result_output(result: subprocess.CompletedProcess[str], stage: str) -> str:
    if result.returncode:
        raise VerificationError(f"{stage} failed (exit {result.returncode})")
    return result.stdout.strip()


def git_output(args: list[str], stage: str) -> str:
    try:
        result = subprocess.run(["git", *args], capture_output=True, text=True,
                                timeout=180, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(f"{stage} could not finish") from exc
    return result_output(result, stage)


def gh_output(args: list[str], stage: str) -> str:
    try:
        result = subprocess.run(["gh", *args], capture_output=True, text=True,
                                encoding="utf-8",
                                timeout=180, check=False, shell=False)
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(f"{stage} could not finish") from exc
    return result_output(result, stage)


def docker_output(args: list[str], stage: str) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                timeout=180, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(f"{stage} could not finish") from exc
    return result_output(result, stage)


def checked_receipt(raw: bytes, expected_tag: str) -> dict[str, object]:
    if not raw or len(raw) > MAX_RECEIPT_BYTES:
        raise VerificationError("image receipt is empty or exceeds the size limit")
    try:
        receipt = json.loads(raw.decode("utf-8"))
        if not isinstance(receipt, dict) or type(receipt.get("schema_version")) is not int \
                or receipt["schema_version"] != 1:
            raise ValueError("unknown receipt schema")
        run_id = receipt["workflow_run_id"]
        attempt = receipt["workflow_run_attempt"]
        if type(run_id) is not int or type(attempt) is not int:
            raise ValueError("workflow identity is invalid")
        expected = image_receipt(expected_tag, receipt["source_commit"],
                                 receipt["image_digest"], run_id, attempt)
    except (UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise VerificationError("image receipt is invalid") from exc
    if receipt != expected:
        raise VerificationError("image receipt fields do not match the selected release")
    return receipt


def verify_tag(tag: str, commit: str) -> None:
    ref = f"refs/tags/{tag}"
    if git_output(["cat-file", "-t", ref], "annotated tag lookup") != "tag":
        raise VerificationError("release tag is not annotated")
    if git_output(["rev-parse", f"{ref}^{{commit}}"], "tag commit lookup") != commit:
        raise VerificationError("receipt commit differs from the annotated tag")
    git_output(["merge-base", "--is-ancestor", commit, "origin/main"],
               "main ancestry check")


def verify_attestation(receipt: dict[str, object]) -> None:
    image_ref = str(receipt["image_ref"])
    output = gh_output([
        "attestation", "verify", f"oci://{image_ref}",
        "--repo", REPOSITORY, "--signer-workflow", WORKFLOW,
        "--source-ref", f"refs/tags/{receipt['source_tag']}",
        "--source-digest", str(receipt["source_commit"]), "--format", "json",
    ], "image attestation verification")
    try:
        verified = json.loads(output)
        if not isinstance(verified, list) or not any(
            subject.get("name") == IMAGE
            and subject.get("digest", {}).get("sha256") ==
                str(receipt["image_digest"])[len("sha256:"):]
            for item in verified
            for subject in item["verificationResult"]["statement"]["subject"]
        ):
            raise ValueError("subject mismatch")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise VerificationError("verified attestation does not name the selected image digest") from exc


def verify_sbom_attestation(receipt: dict[str, object]) -> None:
    image_ref = str(receipt["image_ref"])
    try:
        document = published_sbom(image_ref)
        predicate_type = spdx_predicate(document)
    except SbomError as exc:
        raise VerificationError("published image has no verified SPDX SBOM") from exc
    output = gh_output([
        "attestation", "verify", f"oci://{image_ref}",
        "--repo", REPOSITORY, "--signer-workflow", WORKFLOW,
        "--source-ref", f"refs/tags/{receipt['source_tag']}",
        "--source-digest", str(receipt["source_commit"]),
        "--predicate-type", predicate_type, "--format", "json",
    ], "image SBOM attestation verification")
    try:
        verified = json.loads(output)
        if not isinstance(verified, list) or not any(
            statement.get("predicateType") == predicate_type
            and statement.get("predicate") == document
            and any(subject.get("name") == IMAGE
                    and subject.get("digest", {}).get("sha256") ==
                        str(receipt["image_digest"])[len("sha256:"):]
                    for subject in statement["subject"])
            for item in verified
            for statement in [item["verificationResult"]["statement"]]
        ):
            raise ValueError("SBOM subject or predicate mismatch")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise VerificationError("verified SBOM differs from the published image digest") from exc


def ensure_local_docker() -> None:
    override = os.environ.get("DOCKER_HOST", "")
    if override and not override.startswith(("npipe://", "unix://")):
        raise VerificationError("image verification requires a local Docker daemon")
    try:
        endpoint = json.loads(docker_output(["context", "inspect", "--format",
                                             "{{json .Endpoints.docker.Host}}"],
                                            "Docker context check"))
    except (ValueError, TypeError) as exc:
        raise VerificationError("Docker context endpoint is invalid") from exc
    if not isinstance(endpoint, str) or not endpoint.startswith(("npipe://", "unix://")):
        raise VerificationError("image verification requires a local Docker context")


def verify_image(receipt: dict[str, object]) -> None:
    image_ref = str(receipt["image_ref"])
    ensure_local_docker()
    docker_output(["pull", image_ref], "immutable image pull")
    try:
        digests = json.loads(docker_output(["image", "inspect", image_ref,
                                            "--format", "{{json .RepoDigests}}"],
                                           "pulled image digest lookup"))
        labels = json.loads(docker_output(["image", "inspect", image_ref,
                                           "--format", "{{json .Config.Labels}}"],
                                          "pulled image label lookup"))
    except (ValueError, TypeError) as exc:
        raise VerificationError("pulled image metadata is invalid") from exc
    if not isinstance(digests, list) or image_ref not in digests:
        raise VerificationError("pulled image does not retain the receipt digest")
    if not isinstance(labels, dict) or labels.get("org.opencontainers.image.source") != SOURCE \
            or labels.get("org.opencontainers.image.revision") != receipt["source_commit"] \
            or labels.get("org.opencontainers.image.version") != receipt["source_tag"] \
            or labels.get("org.opencontainers.image.licenses") != "AGPL-3.0-only":
        raise VerificationError("pulled image labels differ from the source release")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True,
                        help="independently selected annotated source tag")
    args = parser.parse_args()
    receipt = checked_receipt(sys.stdin.buffer.read(MAX_RECEIPT_BYTES + 1), args.tag)
    verify_tag(args.tag, str(receipt["source_commit"]))
    verify_attestation(receipt)
    verify_sbom_attestation(receipt)
    verify_image(receipt)
    print(f"verified server image {receipt['image_ref']} from {args.tag} "
          f"at {receipt['source_commit']}")


if __name__ == "__main__":
    try:
        main()
    except VerificationError as exc:
        parser_message = f"release image verification failed: {exc}"
        raise SystemExit(parser_message)
