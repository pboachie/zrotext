#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify a fresh Compose install and restore in disposable local projects.

With --image-ref, exercise the exact immutable image selected for release.
"""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

from restore_rehearsal import (
    COMPOSE, DrillError, protected_tempdir, summary, target_is_new,
    verify_ledger,
)


IMAGE_REF = re.compile(
    r"(?:ghcr\.io/pboachie/zrotext|127\.0\.0\.1:[1-9][0-9]{0,4}/zrotext)"
    r"@sha256:[0-9a-f]{64}\Z"
)
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
                 r"(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?\Z")
SOURCE = "https://github.com/pboachie/zrotext"
STAGED_IMAGE = "zrotext-release-smoke:local"


def validate_image_args(image_ref, source_commit, source_tag,
                        web_sha=None, schema_sha=None, migration_last=None):
    if image_ref is None:
        if any(value is not None for value in (
                source_commit, source_tag, web_sha, schema_sha, migration_last)):
            raise DrillError("source identity requires --image-ref")
        return
    if not IMAGE_REF.fullmatch(image_ref):
        raise DrillError("release image must be an allowed digest reference")
    if not source_commit or not COMMIT.fullmatch(source_commit):
        raise DrillError("release image needs a full source commit")
    if not source_tag or not TAG.fullmatch(source_tag):
        raise DrillError("release image needs a valid source tag")
    if not web_sha or not re.fullmatch(r"[0-9a-f]{64}", web_sha) \
            or not schema_sha or not re.fullmatch(r"[0-9a-f]{64}", schema_sha) \
            or type(migration_last) is not int or migration_last < 1:
        raise DrillError("release image needs web, protocol and migration source metadata")


def inspect_release_image(image_ref, source_commit, source_tag,
                          web_sha, schema_sha, migration_last):
    raw = run(["docker", "image", "inspect", STAGED_IMAGE, "--format",
               "{{json .RepoDigests}}"], "staged image digests")
    try:
        repo_digests = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise DrillError("staged image digests are invalid") from exc
    if not isinstance(repo_digests, list) or image_ref not in repo_digests:
        raise DrillError("staged image does not match selected digest")
    raw = run(["docker", "image", "inspect", STAGED_IMAGE, "--format",
               "{{json .Config.Labels}}"], "release image labels")
    try:
        labels = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise DrillError("release image labels are invalid") from exc
    if not isinstance(labels, dict) or any((
        labels.get("org.opencontainers.image.source") != SOURCE,
        labels.get("org.opencontainers.image.revision") != source_commit,
        labels.get("org.opencontainers.image.version") != source_tag,
        labels.get("org.opencontainers.image.licenses") != "AGPL-3.0-only",
        labels.get("org.zrotext.web.static-sha256") != web_sha,
        labels.get("org.zrotext.device-stream.schema-sha256") != schema_sha,
        labels.get("org.zrotext.migration.last") != str(migration_last),
    )):
        raise DrillError("release image source labels differ from selected release")
    image_id = run(["docker", "image", "inspect", STAGED_IMAGE, "--format",
                    "{{.Id}}"], "release image ID").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise DrillError("release image ID is invalid")
    return image_id


def verify_release_licenses():
    license_text = run(["docker", "run", "--rm", "--entrypoint", "cat", STAGED_IMAGE,
                        "/usr/share/doc/zrotext/LICENSE"], "bundled AGPL license")
    expected = (Path(__file__).resolve().parents[2] / "LICENSE").read_text(encoding="utf-8")
    if license_text != expected:
        raise DrillError("bundled AGPL license differs from selected source")
    notices = run(["docker", "run", "--rm", "--entrypoint", "cat", STAGED_IMAGE,
                   "/usr/share/doc/zrotext/THIRD_PARTY_NOTICES"],
                  "bundled third-party notices")
    if len(notices) < 1000 or not all(marker in notices for marker in (
            "License:", "axum ", "tokio-postgres ")):
        raise DrillError("bundled third-party notices are incomplete")


def verify_running_image(compose, image_id):
    for service in ("migrate", "app"):
        container = run([*compose, "ps", "--no-trunc", "-aq", service],
                        f"{service} container lookup").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container):
            raise DrillError(f"{service} container is missing")
        actual = run(["docker", "inspect", "--format", "{{.Image}}", container],
                     f"{service} image lookup").strip()
        if actual != image_id:
            raise DrillError(f"{service} did not run the selected release image")


def available_loopback_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(command, stage, timeout=180, input_data=None):
    try:
        result = subprocess.run(command, input=input_data, capture_output=True, text=True,
                                errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DrillError(f"{stage} could not finish") from exc
    if result.returncode:
        # Compose can echo environment and connection details on failure.
        raise DrillError(f"{stage} failed (exit {result.returncode})")
    return result.stdout


def ensure_local_docker():
    host_override = os.environ.get("DOCKER_HOST", "")
    if host_override and not host_override.startswith(("npipe://", "unix://")):
        raise DrillError("fresh smoke requires a local Docker daemon")
    raw = run(["docker", "context", "inspect", "--format",
               "{{json .Endpoints.docker.Host}}"], "Docker context check")
    try:
        context_host = json.loads(raw.strip())
    except (json.JSONDecodeError, TypeError) as exc:
        raise DrillError("Docker context endpoint is invalid") from exc
    if not isinstance(context_host, str) or not context_host.startswith(
            ("npipe://", "unix://")):
        raise DrillError("fresh smoke requires a local Docker context")


def wait_for_endpoint(port, path, expected):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as response:
                if response.status == 200 and json.load(response) == {"status": expected}:
                    return
        except (OSError, URLError, ValueError):
            pass
        time.sleep(1)
    raise DrillError(f"{path} did not report {expected}")


def verify_version_endpoint(port, source_commit, source_tag,
                            web_sha, schema_sha, migration_last):
    try:
        with urlopen(f"http://127.0.0.1:{port}/about/version", timeout=3) as response:
            actual = json.load(response) if response.status == 200 else None
    except (OSError, URLError, ValueError) as exc:
        raise DrillError("release version endpoint unavailable") from exc
    expected = {
        "bundle_version": source_tag,
        "source_commit": source_commit,
        "web_static_sha256": web_sha,
        "device_stream_protocol": "v1",
        "device_stream_schema_sha256": schema_sha,
        "migration_last": str(migration_last),
    }
    if actual != expected:
        raise DrillError("release version endpoint differs from selected source")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-ref", help="immutable released image digest")
    parser.add_argument("--source-commit", help="expected full source commit")
    parser.add_argument("--source-tag", help="expected version tag")
    parser.add_argument("--web-static-sha256", help="expected embedded web digest")
    parser.add_argument("--device-stream-schema-sha256", help="expected device protocol schema digest")
    parser.add_argument("--migration-last", type=int, help="expected last bundled migration")
    args = parser.parse_args()
    validate_image_args(args.image_ref, args.source_commit, args.source_tag,
                        args.web_static_sha256, args.device_stream_schema_sha256,
                        args.migration_last)
    # Compose gives shell variables precedence over --env-file and imports
    # bare environment keys from the shell. Do not pass live account, SMTP,
    # or MFA settings into this disposable stack.
    for name in ("POSTGRES_PASSWORD", "DATABASE_URL", "RUNTIME_DATABASE_PASSWORD", "APP_PORT", "SITE_ID",
                 "INSTANCE_ID", "DEPLOYMENT_EPOCH", "DISPATCH_ENABLED",
                 "SYNTHETIC_ALPHA_ENABLED", "M0_TEST_TOKEN", "COMPOSE_PROFILES",
                 "COMPOSE_ENV_FILES", "COMPOSE_PROJECT_NAME", "COMPOSE_FILE",
                 "AUTH_ORIGIN", "AUTH_TOKEN_PEPPER_B64", "ENROLLMENT_TOKEN_PEPPER_B64",
                 "SMTP_HOST", "SMTP_PORT", "SMTP_SECURE",
                 "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM",
                 "SMTP_FROM_NAME", "SMTP_REPLY_TO", "SMTP_USER", "SMTP_PASS",
                 "EMAIL_FROM", "EMAIL_FROM_NAME", "EMAIL_REPLY_TO",
                 "MFA_ENCRYPTION_KEY_B64", "MFA_ENROLLMENT_ENABLED",
                 "MFA_RECOVERY_ONLY"):
        os.environ.pop(name, None)
    ensure_local_docker()
    project = "zt-fresh-" + secrets.token_hex(8)
    target_is_new(project)
    directory = protected_tempdir()
    env_file = directory / ".env"
    secret = secrets.token_hex(24)
    port = available_loopback_port()
    try:
        # The restore drill requires --env-file, but Compose gives the process
        # environment precedence. Keep the random test password out of files.
        with open(env_file, "x", encoding="utf-8",
                  opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
            output.write("# Disposable smoke values are process-scoped.\n")
    except OSError:
        shutil.rmtree(directory)
        raise
    os.environ.update({
        "POSTGRES_PASSWORD": secret,
        "RUNTIME_DATABASE_PASSWORD": secrets.token_hex(32),
        "DATABASE_URL": f"postgres://zrotext:{secret}@db:5432/zrotext",
        "APP_PORT": str(port),
        "SITE_ID": "local-a", "INSTANCE_ID": "api-1", "DEPLOYMENT_EPOCH": "1",
        "DISPATCH_ENABLED": "false", "SYNTHETIC_ALPHA_ENABLED": "false",
        "M0_TEST_TOKEN": "",
    })
    compose = ["docker", "compose", "--project-name", project,
               "--env-file", str(env_file), "-f", str(COMPOSE)]
    image_id = None
    started = False
    failure = None
    cleanup_failure = None
    migrations = None
    try:
        if args.image_ref is not None:
            image_id = inspect_release_image(args.image_ref, args.source_commit,
                                             args.source_tag, args.web_static_sha256,
                                             args.device_stream_schema_sha256,
                                             args.migration_last)
            verify_release_licenses()
            override = directory / "release-image.yaml"
            override.write_text(json.dumps({"services": {
                "app": {"image": STAGED_IMAGE},
                "migrate": {"image": STAGED_IMAGE},
            }}), encoding="utf-8")
            compose.extend(("-f", str(override)))
        started = True
        up_options = ["--no-build", "--pull", "missing"] if image_id else ["--build"]
        run([*compose, "up", "-d", *up_options], "fresh Compose startup",
            timeout=3600)
        if image_id:
            verify_running_image(compose, image_id)
        wait_for_endpoint(port, "/healthz", "live")
        wait_for_endpoint(port, "/readyz", "ready")
        if image_id:
            verify_version_endpoint(port, args.source_commit, args.source_tag,
                                    args.web_static_sha256,
                                    args.device_stream_schema_sha256,
                                    args.migration_last)
        run([*compose, "exec", "-T", "app", "sh", "-ec",
             'test "$DISPATCH_ENABLED" = false'],
            "dispatch-disabled check")
        run([*compose, "exec", "-T", "app", "sh", "-ec",
             'test -z "$AUTH_TOKEN_PEPPER_B64" && '
             'test -z "$ENROLLMENT_TOKEN_PEPPER_B64" && '
             'test -z "$SMTP_PASSWORD" && '
             'test -z "$SMTP_PASS" && '
             'test -z "$MFA_ENCRYPTION_KEY_B64"'],
            "disposable credential isolation")
        role_check = Path(__file__).with_name("verify_runtime_role.sql")
        run([*compose, "run", "--rm", "--no-deps", "-T", "--entrypoint", "sh",
             "db-runtime", "-ec", 'PGPASSWORD="$RUNTIME_DATABASE_PASSWORD" '
             'PGUSER=zrotext_runtime exec psql -X -q -v ON_ERROR_STOP=1 -f -'],
            "runtime database privilege check",
            input_data=role_check.read_text(encoding="utf-8"))
        database = summary(project, env_file)
        migrations = verify_ledger(database["ledger"])
        if database["tenants"] or database["messages"]:
            raise DrillError("fresh database is not empty")
        run([*compose, "stop", "app"], "writer quiescence")
        fixture = Path(__file__).with_name("seed_restore_fixture.sql")
        run([*compose, "exec", "-T", "db", "sh", "-ec",
             'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -q '
             '-v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f -'],
            "synthetic restore fixture", input_data=fixture.read_text(encoding="utf-8"))
        run([sys.executable, str(Path(__file__).with_name("restore_rehearsal.py")),
             "--source-project", project, "--env-file", str(env_file),
             "--expect-synthetic-fixture"],
            "logical restore rehearsal", timeout=600)
    except (DrillError, OSError) as exc:
        failure = exc
    finally:
        if started:
            try:
                cleanup = [*compose, "down", "--volumes", "--remove-orphans"]
                if image_id is None:
                    cleanup.extend(("--rmi", "local"))
                run(cleanup, "fresh project cleanup")
            except DrillError as exc:
                cleanup_failure = exc
        if cleanup_failure is None:
            shutil.rmtree(directory)
    if cleanup_failure:
        raise DrillError(f"{cleanup_failure}; inspect project {project} and {directory}")
    if failure:
        raise failure
    kind = "immutable image" if image_id else "source build"
    print(f"fresh install smoke passed ({kind}): {migrations} migrations, "
          "health and readiness, dispatch disabled, seeded logical restore; "
          "disposable projects removed")


if __name__ == "__main__":
    try:
        main()
    except (DrillError, FileNotFoundError, KeyboardInterrupt) as error:
        print(f"fresh install smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
