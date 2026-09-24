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


def validate_image_args(image_ref, source_commit, source_tag):
    if image_ref is None:
        if source_commit is not None or source_tag is not None:
            raise DrillError("source identity requires --image-ref")
        return
    if not IMAGE_REF.fullmatch(image_ref):
        raise DrillError("release image must be an allowed digest reference")
    if not source_commit or not COMMIT.fullmatch(source_commit):
        raise DrillError("release image needs a full source commit")
    if not source_tag or not TAG.fullmatch(source_tag):
        raise DrillError("release image needs a valid source tag")


def inspect_release_image(image_ref, source_commit, source_tag):
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
    )):
        raise DrillError("release image source labels differ from selected release")
    image_id = run(["docker", "image", "inspect", STAGED_IMAGE, "--format",
                    "{{.Id}}"], "release image ID").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise DrillError("release image ID is invalid")
    return image_id


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-ref", help="immutable released image digest")
    parser.add_argument("--source-commit", help="expected full source commit")
    parser.add_argument("--source-tag", help="expected version tag")
    args = parser.parse_args()
    validate_image_args(args.image_ref, args.source_commit, args.source_tag)
    # Compose gives shell variables precedence over --env-file and imports
    # bare environment keys from the shell. Do not pass live account, SMTP,
    # or MFA settings into this disposable stack.
    for name in ("POSTGRES_PASSWORD", "DATABASE_URL", "APP_PORT", "SITE_ID",
                 "INSTANCE_ID", "DEPLOYMENT_EPOCH", "DISPATCH_ENABLED",
                 "SYNTHETIC_ALPHA_ENABLED", "M0_TEST_TOKEN", "COMPOSE_PROFILES",
                 "COMPOSE_ENV_FILES", "COMPOSE_PROJECT_NAME", "COMPOSE_FILE",
                 "AUTH_ORIGIN", "AUTH_TOKEN_PEPPER_B64", "ENROLLMENT_TOKEN_PEPPER_B64",
                 "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD",
                 "SMTP_FROM", "SMTP_FROM_NAME", "SMTP_REPLY_TO",
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
                                             args.source_tag)
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
        run([*compose, "exec", "-T", "app", "sh", "-ec",
             'test "$DISPATCH_ENABLED" = false'],
            "dispatch-disabled check")
        run([*compose, "exec", "-T", "app", "sh", "-ec",
             'test -z "$AUTH_TOKEN_PEPPER_B64" && '
             'test -z "$ENROLLMENT_TOKEN_PEPPER_B64" && '
             'test -z "$SMTP_PASSWORD" && '
             'test -z "$MFA_ENCRYPTION_KEY_B64"'],
            "disposable credential isolation")
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
