#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify a fresh Compose install and restore in disposable local projects."""

import json
import os
from pathlib import Path
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


def available_loopback_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(command, stage, timeout=180):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
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
    started = False
    failure = None
    cleanup_failure = None
    migrations = None
    try:
        started = True
        run([*compose, "up", "-d", "--build"], "fresh Compose startup",
            timeout=3600)
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
        run([sys.executable, str(Path(__file__).with_name("restore_rehearsal.py")),
             "--source-project", project, "--env-file", str(env_file)],
            "logical restore rehearsal", timeout=600)
    except (DrillError, OSError) as exc:
        failure = exc
    finally:
        if started:
            try:
                run([*compose, "down", "--volumes", "--remove-orphans",
                     "--rmi", "local"], "fresh project cleanup")
            except DrillError as exc:
                cleanup_failure = exc
        if cleanup_failure is None:
            shutil.rmtree(directory)
    if cleanup_failure:
        raise DrillError(f"{cleanup_failure}; inspect project {project} and {directory}")
    if failure:
        raise failure
    print(f"fresh install smoke passed: {migrations} migrations, "
          "health and readiness, dispatch disabled, logical restore; "
          "disposable projects removed")


if __name__ == "__main__":
    try:
        main()
    except (DrillError, FileNotFoundError, KeyboardInterrupt) as error:
        print(f"fresh install smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
