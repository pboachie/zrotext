#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the optional HTTPS edge and WebSocket upgrade in a disposable stack."""

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fresh_install_smoke import available_loopback_port, ensure_local_docker
from restore_rehearsal import COMPOSE, DrillError, protected_tempdir, target_is_new


def run(command, stage, env, timeout=180):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                errors="replace", env=env, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DrillError(f"{stage} could not finish") from exc
    if result.returncode:
        # Compose diagnostics can include credentials from the process environment.
        raise DrillError(f"{stage} failed (exit {result.returncode})")
    return result.stdout


def disposable_env(http_port, https_port, app_port):
    env = os.environ.copy()
    prefixes = ("SMTP_", "STRIPE_", "AUTH_", "ENROLLMENT_", "MFA_", "EMAIL_",
                "EDGE_", "COMPOSE_", "INBOUND_", "DISPATCH_", "SYNTHETIC_", "M0_")
    exact = {"POSTGRES_PASSWORD", "RUNTIME_DATABASE_PASSWORD", "DATABASE_URL",
             "APP_PORT", "SITE_ID", "INSTANCE_ID", "DEPLOYMENT_EPOCH"}
    for key in list(env):
        if key.upper().startswith(prefixes) or key.upper() in exact:
            env.pop(key)
    database_password = secrets.token_hex(24)
    env.update({
        "POSTGRES_PASSWORD": database_password,
        "RUNTIME_DATABASE_PASSWORD": secrets.token_hex(32),
        "DATABASE_URL": f"postgres://zrotext:{database_password}@db:5432/zrotext",
        "APP_PORT": str(app_port),
        "EDGE_BIND": "127.0.0.1",
        "EDGE_DOMAIN": "localhost",
        "EDGE_HTTP_PORT": str(http_port),
        "EDGE_HTTPS_PORT": str(https_port),
        "AUTH_ORIGIN": f"https://localhost:{https_port}",
        "AUTH_TOKEN_PEPPER_B64": base64.b64encode(secrets.token_bytes(32)).decode(),
        "ENROLLMENT_TOKEN_PEPPER_B64": base64.b64encode(secrets.token_bytes(32)).decode(),
        "DISPATCH_ENABLED": "false",
        "SYNTHETIC_ALPHA_ENABLED": "false",
        "M0_TEST_TOKEN": "",
        "SITE_ID": "local-a",
        "INSTANCE_ID": "api-1",
        "DEPLOYMENT_EPOCH": "1",
    })
    return env


def wait_for_tls(port, context):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            for path, expected in (("/healthz", "live"), ("/readyz", "ready")):
                with urlopen(f"https://localhost:{port}{path}", context=context,
                             timeout=3) as response:
                    if response.status != 200 or json.load(response) != {"status": expected}:
                        break
            else:
                return
        except (OSError, URLError, ValueError):
            pass
        time.sleep(1)
    raise DrillError("HTTPS health and readiness routes did not become ready")


def expect_login_status(port, context, origin, expected):
    request = Request(
        f"https://localhost:{port}/v1/auth/login",
        data=json.dumps({"email": "edge-smoke@example.invalid",
                         "password": "never-a-real-account"}).encode(),
        headers={"Content-Type": "application/json", "Origin": origin},
        method="POST",
    )
    try:
        with urlopen(request, context=context, timeout=10) as response:
            status = response.status
    except HTTPError as error:
        status = error.code
        error.close()
    if status != expected:
        raise DrillError(f"HTTPS login route returned {status}, expected {expected}")


def verify_websocket_upgrade(port, context):
    nonce = base64.b64encode(secrets.token_bytes(16)).decode()
    request = (
        f"GET /v1/device-stream HTTP/1.1\r\n"
        f"Host: localhost:{port}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        f"Sec-WebSocket-Key: {nonce}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as secured:
            secured.settimeout(10)
            secured.sendall(request)
            response = b""
            while b"\r\n\r\n" not in response and len(response) < 8192:
                chunk = secured.recv(4096)
                if not chunk:
                    break
                response += chunk
    header = response.split(b"\r\n\r\n", 1)[0].decode("ascii", errors="replace")
    if not header.startswith("HTTP/1.1 101 "):
        raise DrillError("WSS upgrade did not return HTTP 101")
    accept = base64.b64encode(hashlib.sha1(
        (nonce + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
    ).digest()).decode("ascii")
    if f"sec-websocket-accept: {accept}".lower() not in header.lower():
        raise DrillError("WSS upgrade acceptance key is invalid")


def main():
    ensure_local_docker()
    project = "zt-edge-" + secrets.token_hex(8)
    target_is_new(project)
    directory = protected_tempdir()
    env_file = directory / ".env"
    ports = []
    while len(ports) < 3:
        port = available_loopback_port()
        if port not in ports:
            ports.append(port)
    http_port, https_port, app_port = ports
    env = disposable_env(http_port, https_port, app_port)
    compose = ["docker", "compose", "--project-name", project,
               "--profile", "edge", "--env-file", str(env_file),
               "-f", str(COMPOSE)]
    started = False
    failure = None
    cleanup_failure = None
    try:
        env_file.write_text("# Disposable values are process-scoped.\n", encoding="utf-8")
        started = True
        run([*compose, "up", "-d", "--build"], "edge Compose startup", env,
            timeout=3600)
        root_pem = run([*compose, "exec", "-T", "edge", "cat",
                        "/data/caddy/pki/authorities/local/root.crt"],
                       "local CA extraction", env)
        if "BEGIN CERTIFICATE" not in root_pem:
            raise DrillError("Caddy local CA was unavailable")
        cert_file = directory / "local-ca.pem"
        cert_file.write_text(root_pem, encoding="ascii")
        context = ssl.create_default_context(cafile=str(cert_file))
        wait_for_tls(https_port, context)
        expect_login_status(https_port, context,
                            f"https://localhost:{https_port}", 401)
        expect_login_status(https_port, context, "https://wrong.invalid", 403)
        verify_websocket_upgrade(https_port, context)
        print("edge HTTPS health, canonical-Origin login, and WSS upgrade passed")
    except Exception as exc:
        failure = exc
    finally:
        if started:
            try:
                run([*compose, "down", "--volumes", "--remove-orphans"],
                    "edge Compose cleanup", env, timeout=180)
            except Exception as exc:
                cleanup_failure = exc
        # Only the new, named temporary directory is removed.
        target = directory.resolve()
        if target.parent == Path(tempfile.gettempdir()).resolve() \
                and target.name.startswith("zrotext-restore-"):
            shutil.rmtree(target)
        else:
            cleanup_failure = DrillError("unexpected temporary directory path")
    if failure:
        raise failure
    if cleanup_failure:
        raise cleanup_failure


if __name__ == "__main__":
    main()
