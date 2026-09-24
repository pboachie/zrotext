#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise HTTPS owner sign-in and WSS through a disposable local edge."""

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
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fresh_install_smoke import available_loopback_port, ensure_local_docker
from restore_rehearsal import COMPOSE, DrillError, protected_tempdir, target_is_new

TEST_EMAIL = "edge-smoke@example.invalid"


def run(command, stage, env, timeout=180, input_data=None):
    try:
        result = subprocess.run(command, input=input_data, capture_output=True, text=True,
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
             "DATABASE_TLS_CA_PEM_B64", "DATABASE_ALLOW_PLAINTEXT",
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
        data=json.dumps({"email": TEST_EMAIL,
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


def seed_verified_owner(compose, env):
    """Insert only disposable account rows to exercise successful HTTPS login."""
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError as exc:
        raise DrillError("edge smoke needs Python cryptography with Argon2id support") from exc
    synthetic_passphrase = secrets.token_urlsafe(32)
    password_hash = Argon2id(
        salt=secrets.token_bytes(16), length=32, iterations=3,
        lanes=1, memory_cost=64 * 1024,
    ).derive_phc_encoded(synthetic_passphrase.encode())
    account_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    sql = (
        "BEGIN;\n"
        f"INSERT INTO accounts(id) VALUES ('{account_id}');\n"
        f"INSERT INTO users(id,email,password_hash,email_verified_at) VALUES "
        f"('{user_id}','{TEST_EMAIL}','{password_hash}',now());\n"
        f"INSERT INTO memberships(account_id,user_id,role) VALUES "
        f"('{account_id}','{user_id}','owner');\n"
        "COMMIT;\n"
    )
    run([*compose, "exec", "-T", "db", "sh", "-ec",
         'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -X -q -v ON_ERROR_STOP=1 '
         '-U zrotext -d zrotext -f -'], "synthetic verified owner seed", env,
        input_data=sql)
    return synthetic_passphrase


def verify_owner_sign_in(port, context, synthetic_passphrase):
    origin = f"https://localhost:{port}"
    request = Request(
        f"{origin}/v1/auth/login",
        data=json.dumps({"email": TEST_EMAIL, "password": synthetic_passphrase}).encode(),
        headers={"Content-Type": "application/json", "Origin": origin},
        method="POST",
    )
    with urlopen(request, context=context, timeout=15) as response:
        if response.status != 204:
            raise DrillError("HTTPS owner sign-in did not return 204")
        set_cookies = response.headers.get_all("Set-Cookie", [])
    session = next((item for item in set_cookies
                    if item.startswith("__Host-zrotext_session=")), None)
    csrf = next((item for item in set_cookies
                 if item.startswith("__Host-zrotext_csrf=")), None)
    if not session or not csrf:
        raise DrillError("HTTPS owner sign-in omitted session cookies")
    attributes = {part.strip().lower() for part in session.split(";")[1:]}
    if not {"path=/", "secure", "httponly"}.issubset(attributes) \
            or any(part.startswith("domain=") for part in attributes):
        raise DrillError("HTTPS session cookie is not securely scoped")
    csrf_token = csrf.split(";", 1)[0].split("=", 1)[1]
    cookies = "; ".join(item.split(";", 1)[0] for item in (session, csrf))
    session_request = Request(
        f"{origin}/v1/auth/session",
        headers={"Cookie": cookies, "x-zrotext-csrf": csrf_token},
    )
    with urlopen(session_request, context=context, timeout=10) as response:
        if response.status != 200:
            raise DrillError("HTTPS owner session was not readable")
        owner = json.load(response)
    if not all(owner.get(name) for name in ("account_id", "user_id", "session_id")):
        raise DrillError("HTTPS owner session identity was incomplete")


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
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        wait_for_tls(https_port, context)
        expect_login_status(https_port, context,
                            f"https://localhost:{https_port}", 401)
        expect_login_status(https_port, context, "https://wrong.invalid", 403)
        synthetic_passphrase = seed_verified_owner(compose, env)
        verify_owner_sign_in(https_port, context, synthetic_passphrase)
        verify_websocket_upgrade(https_port, context)
        print("edge HTTPS health, owner sign-in/session, Origin guard, and WSS upgrade passed")
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
