"""Disposable PostgreSQL TLS proof for the shared connector and migrator."""

from datetime import datetime, timedelta, timezone
import base64
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


ROOT = Path(__file__).resolve().parents[2]


def certificate(directory: Path, label: str, ca_key=None, ca_cert=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject if ca_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca_cert is None, path_length=None), critical=True)
    )
    if ca_cert is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    cert = builder.sign(private_key=ca_key or key, algorithm=hashes.SHA256())
    (directory / f"{label}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / f"{label}.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return key, cert


def command(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, text=True, **kwargs)


def cargo(env, should_pass, *args):
    result = subprocess.run(
        ["cargo", *args], cwd=ROOT, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180,
    )
    if (result.returncode == 0) != should_pass:
        raise AssertionError(f"unexpected cargo result for {args}:\n{result.stdout}")


def main():
    root = Path(tempfile.gettempdir()).resolve()
    directory = Path(tempfile.mkdtemp(prefix="zrotext-postgres-tls-", dir=root)).resolve()
    if directory.parent != root:
        raise RuntimeError("unsafe temporary directory")
    container = f"zrotext-tls-{secrets.token_hex(6)}"
    try:
        ca_key, ca_cert = certificate(directory, "ca")
        certificate(directory, "server", ca_key, ca_cert)
        certificate(directory, "wrong-ca")
        command([
            "docker", "run", "--detach", "--rm", "--name", container,
            "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p", "127.0.0.1::5432",
            "-v", f"{directory}:/certs:ro", "--entrypoint", "bash",
            "postgres:18.6-bookworm", "-ec",
            "cp /certs/server.pem /tmp/zrotext-server.pem; "
            "cp /certs/server.key /tmp/zrotext-server.key; "
            "chown postgres:postgres /tmp/zrotext-server.*; "
            "chmod 600 /tmp/zrotext-server.key; "
            "exec docker-entrypoint.sh postgres -c ssl=on "
            "-c ssl_cert_file=/tmp/zrotext-server.pem "
            "-c ssl_key_file=/tmp/zrotext-server.key",
        ], stdout=subprocess.DEVNULL)
        # The image's first-start init server listens only on the Unix socket,
        # then restarts. Probe TCP so readiness means the final server is up.
        for _ in range(60):
            ready = subprocess.run(
                ["docker", "exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("TLS PostgreSQL container did not become ready")
        binding = command(["docker", "port", container, "5432/tcp"], capture_output=True).stdout.strip()
        port = binding.splitlines()[0].rsplit(":", 1)[1]
        trusted = os.environ.copy()
        trusted["DATABASE_TLS_CA_PEM_B64"] = base64.b64encode((directory / "ca.pem").read_bytes()).decode("ascii")
        trusted["DATABASE_URL"] = f"postgresql://postgres@localhost:{port}/postgres?sslmode=require"
        trusted["ZT_POSTGRES_TLS_TEST_DATABASE_URL"] = trusted["DATABASE_URL"]
        cargo(trusted, True, "run", "--locked", "-p", "zrotext-migrator")
        cargo(trusted, True, "test", "--locked", "-p", "zrotext-postgres-connection", "verified_tls_connection_is_encrypted")
        cargo(trusted, True, "test", "--locked", "-p", "zrotext-server", "tls_runtime_connection_is_encrypted")
        wrong_host = trusted.copy()
        wrong_host["DATABASE_URL"] = f"postgresql://postgres@127.0.0.1:{port}/postgres?sslmode=require"
        cargo(wrong_host, False, "run", "--locked", "-p", "zrotext-migrator")
        wrong_ca = trusted.copy()
        wrong_ca["DATABASE_TLS_CA_PEM_B64"] = base64.b64encode((directory / "wrong-ca.pem").read_bytes()).decode("ascii")
        cargo(wrong_ca, False, "run", "--locked", "-p", "zrotext-migrator")
        print("PostgreSQL TLS: migration and encrypted query passed; wrong host and CA rejected")
    finally:
        subprocess.run(["docker", "rm", "--force", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if directory.parent != root or not directory.name.startswith("zrotext-postgres-tls-"):
            raise RuntimeError("refusing unsafe temporary directory cleanup")
        shutil.rmtree(directory)


if __name__ == "__main__":
    main()
