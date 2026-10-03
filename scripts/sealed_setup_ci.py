#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Own disposable PostgreSQL/TLS fixtures for the explicit compiled setup consumer.

Existing isolated database mode never initializes/stops a cluster. No credentials,
ready records or TLS private material are printed or written as evidence.
"""
import argparse
import ctypes
import datetime
import ipaddress
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent.parent


def database_url(value):
    parsed = urlsplit(value)
    try:
        loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname).is_loopback
    except (ValueError, TypeError):
        loopback = False
    if (parsed.scheme not in {"postgres", "postgresql"} or not loopback
            or parsed.username not in {"fixture", "postgres"} or parsed.password is not None
            or not parsed.port or parsed.path != "/postgres" or parsed.query or parsed.fragment):
        raise ValueError("Explicit credential-free loopback fixture database required")
    return value


def tls_fixture():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owner.example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("owner.example.test")]), False)
            .sign(key, hashes.SHA256()))
    return {"key": key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode("ascii"),
            "cert": cert.public_bytes(serialization.Encoding.PEM).decode("ascii")}


def installed_postgres_directory(requested):
    # Ask Windows for its protected installed-programs directory; do not select
    # an executable from a caller-controlled path or inherited environment.
    buffer = ctypes.create_unicode_buffer(32768)
    result = ctypes.windll.shell32.SHGetFolderPathW(None, 0x26, None, 0, buffer)
    if result != 0:
        raise ValueError("Installed PostgreSQL directory unavailable")
    trusted = (Path(buffer.value) / "PostgreSQL" / "17" / "bin").resolve(strict=True)
    if requested.resolve(strict=True) != trusted:
        raise ValueError("Installed PostgreSQL directory required")
    return trusted


def system_tree_killer():
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise ValueError("System process cleanup tool unavailable")
    return tool(Path(buffer.value), "taskkill")


def tool(directory, name):
    directory = directory.resolve(strict=True)
    candidate = directory / (name + (".exe" if os.name == "nt" else ""))
    if candidate.is_symlink() or not candidate.is_file() or candidate.resolve().parent != directory:
        raise ValueError("Existing PostgreSQL tool required")
    return candidate


def confined(directory, parent):
    actual = directory.resolve(strict=True)
    root = parent.resolve(strict=True)
    if directory.is_symlink() or actual.parent != root:
        raise ValueError("Owned direct-child fixture directory required")
    return actual


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("localhost", 0))
        return listener.getsockname()[1]


def quiet(command, timeout=60):
    # PostgreSQL setup output contains no credentials; withhold even filesystem
    # paths on error. The bound is time, with diagnostics discarded entirely.
    subprocess.run([str(value) for value in command], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=timeout, check=True)


class OwnedCluster:
    def __init__(self, directory, pg_bin):
        self.directory = confined(directory, directory.parent)
        self.data = self.directory / "data"
        self.control = tool(pg_bin, "pg_ctl")
        self.initialize = tool(pg_bin, "initdb")
        self.attempted = False

    def start(self):
        quiet([self.initialize, "-D", self.data, "-U", "fixture", "-A", "trust", "--no-locale"])
        port = reserve_port()
        self.attempted = True
        quiet([self.control, "-D", self.data, "-w", "-t", "30", "-o",
               f"-h localhost -p {port} -c max_locks_per_transaction=256", "start"])
        return f"postgresql://fixture@localhost:{port}/postgres"

    def close(self):
        if not self.attempted:
            return
        status = subprocess.run([str(self.control), "-D", str(self.data), "status"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10, check=False)
        if status.returncode == 3:
            return  # pg_ctl's documented not-running result, including failed start.
        if status.returncode != 0:
            raise ValueError("Owned cluster state unknown; cleanup failed")
        quiet([self.control, "-D", self.data, "-w", "-t", "30", "stop", "-m", "immediate"])


def cleanup_owned_directory(directory, cluster):
    # Refuse removal if pg_ctl cannot prove the owned server stopped. Preserve
    # the directory on status/stop failure for the runner to inspect privately.
    if cluster is not None:
        cluster.close()
    actual = confined(directory, directory.parent)
    if not actual.name.startswith("sealed-setup-ci-"):
        raise ValueError("Owned fixture prefix required")
    shutil.rmtree(actual)


class ProcessCleanupFailure(RuntimeError):
    pass


def launch_consumer(command, env, public_input, timeout=2400):
    child = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.PIPE, text=True)
    try:
        child.communicate(public_input, timeout=timeout)
    except subprocess.TimeoutExpired:
        # /PID targets this exact child; /T includes only its descendants. Never
        # kill by image name. Require taskkill success AND the child's receipt.
        try:
            taskkill = system_tree_killer()
            subprocess.run([str(taskkill), "/PID", str(child.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=15, check=True)
            child.wait(timeout=10)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            raise ProcessCleanupFailure("Owned consumer termination unknown") from error
        raise subprocess.TimeoutExpired(command[0], timeout) from None
    if child.returncode == 2:
        raise ProcessCleanupFailure("Consumer could not confirm owned process cleanup")
    if child.returncode:
        raise subprocess.CalledProcessError(child.returncode, command[0])


def native_host_supported():
    return os.name == "nt"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", required=True)
    parser.add_argument("--existing-database", action="store_true")
    parser.add_argument("--pg-bin", type=Path, help="Installed PostgreSQL tools, required for owned cluster")
    for name in ("server-executable", "native-executable", "server-source", "native-source"):
        parser.add_argument("--" + name)
    args = parser.parse_args(argv)
    cluster = None
    failed = False
    cleanup_safe = True
    try:
        if not native_host_supported():
            raise ValueError("Protected native composition requires Windows")
        if not args.existing_database and not os.environ.get("RUNNER_TEMP"):
            raise ValueError("Owned CI PostgreSQL requires the runner temporary directory")
        temporary = Path(tempfile.mkdtemp(prefix="sealed-setup-ci-"))
        try:
            if args.existing_database:
                uri = database_url(os.environ.get("ZT_INBOUND_TEST_DATABASE_URL", ""))
            else:
                if not args.pg_bin:
                    raise ValueError("Explicit installed PostgreSQL directory required")
                cluster = OwnedCluster(Path(temporary), installed_postgres_directory(args.pg_bin))
                uri = cluster.start()
            env = dict(os.environ, DATABASE_ALLOW_PLAINTEXT="true")
            for name in ("ZT_AUTH_TEST_DATABASE_URL", "ZT_DELIVERY_TEST_DATABASE_URL",
                         "ZT_INBOUND_TEST_DATABASE_URL", "ZT_FAILOVER_TEST_DATABASE_URL"):
                env[name] = uri
            command = ["node", str(ROOT / "scripts/sealed_setup_ci_driver.mjs"), "--tools", args.tools]
            for name in ("server-executable", "native-executable", "server-source", "native-source"):
                value = getattr(args, name.replace("-", "_"))
                if value:
                    command.extend(["--" + name, value])
            launch_consumer(command, env, json.dumps(tls_fixture()))
        except ProcessCleanupFailure:
            cleanup_safe = False
            raise
        finally:
            if cleanup_safe:
                cleanup_owned_directory(temporary, cluster)
    except (ValueError, OSError, subprocess.SubprocessError, ProcessCleanupFailure):
        failed = True
        print("Explicit sealed setup fixture failed; private inputs withheld.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
