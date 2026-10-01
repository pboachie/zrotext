#!/usr/bin/env python3
"""Reviewed local MCP configuration. No pairing, credentials or live activation."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ENTRY = "zrotext-local-preview"
MAX_CONFIG = 1024 * 1024

class SetupError(Exception):
    pass

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def checked_artifact(server: Path, expected: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SetupError("invalid_artifact_digest")
    if server.is_symlink() or not server.is_file() or server.suffix != ".mjs":
        raise SetupError("artifact_missing")
    if server.stat().st_size > MAX_CONFIG or digest(server.read_bytes()) != expected:
        raise SetupError("artifact_changed")
    return server.resolve()

def node_runtime() -> tuple[str, str]:
    node = shutil.which("node")
    if not node:
        raise SetupError("node_missing")
    try:
        version = subprocess.run([node, "--version"], capture_output=True, text=True,
                                 timeout=5, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise SetupError("node_unavailable") from None
    if not re.fullmatch(r"v\d+\.\d+\.\d+", version) or int(version.split(".")[0][1:]) < 22:
        raise SetupError("node_unsupported")
    return node, version

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SetupError("duplicate_config_key")
        result[key] = value
    return result

def invalid_constant(_):
    raise SetupError("invalid_config")

def read_config(path: Path) -> tuple[bytes, dict]:
    if path.is_symlink() or not path.parent.is_dir():
        raise SetupError("invalid_config_path")
    if not path.exists():
        return b"", {}
    if not path.is_file() or path.stat().st_size > MAX_CONFIG:
        raise SetupError("invalid_config")
    raw = path.read_bytes()
    try:
        config = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (ValueError, UnicodeError):
        raise SetupError("invalid_config") from None
    if not isinstance(config, dict) or not isinstance(config.get("mcpServers", {}), dict):
        raise SetupError("invalid_config")
    return raw, config

def launch_entry(server: Path, expected: str) -> dict:
    return {"command": sys.executable, "args": [str(Path(__file__).resolve()), "stdio",
            "--server", str(server), "--sha256", expected]}

def plan_config(path: Path, client: str, server: Path, expected: str, remove=False) -> tuple[dict, bytes, bytes]:
    if client not in ("claude-desktop", "mcp-json"):
        raise SetupError("unsupported_client")
    if remove:
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise SetupError("invalid_artifact_digest")
        server = server.resolve()
    else:
        server = checked_artifact(server, expected)
    raw, config = read_config(path)
    desired = launch_entry(server, expected)
    servers = config.get("mcpServers", {})
    existing = servers.get(ENTRY)
    if existing is not None and existing != desired:
        raise SetupError("entry_conflict")
    updated = dict(config)
    updated_servers = dict(servers)
    if remove:
        updated_servers.pop(ENTRY, None)
        action = "remove" if ENTRY in servers else "unchanged"
    else:
        updated_servers[ENTRY] = desired
        action = "unchanged" if existing == desired else "install"
    # Preserve an absent mcpServers key on an already-disconnected configuration.
    if action != "unchanged":
        updated["mcpServers"] = updated_servers
    encoded = json.dumps(updated, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    if len(encoded) > MAX_CONFIG:
        raise SetupError("config_size_limit")
    review = digest(raw + b"\0" + encoded + b"\0" + action.encode())
    plan = {"mode": "local-preview", "liveAvailable": False, "action": action,
            "client": client, "entry": ENTRY, "launch": desired,
            "reviewDigest": review, "artifactDigest": expected,
            "grantRevoked": False, "grantCreated": False}
    return plan, raw, encoded

def apply_plan(path: Path, plan: dict, original: bytes, encoded: bytes, reviewed: str) -> dict:
    if reviewed != plan["reviewDigest"]:
        raise SetupError("review_required_or_configuration_changed")
    if plan["action"] == "unchanged":
        return {"action": "unchanged", "liveAvailable": False, "grantRevoked": False}
    # Cross-process exclusion for this tool; compare again before atomic replacement.
    lock = path.with_name(path.name + ".zrotext-lock")
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise SetupError("setup_busy") from None
    temp_name = None
    try:
        os.close(lock_fd)
        current, _ = read_config(path)
        if current != original:
            raise SetupError("configuration_changed")
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".zrotext-", delete=False) as staged:
            temp_name = staged.name
            os.chmod(temp_name, mode)
            staged.write(encoded)
            staged.flush()
            os.fsync(staged.fileno())
        # Refuse an external editor change observed while preparing the file.
        current, _ = read_config(path)
        if current != original:
            raise SetupError("configuration_changed")
        os.replace(temp_name, path)
        temp_name = None
        return {"action": plan["action"], "liveAvailable": False, "grantRevoked": False}
    finally:
        if temp_name:
            os.unlink(temp_name)
        os.unlink(lock)

def doctor(server: Path, expected: str, client="mcp-json") -> dict:
    if client not in ("claude-desktop", "mcp-json"):
        raise SetupError("unsupported_client")
    checked_artifact(server, expected)
    _, version = node_runtime()
    return {"mode": "local-preview", "client": client, "clientVersion": "unknown", "nodeVersion": version, "pythonVersion": sys.version.split()[0],
            "artifactVerified": True, "liveAvailable": False,
            "gates": {"scopedPolicy": "unavailable", "pairing": "unavailable", "lineHealth": "unknown",
                      "androidPermissions": "unknown", "simReadiness": "unknown", "release": "unavailable"}}

def demo(server: Path, expected: str) -> dict:
    server = checked_artifact(server, expected)
    node, _ = node_runtime()
    fixture_path = Path(__file__).resolve().parents[1] / "protocol/v1/vectors/ztse-draft-01.json"
    import base64
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    encoded = base64.b64encode(bytes.fromhex(fixture["outbound"]["envelopeHex"])).decode("ascii")
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "zrotext-setup-demo", "version": "0.0.0-experimental"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "zrotext_readiness", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "zrotext_preview", "arguments": {"envelopeBase64": encoded}}},
    ]
    started = time.monotonic()
    try:
        run = subprocess.run([node, str(server)], input="".join(json.dumps(item) + "\n" for item in requests),
                             capture_output=True, text=True, encoding="utf-8", timeout=15, check=True)
        if len(run.stdout.encode("utf-8")) > 65536:
            raise SetupError("unexpected_connector_response")
        replies = [json.loads(line) for line in run.stdout.splitlines()]
        if len(replies) != 3 or [item.get("id") for item in replies] != [1, 2, 3]:
            raise SetupError("unexpected_connector_response")
        readiness = replies[1]["result"]["structuredContent"]
        preview = replies[2]["result"]["structuredContent"]
        if readiness.get("available") is not False or preview.get("code") != "preview_only" or preview.get("cryptoVerified") is not False:
            raise SetupError("unexpected_connector_response")
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError):
        raise SetupError("connector_demo_unavailable") from None
    return {"synthetic": True, "mode": "local-preview", "liveAvailable": False,
            "firstExchange": "SDK fixture preview", "manualCommands": 1,
            "elapsedSeconds": round(time.monotonic() - started, 3), "carrierDelivery": "unverified"}

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("doctor", "demo", "install", "disconnect", "stdio"))
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--sha256", required=True, help="Fingerprint reviewed from a trusted source checkout/artifact")
    parser.add_argument("--client", default="mcp-json")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--review-digest")
    args = parser.parse_args(argv)
    try:
        if args.operation == "stdio":
            server = checked_artifact(args.server, args.sha256)
            node, _ = node_runtime()
            # Stdout must contain only the selected server's MCP protocol.
            os.execv(node, [node, str(server)])
            return 0
        if args.operation == "demo":
            output = demo(args.server, args.sha256)
        elif args.operation == "doctor":
            output = doctor(args.server, args.sha256, args.client)
        else:
            if args.config is None:
                raise SetupError("config_required")
            if args.operation == "install":
                node_runtime()
            plan, raw, encoded = plan_config(args.config, args.client, args.server, args.sha256,
                                             remove=args.operation == "disconnect")
            output = apply_plan(args.config, plan, raw, encoded, args.review_digest) if args.apply else plan
        print(json.dumps(output, ensure_ascii=True, indent=2))
        return 0
    except (SetupError, OSError) as error:
        code = str(error) if isinstance(error, SetupError) else "local_io_failure"
        if args.operation == "stdio":
            print("Connector launch refused: " + code, file=sys.stderr)
        else:
            print(json.dumps({"code": code, "liveAvailable": False}))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
