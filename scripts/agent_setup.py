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

def node_runtime(environment=None) -> tuple[str, str]:
    node = shutil.which("node")
    if not node:
        raise SetupError("node_missing")
    try:
        version = subprocess.run([node, "--version"], capture_output=True, text=True,
                                 timeout=5, check=True, env=environment).stdout.strip()
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

JOURNEY_STATES = {
    "task_notification": "accepted", "notification_replay": "accepted",
    "verified_fixture_reply": "reply_routed_for_review", "reply_replay_after_restart": "replayed",
    "next_action_owner_review": "awaiting_authenticated_exact_approval",
    "edited_notification_identity": "action_identity_conflict", "foreign_reply": "unverified_or_foreign_event",
    "tampered_reply": "signature_refused", "unavailable_content": "content_unavailable",
    "ambiguous_reply": "owner_review", "opt_out": "metadata_only_stop",
    "notification_after_opt_out": "opted_out", "revoked_access": "revoked", "offline_expiry": "expired",
    "unknown_submission": "unknown", "unknown_replay_after_restart": "unknown",
}

def checked_journey(value: dict) -> dict:
    expected = {"synthetic": True, "version": 1, "mode": "guided-local-fixture", "available": False,
                "transport": "shared-synthetic-adapter", "replyTrust": "pinned-public-test-vector-only",
                "ownerApproval": "unavailable", "radioSubmission": "unavailable", "carrierDelivery": "unverified",
                "modelProviderAccess": "none", "checkpointLifetime": "one-command"}
    if not isinstance(value, dict) or set(value) != set(expected) | {"steps", "accounting"}:
        raise SetupError("unexpected_journey_response")
    if any(type(value[key]) is not type(item) or value[key] != item for key, item in expected.items()):
        raise SetupError("unexpected_journey_response")
    steps = value["steps"]
    if not isinstance(steps, list) or len(steps) != len(JOURNEY_STATES):
        raise SetupError("unexpected_journey_response")
    for row, (step, state) in zip(steps, JOURNEY_STATES.items()):
        if not isinstance(row, dict) or set(row) - {"step", "synthetic", "available", "state", "actionId", "content", "modelProviderAccess"}:
            raise SetupError("unexpected_journey_response")
        if (row.get("step") != step or row.get("state") != state or row.get("synthetic") is not True
                or row.get("available") is not False or row.get("modelProviderAccess") != "none"
                or row.get("content") not in ("unavailable", "selected-reader")
                or ("actionId" in row and not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", row["actionId"]))):
            raise SetupError("unexpected_journey_response")
    expected_counts = {"notificationIdentities": 1, "notificationAttempts": 1, "replyIdentities": 2,
                       "replyTurns": 1, "unknownIdentities": 1, "unknownAttempts": 1}
    if value["accounting"] != expected_counts or any(type(item) is not int for item in value["accounting"].values()):
        raise SetupError("unexpected_journey_response")
    return value

def journey() -> dict:
    entry = Path(__file__).resolve().parents[1] / "sdk/typescript/examples/guided-journey.mjs"
    # This command runs only the source-controlled fixture composition. Inherited
    # credentials, NODE_OPTIONS and integration activation variables are absent.
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR")}
    node, version = node_runtime(environment)
    started = time.monotonic()
    try:
        # The parent also owns the temporary lifetime: subprocess.run kills and
        # waits for a timed-out child before this context removes its checkpoint.
        with tempfile.TemporaryDirectory(prefix="zrotext-guided-command-") as temporary:
            environment.update(TEMP=temporary, TMP=temporary, TMPDIR=temporary)
            run = subprocess.run([node, str(entry)], cwd=entry.parent, env=environment,
                                 capture_output=True, text=True, encoding="utf-8", timeout=30, check=True)
        if len(run.stdout.encode("utf-8")) > 16384 or run.stderr:
            raise SetupError("unexpected_journey_response")
        result = checked_journey(json.loads(run.stdout, object_pairs_hook=unique_object, parse_constant=invalid_constant))
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError, SetupError):
        raise SetupError("synthetic_journey_unavailable") from None
    return {**result, "nodeVersion": version, "pythonVersion": sys.version.split()[0],
            "elapsedSeconds": round(time.monotonic() - started, 3)}

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("doctor", "demo", "journey", "install", "disconnect", "stdio"))
    parser.add_argument("--server", type=Path)
    parser.add_argument("--sha256", help="Fingerprint reviewed from a trusted source checkout/artifact")
    parser.add_argument("--client", default="mcp-json")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--review-digest")
    args = parser.parse_args(argv)
    try:
        if args.operation == "journey":
            if args.server is not None or args.sha256 is not None or args.config is not None or args.apply or args.review_digest or args.client != "mcp-json":
                raise SetupError("journey_configuration_unavailable")
            output = journey()
        elif args.server is None or args.sha256 is None:
            raise SetupError("reviewed_artifact_required")
        elif args.operation == "stdio":
            server = checked_artifact(args.server, args.sha256)
            node, _ = node_runtime()
            # Stdout must contain only the selected server's MCP protocol.
            os.execv(node, [node, str(server)])
            return 0
        elif args.operation == "demo":
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
