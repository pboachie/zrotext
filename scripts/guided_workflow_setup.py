# SPDX-License-Identifier: AGPL-3.0-only
"""Reviewed setup of an existing independent workflow scope; simulator is default."""
from __future__ import annotations
import argparse
import getpass
import json
import os
import re
import stat
from pathlib import Path
import subprocess
import sys
import threading
import uuid
from workflow_paths import checked_path, ParentGuard
import agent_setup as local
from workflow_owner_setup import OwnerSession, OwnerSetupError, scope, identity
from workflow_secret_store import operating_system_store, SecretStoreError, reference

ENTRY = "zrotext-scoped-workflow"


class SetupRecovery(OwnerSetupError):
    def __init__(self, grant, secret):
        super().__init__("setup_incomplete_revocation_unconfirmed")
        self.grant, self.secret = grant, secret


def plan(path, client, broker, expected, origin, grant, secret, remove=False, scope_digest=None):
    path = checked_path(path)
    broker = checked_path(broker, artifact=True)
    if client not in ("mcp-json", "claude-desktop"):
        raise local.SetupError("unsupported_client")
    broker = local.checked_artifact(broker, expected)
    identity(grant)
    reference(secret)
    raw, config = local.read_config(path)
    desired = {"command": sys.executable, "args": [str(Path(__file__).resolve()), "stdio",
               "--broker", str(broker), "--sha256", expected, "--origin", origin,
               "--grant", grant, "--secret-reference", secret]}
    if scope_digest is not None:
        if not isinstance(scope_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", scope_digest):
            raise local.SetupError("invalid_scope_digest")
        desired["args"] += ["--scope-digest", scope_digest]
    servers = dict(config.get("mcpServers", {}))
    existing = servers.get(ENTRY)
    if remove and existing is not None and scope_digest is None:
        prior_args = existing.get("args", []) if isinstance(existing, dict) else []
        if prior_args[:len(desired["args"])] == desired["args"] and len(prior_args) == len(desired["args"]) + 2 and prior_args[-2] == "--scope-digest":
            desired["args"] = prior_args
    if existing is not None and existing != desired:
        raise local.SetupError("entry_conflict")
    action = "remove" if remove and existing else "install" if not remove and not existing else "unchanged"
    if remove:
        servers.pop(ENTRY, None)
    else:
        servers[ENTRY] = desired
    updated = dict(config)
    if action != "unchanged":
        updated["mcpServers"] = servers
    encoded = json.dumps(updated, ensure_ascii=False, indent=2).encode() + b"\n"
    if len(encoded) > local.MAX_CONFIG:
        raise local.SetupError("config_size_limit")
    review = local.digest(raw + b"\0" + encoded + b"\0" + action.encode())
    return {"mode": "scoped-metadata", "action": action, "launch": desired, "reviewDigest": review,
            "permissions": ["context_metadata", "status"], "pairingCreated": False,
            "sendAvailable": False}, raw, encoded


def intent_path(path):
    path = checked_path(path)
    return checked_path(path.with_name(path.name + ".zrotext-grant-intent"))


def validate_intent(value):
    required = {"v", "state", "scope_digest", "configuration_digest", "artifact_digest", "secret_reference", "creator", "origin"}
    if (not isinstance(value, dict) or not required <= set(value) or set(value) - required - {"grant_id"}
            or value["v"] != 1 or value["state"] not in ("issuance_unknown", "issued")):
        raise OwnerSetupError("setup_recovery_required")
    for key in ("scope_digest", "configuration_digest", "artifact_digest"):
        if not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            raise OwnerSetupError("setup_recovery_required")
    reference(value["secret_reference"])
    if not isinstance(value["origin"], str) or len(value["origin"]) > 2048:
        raise OwnerSetupError("setup_recovery_required")
    creator = value["creator"]
    if not isinstance(creator, dict) or set(creator) != {"account_id", "user_id", "session_id"}:
        raise OwnerSetupError("setup_recovery_required")
    for value_id in creator.values():
        identity(value_id)
    if value["state"] == "issued":
        identity(value.get("grant_id"))
    return value


def persist_parent(path):
    # POSIX direntry persistence precedes the remote effect. Windows directory
    # flush semantics are not provided by this API; its power-loss limit is explicit.
    if os.name == "posix":
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def read_intent(path):
    receipt = intent_path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(receipt, flags)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096
                or (os.name == "posix" and info.st_mode & 0o077)
                or receipt.is_symlink()):
            raise OwnerSetupError("setup_recovery_required")
        try:
            value = json.loads(stream.read(4097), object_pairs_hook=local.unique_object)
        except (ValueError, UnicodeError):
            raise OwnerSetupError("setup_recovery_required") from None
    return validate_intent(value)


def write_intent(stream, value):
    encoded = json.dumps(value, sort_keys=True).encode()
    if len(encoded) > 4096:
        raise OwnerSetupError("setup_recovery_required")
    stream.seek(0)
    stream.write(encoded)
    stream.truncate()
    stream.flush()
    os.fsync(stream.fileno())


def preflight(path, client, broker, expected, origin, selected):
    path = checked_path(path)
    broker = checked_path(broker, artifact=True)
    scope(selected)
    if client not in ("mcp-json", "claude-desktop"):
        raise local.SetupError("unsupported_client")
    # Validate origin without authenticating or opening a network connection.
    from urllib.parse import urlsplit
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment):
        raise OwnerSetupError("invalid_origin")
    local.checked_artifact(broker, expected)
    raw, config = local.read_config(path)
    selected_digest = local.digest(json.dumps(scope(selected), sort_keys=True).encode())
    existing = config.get("mcpServers", {}).get(ENTRY)
    if existing is not None:
        args = existing.get("args", []) if isinstance(existing, dict) else []
        if len(args) != 14 or args[-2:] != ["--scope-digest", selected_digest]:
            raise local.SetupError("entry_conflict")
        proposal, _, _ = plan(path, client, broker, expected, origin, args[9], args[11],
                              scope_digest=selected_digest)
        if proposal["action"] != "unchanged":
            raise local.SetupError("entry_conflict")
    else:
        pending = read_intent(path)
        if pending is not None:
            raise OwnerSetupError("setup_recovery_required")
    return raw, config


def install(path, reviewed, owner, selected, password, code, store, client, broker, expected, origin):
    path = checked_path(path)
    broker = checked_path(broker, artifact=True)
    guard = ParentGuard(path)
    # Scope and artifact are validated before consuming the MFA factor.
    scope(selected)
    if client not in ("mcp-json", "claude-desktop"):
        raise local.SetupError("unsupported_client")
    local.checked_artifact(broker, expected)
    raw, config = preflight(path, client, broker, expected, origin, selected)
    if local.digest(raw) != reviewed:
        raise local.SetupError("configuration_changed")
    scope_digest = local.digest(json.dumps(scope(selected), sort_keys=True).encode())
    existing = config.get("mcpServers", {}).get(ENTRY)
    if existing is not None:
        args = existing.get("args", []) if isinstance(existing, dict) else []
        if len(args) != 14 or args[-2:] != ["--scope-digest", scope_digest]:
            raise local.SetupError("entry_conflict")
        # Parsing fixed positions cannot change the launcher or select authority.
        grant, secret = args[9], args[11]
        proposal, _, _ = plan(path, client, broker, expected, origin, grant, secret, scope_digest=scope_digest)
        if proposal["action"] != "unchanged":
            raise local.SetupError("entry_conflict")
        store.get(secret)  # Missing custody refuses; no replacement grant is minted.
        return {"action": "resumed", "grant_id": grant, "secret_reference": secret,
                "currentAuthority": "checked_on_each_tool_call", "sendAvailable": False}
    # Exclusive durable intent precedes the effect. Never retry an ambiguous create.
    receipt = intent_path(path)
    secret = "zrotext-workflow-" + uuid.uuid4().hex
    intent = {"v": 1, "state": "issuance_unknown", "scope_digest": scope_digest,
              "configuration_digest": reviewed, "artifact_digest": expected,
              "secret_reference": secret, "creator": owner.session_identity, "origin": origin}
    try:
        fd = os.open(receipt, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise OwnerSetupError("setup_recovery_required") from None
    with os.fdopen(fd, "w+b") as stream:
        write_intent(stream, intent)
        persist_parent(receipt)
        guard.check()
        grant, token = owner.create(selected, password, code)
        intent.update(state="issued", grant_id=grant)
        # Same exclusively created descriptor: never reopen an attacker-replaced receipt.
        write_intent(stream, intent)
    try:
        store.put(secret, token)
        guard.check()
        proposal, original, encoded = plan(path, client, broker, expected, origin, grant, secret, scope_digest=scope_digest)
        if original != raw:
            raise local.SetupError("configuration_changed")
        guard.check()
        local.apply_plan(path, proposal, original, encoded, proposal["reviewDigest"], path_check=guard.check)
    except Exception:
        # Keep narrow credential custody if remote revocation cannot be confirmed.
        try:
            owner.revoke(grant)
            store.delete(secret)
        except (OwnerSetupError, SecretStoreError):
            raise SetupRecovery(grant, secret) from None
        raise
    owner.retain_creator = True
    return {"creator_session": owner.session_identity, "grant_id": grant, "secret_reference": secret, "permissions": ["context_metadata", "status"],
            "sendAvailable": False, "pairingCreated": False}


def recover(path, reviewed, owner, store):
    path = checked_path(path)
    guard = ParentGuard(path)
    # Deliberate recovery targets only the same user's recorded creator session.
    _, config = local.read_config(path)
    if ENTRY in config.get("mcpServers", {}):
        raise local.SetupError("disconnect_installed_entry_first")
    receipt = intent_path(path)
    fd = os.open(receipt, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096
                or (os.name == "posix" and info.st_mode & 0o077)
                or receipt.is_symlink()):
            raise OwnerSetupError("setup_recovery_required")
        raw = stream.read(4097)
        if local.digest(raw) != reviewed:
            raise local.SetupError("review_required_or_configuration_changed")
        value = validate_intent(json.loads(raw, object_pairs_hook=local.unique_object))
        if value["origin"] != owner.origin:
            raise OwnerSetupError("recovery_identity_refused")
        owner.revoke_creator(value["creator"])
        # Only a confirmed response permits custody/intent cleanup. Unknown preserves it.
        store.delete(reference(value["secret_reference"]))
        current = os.stat(receipt, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise OwnerSetupError("setup_recovery_required")
    guard.check()
    checked_path(receipt).unlink()
    return {"creatorSessionRevoked": True, "automaticRetry": False}


def disconnect(path, client, broker, expected, origin, grant, secret, reviewed, owner, store):
    path = checked_path(path)
    guard = ParentGuard(path)
    proposal, raw, encoded = plan(path, client, broker, expected, origin, grant, secret, remove=True)
    if proposal["reviewDigest"] != reviewed:
        raise local.SetupError("review_required_or_configuration_changed")
    owner.revoke(grant)  # Never remove custody/config first and leave an active grant.
    local.apply_plan(path, proposal, raw, encoded, reviewed, path_check=guard.check)
    pending = read_intent(path)
    if pending is not None:
        if pending.get("grant_id") != grant or pending.get("secret_reference") != secret:
            raise OwnerSetupError("setup_recovery_required")
        recover(path, local.digest(intent_path(path).read_bytes()), owner, store)
    else:
        store.delete(secret)
    return {"grantRevoked": True, "action": proposal["action"]}


def launch(broker, expected, origin, secret, store):
    broker = checked_path(broker, artifact=True)
    broker = local.checked_artifact(broker, expected)
    node, _ = local.node_runtime()
    token = store.get(secret)
    env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH"}}
    child = subprocess.Popen([node, str(broker)], stdin=subprocess.PIPE, stdout=sys.stdout.buffer,
                             stderr=subprocess.DEVNULL, env=env)
    try:
        frame = bytearray((json.dumps({"v": 1, "origin": origin, "credential": token}) + "\n").encode())
        try:
            child.stdin.write(frame)
            child.stdin.flush()
        finally:
            frame[:] = bytes(len(frame))
            token = None
        def forward():
            try:
                while chunk := sys.stdin.buffer.read1(65536):
                    child.stdin.write(chunk)
                    child.stdin.flush()
                child.stdin.close()
            except (OSError, ValueError):
                pass
        threading.Thread(target=forward, daemon=True).start()
        return child.wait()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def refusal(error):
    ambiguous = {"owner_response_unknown", "grant_refused_or_unknown", "setup_recovery_required",
                 "revocation_unconfirmed", "setup_incomplete_revocation_unconfirmed"}
    code = str(error)
    if code in ambiguous:
        return {"code": code, "state": "unknown", "automaticRetry": False}
    return {"code": "guided_setup_refused", "state": "unknown" if isinstance(error, OSError) else "refused",
            "automaticRetry": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["simulator", "preview", "connect", "disconnect", "recovery-preview", "recover", "stdio"], default="simulator", nargs="?")
    for option in ["client", "origin", "grant", "secret-reference", "sha256", "review-digest", "scope-digest"]:
        parser.add_argument("--" + option)
    for option in ["broker", "config", "scope"]:
        parser.add_argument("--" + option, type=Path)
    args = parser.parse_args()
    owner = None
    try:
        required = {"simulator": (), "stdio": ("broker", "sha256", "origin", "secret_reference"),
                    "preview": ("client", "config", "broker", "sha256", "origin", "grant", "secret_reference"),
                    "connect": ("client", "config", "broker", "sha256", "origin", "scope"),
                    "disconnect": ("client", "config", "broker", "sha256", "origin", "grant", "secret_reference", "review_digest"),
                    "recovery-preview": ("config",), "recover": ("config", "origin", "review_digest")}
        if any(getattr(args, name) is None for name in required[args.operation]):
            raise local.SetupError("missing_setup_arguments")
        for name in ("config", "scope", "broker"):
            value = getattr(args, name)
            if value is not None:
                setattr(args, name, checked_path(value, artifact=name == "broker"))
        if args.operation == "simulator":
            result = local.journey()
        elif args.operation == "stdio":
            return launch(args.broker, args.sha256, args.origin, args.secret_reference, operating_system_store())
        elif args.operation == "recovery-preview":
            pending = read_intent(args.config)
            if pending is None:
                raise OwnerSetupError("setup_recovery_required")
            result = {"creator": pending.get("creator"), "grant_id": pending.get("grant_id"),
                      "state": pending.get("state"), "automaticRetry": False,
                      "reviewDigest": local.digest(intent_path(args.config).read_bytes())}
        elif args.operation == "preview":
            result, _, _ = plan(args.config, args.client, args.broker, args.sha256, args.origin,
                                args.grant, args.secret_reference, remove=True)
        else:
            if args.operation == "connect":
                if not args.scope.is_file() or args.scope.stat().st_size > 4096:
                    raise local.SetupError("invalid_scope")
                selected = json.loads(args.scope.read_bytes(), object_pairs_hook=local.unique_object,
                                      parse_constant=local.invalid_constant)
                scope(selected)
                local.checked_artifact(args.broker, args.sha256)
                raw, configuration = preflight(args.config, args.client, args.broker, args.sha256, args.origin, selected)
                print(json.dumps({"status": "confirmation_required", "configurationDigest": local.digest(raw),
                                  "scopeDigest": local.digest(json.dumps(scope(selected), sort_keys=True).encode()),
                                  "permissions": ["context_metadata", "status"],
                                  "pairingCreated": False, "sendAvailable": False}))
                if input("Type the displayed configuration digest to confirm: ") != local.digest(raw):
                    raise local.SetupError("review_required")
            if args.operation == "recover":
                _, configuration = local.read_config(args.config)
                if ENTRY in configuration.get("mcpServers", {}):
                    raise local.SetupError("disconnect_installed_entry_first")
                pending = read_intent(args.config)
                if pending is None:
                    raise OwnerSetupError("setup_recovery_required")
                raw_receipt = intent_path(args.config).read_bytes()
                if local.digest(raw_receipt) != args.review_digest:
                    raise local.SetupError("review_required_or_configuration_changed")
            store = operating_system_store()
            owner = OwnerSession(args.origin)
            password = getpass.getpass("Owner password: ")
            owner.login(input("Owner email: "), password, lambda: getpass.getpass("Login MFA code: "))
            if args.operation == "connect":
                result = install(args.config, local.digest(raw), owner, selected, password,
                                 (None if ENTRY in configuration.get("mcpServers", {}) else getpass.getpass("Fresh grant MFA code: ")), store, args.client,
                                 args.broker, args.sha256, args.origin)
            elif args.operation == "recover":
                result = recover(args.config, args.review_digest, owner, store)
            else:
                result = disconnect(args.config, args.client, args.broker, args.sha256, args.origin,
                                    args.grant, args.secret_reference, args.review_digest, owner, store)
        public = {"status": "completed", "operation": args.operation, "automaticRetry": False,
                  "sendAvailable": False, "pairingCreated": False}
        if args.operation in ("preview", "recovery-preview"):
            public["reviewDigest"] = result["reviewDigest"]
        print(json.dumps(public))
        return 0
    except SetupRecovery as error:
        print('{"code":"setup_incomplete_revocation_unconfirmed","state":"unknown","automaticRetry":false}', file=sys.stderr)
        return 2
    except (local.SetupError, OwnerSetupError, SecretStoreError, OSError, ValueError, TypeError) as error:
        print(json.dumps(refusal(error)), file=sys.stderr)
        return 2
    finally:
        if owner:
            owner.close()


if __name__ == "__main__":
    raise SystemExit(main())
