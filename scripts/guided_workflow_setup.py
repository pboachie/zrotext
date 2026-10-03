# SPDX-License-Identifier: AGPL-3.0-only
"""Reviewed setup of an existing independent workflow scope; simulator is default."""
from __future__ import annotations
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import uuid
import agent_setup as local
from workflow_owner_setup import OwnerSession, OwnerSetupError, scope, identity
from workflow_secret_store import operating_system_store, SecretStoreError, reference

ENTRY = "zrotext-scoped-workflow"


class SetupRecovery(OwnerSetupError):
    def __init__(self, grant, secret):
        super().__init__("setup_incomplete_revocation_unconfirmed")
        self.grant, self.secret = grant, secret


def plan(path, client, broker, expected, origin, grant, secret, remove=False, scope_digest=None):
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
        if not isinstance(scope_digest, str) or len(scope_digest) != 64:
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


def install(path, reviewed, owner, selected, password, code, store, client, broker, expected, origin):
    # Scope and artifact are validated before consuming the MFA factor.
    scope(selected)
    local.checked_artifact(broker, expected)
    raw, config = local.read_config(path)
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
    grant, token = owner.create(selected, password, code)
    secret = "zrotext-workflow-" + uuid.uuid4().hex
    try:
        store.put(secret, token)
        proposal, original, encoded = plan(path, client, broker, expected, origin, grant, secret, scope_digest=scope_digest)
        if original != raw:
            raise local.SetupError("configuration_changed")
        local.apply_plan(path, proposal, original, encoded, proposal["reviewDigest"])
    except Exception:
        # Keep narrow credential custody if remote revocation cannot be confirmed.
        try:
            owner.revoke(grant)
            store.delete(secret)
        except (OwnerSetupError, SecretStoreError):
            raise SetupRecovery(grant, secret) from None
        raise
    return {"grant_id": grant, "secret_reference": secret, "permissions": ["context_metadata", "status"],
            "sendAvailable": False, "pairingCreated": False}


def disconnect(path, client, broker, expected, origin, grant, secret, reviewed, owner, store):
    proposal, raw, encoded = plan(path, client, broker, expected, origin, grant, secret, remove=True)
    if proposal["reviewDigest"] != reviewed:
        raise local.SetupError("review_required_or_configuration_changed")
    owner.revoke(grant)  # Never remove custody/config first and leave an active grant.
    local.apply_plan(path, proposal, raw, encoded, reviewed)
    store.delete(secret)
    return {"grantRevoked": True, "action": proposal["action"]}


def launch(broker, expected, origin, secret, store):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["simulator", "preview", "connect", "disconnect", "stdio"], default="simulator", nargs="?")
    for option in ["client", "origin", "grant", "secret-reference", "sha256", "review-digest", "scope-digest"]:
        parser.add_argument("--" + option)
    for option in ["broker", "config", "scope"]:
        parser.add_argument("--" + option, type=Path)
    args = parser.parse_args()
    owner = None
    try:
        if args.operation == "simulator":
            result = local.journey()
        elif args.operation == "stdio":
            return launch(args.broker, args.sha256, args.origin, args.secret_reference, operating_system_store())
        elif args.operation == "preview":
            result, _, _ = plan(args.config, args.client, args.broker, args.sha256, args.origin,
                                args.grant, args.secret_reference, remove=True)
        else:
            if args.operation == "connect":
                selected = json.loads(args.scope.read_text(encoding="utf-8"))
                scope(selected)
                local.checked_artifact(args.broker, args.sha256)
                raw, _ = local.read_config(args.config)
                print(json.dumps({"configurationDigest": local.digest(raw), "permissions": ["context_metadata", "status"],
                                  "scope": selected, "pairingCreated": False, "sendAvailable": False,
                                  "launch": [sys.executable, str(Path(__file__).resolve()), "stdio", "--broker", str(args.broker.resolve()), "--sha256", args.sha256]}))
                if input("Type the displayed configuration digest to confirm: ") != local.digest(raw):
                    raise local.SetupError("review_required")
            store = operating_system_store()
            owner = OwnerSession(args.origin)
            password = getpass.getpass("Owner password: ")
            owner.login(input("Owner email: "), password, lambda: getpass.getpass("Login MFA code: "))
            if args.operation == "connect":
                result = install(args.config, local.digest(raw), owner, selected, password,
                                 getpass.getpass("Fresh grant MFA code: "), store, args.client,
                                 args.broker, args.sha256, args.origin)
            else:
                result = disconnect(args.config, args.client, args.broker, args.sha256, args.origin,
                                    args.grant, args.secret_reference, args.review_digest, owner, store)
        print(json.dumps(result))
        return 0
    except SetupRecovery as error:
        print(json.dumps({"code": "setup_incomplete_revocation_unconfirmed", "grant_id": error.grant,
                          "secret_reference": error.secret, "automaticRetry": False}), file=sys.stderr)
        return 2
    except (local.SetupError, OwnerSetupError, SecretStoreError, OSError, ValueError, TypeError):
        print(json.dumps({"code": "guided_setup_refused"}), file=sys.stderr)
        return 2
    finally:
        if owner:
            owner.close()


if __name__ == "__main__":
    raise SystemExit(main())
