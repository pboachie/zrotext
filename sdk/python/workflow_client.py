# SPDX-License-Identifier: AGPL-3.0-only
"""Scoped workflow HTTPS functions using the built TypeScript SDK, not new crypto.

Credentials remain in caller memory and bridge stdin, never process arguments.
Neither readiness hints nor prepared outcomes authorize carrier dispatch.
"""
import json
from pathlib import Path
import subprocess


class WorkflowError(Exception):
    """Redacted refusal or unknown result; never includes server diagnostics."""

    def __init__(self, code, state="refused", attempts=0):
        super().__init__(code)
        self.code, self.state, self.attempts = code, state, attempts


def _bridge(request):
    try:
        payload = json.dumps(request, ensure_ascii=True, allow_nan=False)
        if len(payload.encode("utf-8")) > 98304:
            raise ValueError()
    except (ValueError, TypeError):
        raise WorkflowError("invalid_request") from None
    try:
        process = subprocess.run(
            ["node", str(Path(__file__).with_name("workflow_bridge.mjs"))],
            input=payload, text=True, encoding="utf-8", capture_output=True,
            timeout=35, check=True,
        )
        if len(process.stdout.encode("utf-8")) > 196608:
            raise ValueError()
        result = json.loads(process.stdout)
        if not isinstance(result, dict) or type(result.get("ok")) is not bool:
            raise ValueError()
        if result["ok"]:
            if set(result) != {"ok", "result"}:
                raise ValueError()
            return result["result"]
        if set(result) != {"ok", "error"}:
            raise ValueError()
        error = result["error"]
        codes = {"invalid_request", "invalid_configuration", "response_unknown", "unauthorized", "forbidden",
                 "not_found", "conflict", "rate_limited", "unavailable"}
        if (not isinstance(error, dict) or set(error) != {"code", "state", "attempts"}
                or error["code"] not in codes or error["state"] not in {"refused", "unknown"}
                or type(error["attempts"]) is not int or not 0 <= error["attempts"] <= 3):
            raise ValueError()
        raise WorkflowError(error["code"], error["state"], error["attempts"])
    except WorkflowError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        # A failed bridge can follow an accepted effect. Never infer nonacceptance.
        raise WorkflowError("response_unknown", "unknown") from None


def workflow_functions():
    """The same closed function schemas used by TypeScript and MCP."""
    return _bridge({"op": "functions"})


def action_digest(descriptor):
    """Shared canonical action digest; not a signature, decryption or approval."""
    return _bridge({"op": "action_digest", "descriptor": descriptor})


class WorkflowClient:
    def __init__(self, origin, credential, timeout_ms=10000):
        if not isinstance(origin, str) or not isinstance(credential, str) or type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise WorkflowError("invalid_configuration")
        self.__configuration = {"origin": origin, "credential": credential, "timeoutMs": timeout_ms}

    def __repr__(self):
        return "WorkflowClient(<credential redacted>)"

    def readiness(self):
        return _bridge({"op": "readiness", **self.__configuration})

    def call(self, method, params, max_attempts=1):
        if not isinstance(method, str) or not isinstance(params, dict) or type(max_attempts) is not int or not 1 <= max_attempts <= 3:
            raise WorkflowError("invalid_request")
        return _bridge({"op": "call", "method": method, "params": params,
                        "maxAttempts": max_attempts, **self.__configuration})

    def preview(self, request_id, descriptor):
        """Persist a proposal through policy. This does not approve or send it."""
        return self.call("workflow.action.propose", {"request_id": request_id, "descriptor": descriptor})

    def status(self, request_id, context_id, action_id):
        return self.call("workflow.action.status", {"request_id": request_id, "context_id": context_id, "action_id": action_id})

    def submit(self, request_id, key, occurrence_id=None):
        """Prepare an independently owner-bound action; never plaintext SMS."""
        return self.call("workflow.action.send", {"request_id": request_id, "key": key, "occurrence_id": occurrence_id})

    def cancel(self, request_id, key):
        """Withdraw this grant's exact prepared action before the phone grant."""
        return self.call("workflow.action.cancel", {"request_id": request_id, "key": key})
