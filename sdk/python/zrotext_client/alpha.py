"""Minimal stdlib client for the allowlisted synthetic-alpha test plane.

Covers only POST /v1/alpha/messages, GET /v1/alpha/messages/{id} and
POST /v1/alpha/messages/{id}/cancel (protocol/v1/openapi/public-v1.json).
This is not a general send API: a general POST /v1/messages does not exist,
the alpha plane is mounted only for allowlisted accounts and recipients, the
caller never supplies message content, and no hosted service is implied.

The client never retries. Submission needs an explicit caller-chosen
Idempotency-Key. A transport failure or timeout raises OutcomeUnknownError;
the caller may resubmit the IDENTICAL request with the SAME key. A message in
the ``unknown`` writer state must never be resent automatically.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "AlphaApiError",
    "AlphaClient",
    "AlphaAccepted",
    "AlphaStatus",
    "OutcomeUnknownError",
    "requires_reconciliation",
]

_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_E164 = re.compile(r"^\+[1-9][0-9]{1,14}$")
_TEST_CASE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_RETRY_AFTER = re.compile(r"^[0-9]{1,6}$")


class AlphaApiError(Exception):
    """The server answered with a non-success status."""

    def __init__(self, status: int, code: Optional[str], retry_after_seconds: Optional[int]):
        super().__init__(f"alpha request failed with HTTP {status}" + (f" ({code})" if code else ""))
        self.status = status
        self.code = code
        self.retry_after_seconds = retry_after_seconds


class OutcomeUnknownError(Exception):
    """The request may or may not have reached the server.

    For a submission, resubmit the identical request with the same
    Idempotency-Key or poll status. Never use a new key for the same message.
    """

    def __init__(self, operation: str):
        super().__init__(f"alpha {operation} outcome unknown: the response was not received intact")
        self.operation = operation


@dataclass(frozen=True)
class AlphaAccepted:
    message_id: str
    created: bool


@dataclass(frozen=True)
class AlphaStatus:
    message_id: str
    device_id: str
    state: str
    state_version: int
    created_at_ms: int
    updated_at_ms: int


def requires_reconciliation(state: str) -> bool:
    """True when the state must not be resent automatically."""
    return state in ("unknown", "delivery_unknown")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib hook
        return None


def _require_uuid(value: object, name: str) -> None:
    if not isinstance(value, str) or not _UUID.match(value):
        raise ValueError(f"{name} must be a UUID")


class AlphaClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        timeout: float = 35.0,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ):
        if not api_key or "\r" in api_key or "\n" in api_key:
            raise ValueError("api_key must be a non-empty single-line token")
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("base_url must be an http(s) origin")
        self._base = f"{parts.scheme}://{parts.netloc}"
        self._key = api_key
        self._timeout = timeout
        self._opener = opener or urllib.request.build_opener(_NoRedirect)

    def submit(
        self,
        *,
        client_message_id: str,
        device_id: str,
        recipient_e164: str,
        test_case_id: str,
        expires_at_ms: int,
        idempotency_key: str,
    ) -> AlphaAccepted:
        """Submit one synthetic-alpha test message. idempotency_key is required."""
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_KEY.match(idempotency_key):
            raise ValueError(
                "idempotency_key must be 1-128 ASCII alphanumeric, dash, dot or underscore characters"
            )
        _require_uuid(client_message_id, "client_message_id")
        _require_uuid(device_id, "device_id")
        if not isinstance(recipient_e164, str) or not _E164.match(recipient_e164):
            raise ValueError("recipient_e164 must be E.164")
        if not isinstance(test_case_id, str) or not _TEST_CASE.match(test_case_id):
            raise ValueError("test_case_id must be 1-32 alphanumeric, dash or underscore characters")
        if isinstance(expires_at_ms, bool) or not isinstance(expires_at_ms, int) or expires_at_ms < 0:
            raise ValueError("expires_at_ms must be a non-negative integer")
        body = json.dumps(
            {
                "client_message_id": client_message_id,
                "device_id": device_id,
                "recipient_e164": recipient_e164,
                "test_case_id": test_case_id,
                "expires_at_ms": expires_at_ms,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        raw = self._send(
            "submit",
            "POST",
            "/v1/alpha/messages",
            202,
            {"Content-Type": "application/json", "Idempotency-Key": idempotency_key},
            body,
        )
        obj = _parse_object(raw, "submit")
        if not isinstance(obj.get("message_id"), str) or not isinstance(obj.get("created"), bool):
            raise OutcomeUnknownError("submit")
        return AlphaAccepted(message_id=obj["message_id"], created=obj["created"])

    def get_status(self, message_id: str) -> AlphaStatus:
        _require_uuid(message_id, "message_id")
        raw = self._send("status", "GET", f"/v1/alpha/messages/{message_id}", 200)
        obj = _parse_object(raw, "status")
        ints = ("state_version", "created_at_ms", "updated_at_ms")
        if (
            not all(isinstance(obj.get(k), str) for k in ("message_id", "device_id", "state"))
            or not all(isinstance(obj.get(k), int) and not isinstance(obj.get(k), bool) for k in ints)
        ):
            raise OutcomeUnknownError("status")
        return AlphaStatus(
            message_id=obj["message_id"],
            device_id=obj["device_id"],
            state=obj["state"],
            state_version=obj["state_version"],
            created_at_ms=obj["created_at_ms"],
            updated_at_ms=obj["updated_at_ms"],
        )

    def cancel(self, message_id: str) -> None:
        """Request cancellation before dispatch; 409 raises AlphaApiError(code='conflict')."""
        _require_uuid(message_id, "message_id")
        self._send("cancel", "POST", f"/v1/alpha/messages/{message_id}/cancel", 204)

    def _send(
        self,
        operation: str,
        method: str,
        path: str,
        ok_status: int,
        headers: Optional[dict] = None,
        body: Optional[bytes] = None,
    ) -> bytes:
        request = urllib.request.Request(self._base + path, data=body, method=method)
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        request.add_header("Authorization", f"Bearer {self._key}")
        request.add_header("Accept", "application/json")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                status = response.status
                payload = response.read()
        except urllib.error.HTTPError as error:
            raise _api_error(error) from None
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise OutcomeUnknownError(operation) from error
        if status != ok_status:
            raise AlphaApiError(status, None, None)
        return payload


def _parse_object(raw: bytes, operation: str) -> dict:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise OutcomeUnknownError(operation) from error
    if not isinstance(parsed, dict):
        raise OutcomeUnknownError(operation)
    return parsed


def _api_error(error: urllib.error.HTTPError) -> AlphaApiError:
    code = None
    try:
        parsed = json.loads(error.read().decode("utf-8"))
        if isinstance(parsed, dict) and isinstance(parsed.get("code"), str):
            code = parsed["code"]
    except (OSError, UnicodeDecodeError, ValueError):
        pass  # framework 400/408/413 and the bare admission 503 have no JSON body
    raw = error.headers.get("Retry-After") if error.headers else None
    retry = int(raw) if raw is not None and _RETRY_AFTER.match(raw) else None
    return AlphaApiError(error.code, code, retry)
