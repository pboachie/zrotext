"""Webhook signature verifier (stdlib only).

The ``x-zrotext-signature`` header is ``v1=`` plus lowercase hex of
HMAC-SHA256(key = decoded signing secret bytes,
message = ASCII decimal ``x-zrotext-timestamp`` + "." + exact raw body bytes),
as in crates/server/src/webhook_egress.rs. A five-minute window applies.
Pass the RAW request body; re-serialized JSON will not verify. Deduplicating
the event ID inside the body is the receiver's job.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
from typing import Optional, Union

__all__ = [
    "TOLERANCE_SECONDS",
    "WebhookVerificationError",
    "secret_from_base64url",
    "sign_webhook",
    "verify_webhook",
]

TOLERANCE_SECONDS = 300
_TIMESTAMP = re.compile(r"^(0|[1-9][0-9]{0,15})$")
_SIGNATURE = re.compile(r"^v1=([0-9a-f]{64})$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class WebhookVerificationError(Exception):
    """reason is bad_timestamp, timestamp_out_of_window, bad_signature_format or signature_mismatch."""

    def __init__(self, reason: str):
        super().__init__(f"webhook verification failed: {reason}")
        self.reason = reason


def secret_from_base64url(value: str) -> bytes:
    """Decode ``signing_secret_b64url`` from the webhook create/rotate response."""
    if not _B64URL.match(value):
        raise ValueError("secret is not unpadded base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _signed(timestamp: str, body: Union[bytes, str]) -> bytes:
    raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    return timestamp.encode("ascii") + b"." + raw


def sign_webhook(secret: bytes, timestamp_seconds: int, body: Union[bytes, str]) -> str:
    """Compute the ``v1=<hex>`` header value (tests and local simulators)."""
    mac = hmac.new(secret, _signed(str(timestamp_seconds), body), hashlib.sha256)
    return "v1=" + mac.hexdigest()


def verify_webhook(
    *,
    signing_key: bytes,
    timestamp: str,
    signature: str,
    body: Union[bytes, str],
    now_seconds: Optional[float] = None,
    tolerance_seconds: int = TOLERANCE_SECONDS,
) -> None:
    """Return None if valid; raise WebhookVerificationError otherwise."""
    if not _TIMESTAMP.match(timestamp):
        raise WebhookVerificationError("bad_timestamp")
    now = time.time() if now_seconds is None else now_seconds
    if abs(now - int(timestamp)) > tolerance_seconds:
        raise WebhookVerificationError("timestamp_out_of_window")
    match = _SIGNATURE.match(signature)
    if not match:
        raise WebhookVerificationError("bad_signature_format")
    expected = hmac.new(signing_key, _signed(timestamp, body), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, bytes.fromhex(match.group(1))):
        raise WebhookVerificationError("signature_mismatch")
