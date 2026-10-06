"""Minimal stdlib-only ZROtext client: synthetic-alpha plane and webhook verifier."""

from .alpha import (
    AlphaAccepted,
    AlphaApiError,
    AlphaClient,
    AlphaStatus,
    OutcomeUnknownError,
    requires_reconciliation,
)
from .webhook import (
    TOLERANCE_SECONDS,
    WebhookVerificationError,
    secret_from_base64url,
    sign_webhook,
    verify_webhook,
)

__all__ = [
    "AlphaAccepted",
    "AlphaApiError",
    "AlphaClient",
    "AlphaStatus",
    "OutcomeUnknownError",
    "requires_reconciliation",
    "TOLERANCE_SECONDS",
    "WebhookVerificationError",
    "secret_from_base64url",
    "sign_webhook",
    "verify_webhook",
]
