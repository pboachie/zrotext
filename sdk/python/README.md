# ZROtext minimal Python client

Standard library only (`urllib`, `hmac`); no dependencies, not published to PyPI.
It mirrors the minimal TypeScript client in [`sdk/typescript`](../typescript/README.md).

**Scope.** `AlphaClient` covers only the allowlisted synthetic-alpha test plane the
server actually implements: `POST /v1/alpha/messages`, `GET /v1/alpha/messages/{id}`
and `POST /v1/alpha/messages/{id}/cancel`
([contract](../../protocol/v1/openapi/public-v1.json)). That plane is mounted only
while `SYNTHETIC_ALPHA_ENABLED` admits your account and recipient, and the caller
supplies a short test-case identifier, never message content. A general
`POST /v1/messages` does **not** exist yet, and no hosted service is implied:
point `base_url` at a server you operate.

```python
from zrotext_client import AlphaClient, AlphaApiError, OutcomeUnknownError, requires_reconciliation

client = AlphaClient("https://zrotext.example.test", token)

# idempotency_key is mandatory and caller-owned: persist it with the logical
# message before sending and reuse it verbatim on any retry.
try:
    accepted = client.submit(
        client_message_id=cid, device_id=did, recipient_e164="+15550100001",
        test_case_id="smoke-1", expires_at_ms=deadline_ms, idempotency_key="alpha-run-0001",
    )
    status = client.get_status(accepted.message_id)
    if requires_reconciliation(status.state):
        ...  # unknown / delivery_unknown: do NOT resend; reconcile
except OutcomeUnknownError:
    ...  # may have been accepted: resubmit the IDENTICAL request with the SAME key, or poll status
except AlphaApiError as e:
    ...  # e.status, e.code, e.retry_after_seconds (advisory)
```

- No automatic retries; redirects are refused.
- `submit` raises `ValueError` before any request unless the key matches
  `^[A-Za-z0-9._-]{1,128}$`; a new key for the same logical message could send a
  duplicate SMS.
- A message in the `unknown` state is never retried by this client; see
  [`docs/DELIVERY-STATES.md`](../../docs/DELIVERY-STATES.md).

**Webhook verification:** `verify_webhook(signing_key=..., timestamp=..., signature=..., body=raw_bytes)`
checks `v1=` + lowercase hex HMAC-SHA256 over `timestamp + "." + exact raw body`, a
five-minute window, and compares with `hmac.compare_digest`. Decode the one-time
secret with `secret_from_base64url`. It does not deduplicate event IDs. The vector in
`tests/test_webhook.py` is pinned by `signature_uses_exact_raw_body_and_timestamp` in
`crates/server/src/webhook_egress.rs`.

## Tests

```sh
python3 -m unittest discover -s sdk/python/tests -t sdk/python
```

Tests use a loopback stub HTTP server and no network.
