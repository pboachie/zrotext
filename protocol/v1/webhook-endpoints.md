# Owner webhook endpoint lifecycle

These browser routes are mounted only when account routes and an operational
`WEBHOOK_KEK_VERSION`/`WEBHOOK_KEK_B64` pair are configured. They can be used
while `WEBHOOK_DELIVERY_ENABLED=false`; that flag must be set separately to
start the sender. No route sends a test webhook. All routes require a verified,
active owner session. POST also requires the exact configured HTTPS `Origin`
and the session's double-submit CSRF cookie/header. Responses use
`Cache-Control: no-store`; request bodies are limited to 4 KiB.

| Route | Result |
| --- | --- |
| `POST /v1/webhooks` with `{"callback_url":"https://..."}` | Creates a disabled endpoint. Returns its ID, URL, `enabled:false`, and `signing_secret_b64url` once. |
| `GET /v1/webhooks` | Lists this account's IDs, URLs, enabled states, nullable `paused_at_ms` and `failure_started_at_ms`, and creation times. Never includes signing secrets or encrypted secret bytes. |
| `GET /v1/webhooks/{id}/deliveries` | Pages recent delivery and attempt metadata for this account's endpoint. No payload, callback URL, signing secret, response body, recipient, or inbound content is returned. |
| `POST /v1/webhooks/{id}/deliveries/{delivery_id}/replay` | With a caller-generated UUIDv4 `Idempotency-Key`, queues one new bounded generation of an exhausted failed delivery. Returns HTTP 202 with `delivery_id`, `generation`, and `created`. |
| `POST /v1/webhooks/{id}/enable` | Revalidates the HTTPS URL and decryptability of its secret, then enables future inbound fan-out. |
| `POST /v1/webhooks/{id}/disable` | Disables the endpoint and permanently retires its pending and leased deliveries. |
| `POST /v1/webhooks/{id}/rotate` | Generates a new secret, disables the endpoint, and retires pending/leased deliveries. Returns the new secret once. |

The signing secret is 32 random bytes encoded as unpadded base64url in the
create/rotate response. A receiver decodes it to raw bytes for HMAC-SHA256
verification. Only an AES-256-GCM ciphertext, bound to account/endpoint/key
version by authenticated context, is stored. There is no secret retrieval
route. Losing the response requires rotation. The limit is eight endpoints per
account, including disabled endpoints.

An endpoint with transport failures spanning 72 hours is paused automatically.
Pending deliveries remain queued, and the sender skips the endpoint while
`paused_at_ms` is non-null. The owner list exposes the pause and the start of
the failure streak. `POST /enable` clears both fields and resumes due delivery;
a successful acknowledgment also clears a failure streak. Disabling and
rotating retain their permanent retirement behavior.

History accepts optional `limit` (1–20; default 20) and `before` (the
`delivery_id` returned on the preceding page). The response has `deliveries`
and a nullable `next_before`; use the latter while it is present. Deliveries
are ordered newest first by creation time and ID. Each contains `delivery_id`,
`event_id`, `status`, current `generation`, nullable `terminal_reason`, current
generation's `attempt_count`, `created_at_ms`, `updated_at_ms`, a
`next_attempt_at_ms` value only while pending, and attempts ordered by number.
Each attempt contains its generation, number, start/completion times in Unix milliseconds,
outcome, and optional HTTP status. An unknown or another account's endpoint or
cursor returns 404. Invalid IDs and page sizes return 400. History is read-only
and includes attempts from every generation, including retired deliveries.

Manual replay is an explicit owner action, not a direct network send. The
endpoint must be enabled. The delivery must have reached `dead` with reason
`failed` after seven completed transport failures in its current generation.
Pending, leased, succeeded, policy-rejected, retired, and pre-migration legacy
dead rows cannot be replayed. A delivery has at most three generations: its
initial seven attempts and two requested replay generations of seven attempts
each. Replay resets only the current generation's queue counter and due time;
all earlier `webhook_attempts` remain immutable audit history. A previous
timeout may already have reached the receiver, so the receiver still must
deduplicate the original `event_id` across every generation.

The caller must reuse the same random UUIDv4 `Idempotency-Key` after an
uncertain response. Repeating a successful request returns HTTP 202 with the
same generation and `created:false`, even if that generation has since run.
Using the same key for another delivery returns 409. An ineligible delivery or
exhausted generation cap also returns 409; absent or malformed keys return 400.
An unknown or another account's endpoint or delivery returns 404. Disable or
rotation permanently marks even previously failed deliveries as retired, so
re-enabling the endpoint cannot revive them. This action can queue work only;
`WEBHOOK_DELIVERY_ENABLED` remains the separate sender gate.

The URL parser accepts HTTPS DNS names on port 443 and rejects IP literals,
userinfo, fragments, local/internal names, and invalid host labels. It runs
on create and enable. The sender separately checks DNS answers and pins the
validated address on every delivery attempt. A network egress firewall remains
required for deployment.

Enabling an endpoint never replays work retired by disable or rotation. Only
inbound events ingested while the endpoint is enabled create new deliveries.
An HTTPS request that already loaded a leased payload may be in flight when
the owner disables or rotates; its result may reach the receiver, but the
retired delivery cannot retry. The receiver must deduplicate `event_id`.

The [operational KEK rotation procedure](../../docs/WEBHOOK-KEK-ROTATION.md)
supports one active and one secondary encryption-key version, with an explicit
bounded database rewrap. It does not change receiver signing secrets. This
contract also defines bounded manual replay. Endpoint deletion and
customer-decryptable sealed content remain outside this slice. The inbound
pilot remains restricted to synthetic or consented test content pending the M2
review.
