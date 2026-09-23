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
| `GET /v1/webhooks` | Lists this account's IDs, URLs, enabled states, and creation times. Never includes signing secrets or encrypted secret bytes. |
| `POST /v1/webhooks/{id}/enable` | Revalidates the HTTPS URL and decryptability of its secret, then enables future inbound fan-out. |
| `POST /v1/webhooks/{id}/disable` | Disables the endpoint and permanently retires its pending and leased deliveries. |
| `POST /v1/webhooks/{id}/rotate` | Generates a new secret, disables the endpoint, and retires pending/leased deliveries. Returns the new secret once. |

The signing secret is 32 random bytes encoded as unpadded base64url in the
create/rotate response. A receiver decodes it to raw bytes for HMAC-SHA256
verification. Only an AES-256-GCM ciphertext, bound to account/endpoint/key
version by authenticated context, is stored. There is no secret retrieval
route. Losing the response requires rotation. The limit is eight endpoints per
account, including disabled endpoints.

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

This contract does not define endpoint deletion, key-version overlap, or customer-decryptable sealed content. Use synthetic or consented test content with the inbound pilot.
