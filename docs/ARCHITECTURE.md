# Architecture and contracts

This document describes the gateway architecture and protocol direction. Sections marked as proposed are design references; check the code and releases for implemented behavior.

[MULTI-LOCATION.md](MULTI-LOCATION.md) defines two-site API/hub operation, load balancing, database authority and device-session fencing. The diagram below shows a single-site runtime.

## Runtime

```mermaid
flowchart LR
  SDK[Customer app / local SDK] -->|HTTPS: metadata + sealed body| EDGE[Cloudflare / TLS edge]
  WEB[Dashboard + client crypto] --> EDGE
  EDGE --> APP[Rust application]
  APP <--> PG[(Private PostgreSQL)]
  PHONE[Kotlin Android gateway] <-->|WSS: authenticated claims and events| APP
  PHONE -->|Conventional SMS| CARRIER[Mobile carrier]
  CARRIER --> RECIPIENT[Recipient phone]
  APP -->|Signed ciphertext events| HOOK[Customer webhook + local decryptor]
  STRIPE[Stripe] -->|Verified billing events| APP
```

The current foundation uses an Axum/Tokio application binary with `tokio-postgres` for auth, enrollment and delivery transactions, plus a separate locked migration binary. The planned dashboard uses server-rendered templates, vendored HTMX for non-sensitive interactions, SSE metadata updates and structured redacted tracing. Keep API, device hub, dispatcher, and webhook worker as internal modules until load justifies separate processes. Rust stays on the server first; Android uses Kotlin, Compose, Room and the platform telephony APIs. Do not add UniFFI merely to match the old diagram.

Toolchain and dependency pins are recorded in [DEPENDENCIES.md](DEPENDENCIES.md). Redis, S3, NATS and partitioning are not required by this design; add them only for a demonstrated need. Durable quotas and queue ownership remain authoritative in PostgreSQL.

Source layout:

```text
crates/domain/          # message states, IDs, limits, errors
crates/server/          # API/auth/device hub/worker/billing/dashboard modules
crates/delivery-store/  # PostgreSQL message/attempt/claim transactions
crates/migrator/        # advisory-locked numbered schema migrations
crates/device-sim/      # deterministic fault-injecting test client
protocol/              # versioned JSON schemas, OpenAPI, shared test vectors
android/               # Kotlin app, Room queue, telephony adapter
packages/crypto/       # small browser/TS encryption module, after reviewed spec
packages/sdk-ts/       # permissively licensed API/crypto client
web/                   # Askama templates, static CSS, small TS islands
deploy/compose/        # complete public self-host example
docs/                  # architecture, threat model, runbooks
docs/design/           # public application design specs; marketing source separate
```

Authentication and encryption are separate. The account design uses password verification, verified email, secure HttpOnly SameSite cookies, CSRF protection, session revocation and MFA. TLS protects authentication; it does not make passwords invisible to the server. Store server auth secrets independently of content keys. Content vault unlock uses a separate randomly generated recovery/unlock secret; login reset cannot recover content. OPAQUE would require a separate protocol decision and migration.

## Schema boundaries

Every tenant-owned table includes `account_id`. Use composite foreign keys and repository methods requiring tenant context. PostgreSQL row-level security may be defense in depth only if transaction-scoped identity and connection-pool reset behavior are tested; it cannot replace authorization tests.

| Table | Essential fields / invariants |
|---|---|
| accounts, users, memberships | One owner seat for v1; distinct account/user IDs leave room for teams |
| sessions, recovery_requests | Hashed session tokens, expiry, revoked_at; auth recovery separate from vault |
| api_keys | Public prefix, random 256-bit token verifier, scopes, optional device restriction, expiry, last_used_at |
| devices, device_keys | Owner account, capabilities, current SIM ID, key IDs, enrollment state, revoked_at |
| pairing_requests | One-use hashed secret, 5-minute expiry, short human comparison code, approved key fingerprint |
| messages | UUID, account/device, direction, recipient metadata, envelope bytes/version, expiry, state_version, timestamps |
| message_attempts | Unique attempt ID, claim generation, lease, submitted evidence, per-segment results |
| message_events | Event ID, sequence, observed_at and received_at; eligible terminal history pruned after 90 days by default |
| dispatch_jobs | Message/attempt ID, next_attempt_at, lease_owner, lease_until, fencing generation |
| idempotency_keys | Unique account/key, canonical request digest, message ID; expiry enforced on replay and pruned in batches (7 days by default) |
| usage_periods, usage_ledger | Unique period/metric; transactional reservation/refund references; immutable adjustments |
| webhook_endpoints, webhook_deliveries | Encrypted signing secret, stable event ID, attempts, next_attempt_at; terminal delivery history pruned after 30 days by default |
| inbound_events, sealed_inbound_events | Ciphertext or envelope has a 30-day default window; ID, device sequence and digest remain as replay tombstones |
| subscriptions, billing_events | Provider identifiers, current entitlement period, unique Stripe event ID |
| suppression_entries (proposed, not implemented) | Account/normalized-recipient, source, timestamp; created from device opt-out signal/user action |
| security_audit_events | Key/device/permission changes, redacted subjects, no content |

The durable outbound metering core uses an operator or billing-provisioned
`usage_quota_policies` row per account. `accept_metered` reserves one unit in
the same transaction as idempotency, message and job insertion. The period is
the UTC calendar month at PostgreSQL transaction start; its limit is copied
from policy when that month's row is first created. Replays of the same request
reuse the original reservation even across a month boundary. Pre-grant cancel
or expiry writes one refund entry against the original period in the same
transaction. An issued grant or ambiguous radio state does not refund. Policy
changes during a period need an explicit, audited adjustment path before
billing uses them. The private synthetic-alpha HTTP route still uses unmetered
acceptance and is not a customer billing path.

Index queue due times and `(account_id, created_at DESC, id)`. Cursor pagination only. The retention worker redacts terminal, unfenced message recipients and synthetic payloads after 30 days by default, counted from the last state update. It preserves recipient and request digests, message identity, state and attempts. It removes eligible message events after 90 days, terminal webhook delivery/attempt/replay history after 30 days, and inbound ciphertext after 30 days once related webhook history is gone. M1 inbound event IDs, device sequences, digests and signatures remain as replay tombstones. Sealed inbound envelopes are redacted after 30 days while ID, device sequence and unsigned digest remain. Unknown and fenced outbound messages and their related history/content are deferred. See [self-hosting retention settings](SELF-HOSTING.md#data-retention). Default API body limit 32 KiB; one-recipient SMS; payload cannot exceed six radio segments after decryption. Keep ingress limits before expensive crypto/parsing.

## Message semantics and the duplicate-send problem

```text
accepted → queued → claimed → submitting → submitted → delivered
                    │           │              ├── failed
                    │           └── unknown    └── delivery_unknown
                    └── queued (only with evidence no submit began)
accepted/queued → cancelled | expired | failed
inbound: received → stored → webhook_pending → webhook_acked
```

`submitted` requires a successful Android sent callback; it does not mean delivered. If all required segment delivery callbacks succeed, show `delivered`. If the carrier/device provides no delivery receipt, show `delivery_unknown` after the display timeout while preserving the submission fact. Multipart partial submission has an explicit error/result object; do not resend the entire body automatically.

Exactly-once SMS is not attainable by merely combining an outbox and deduplication. A phone can crash between calling `SmsManager` and persisting its result. Before the call, persist a `submitting` intent with a stable attempt ID. After restart, an unresolved intent is `unknown`; query durable callback/provider evidence if available. **Do not automatically retry an ambiguous radio submission or fail it over to another phone.** Manual resend creates a new message and warns that a duplicate is possible.

Protocol: server leases a job; phone durably stores it, acknowledges, obtains/validates an execution grant, records its local submitting intent, and sends. Bind grants to device, attempt, generation, recipient digest, deadline. Reject expired/stale grants, stale keysets, wrong account, replayed events, and unsupported versions. Lease expiry alone cannot revoke an already executing radio operation. Once an execution grant exists, no other phone receives a replacement until reconciliation proves no submission, or an operator explicitly creates a new attempt. A conservative unknown outcome is preferable to a double send.

Use a valid claim transaction such as:

```sql
WITH next_jobs AS (
  SELECT id FROM dispatch_jobs
  WHERE next_attempt_at <= now()
    AND (lease_until IS NULL OR lease_until < now())
    AND execution_grant_issued = false
  ORDER BY next_attempt_at, id
  FOR UPDATE SKIP LOCKED
  LIMIT $1
)
UPDATE dispatch_jobs AS j
SET lease_owner = $2, lease_until = now() + interval '30 seconds',
    generation = generation + 1
FROM next_jobs WHERE j.id = next_jobs.id
RETURNING j.*;
```

The SQL is illustrative: preserve state/tenant constraints in the real transaction and test concurrent claimers. PostgreSQL does not support the old plan's bare `UPDATE ... ORDER BY ... LIMIT ... SKIP LOCKED` syntax. [SELECT locking](https://www.postgresql.org/docs/current/sql-select.html)

Dispatch must pace each device, allow one radio operation at a time, and bound each account's and device's live queue. An overfull queue rejects new work with retry guidance. The device stream uses periodic heartbeats and reconnects with bounded backoff and event reconciliation. A socket reconnect is not a new send attempt. Current limits are defined in server code and migrations.

## Account and device routes

The server mounts these routes only when `AUTH_ORIGIN`, `AUTH_TOKEN_PEPPER_B64`, and
`ENROLLMENT_TOKEN_PEPPER_B64` are configured. Registration is closed unless a
verification mail transport is configured. Device proof establishes an enrolled
identity for the authenticated device stream.

| Method/path | Current contract |
|---|---|
| POST /v1/auth/register; POST /v1/auth/verify-email; POST /v1/auth/resend-verification | Exact HTTPS Origin; verification code is queued in a durable outbox, never returned by HTTP; resend requires the password and uses a generic response; an unverified sign-up expires 24 hours after registration and a later registration replaces it |
| POST /v1/auth/login; POST /v1/auth/logout; GET /v1/auth/session | Owner session with secure host-only cookie; logout requires Origin and CSRF proof |
| POST /v1/auth/api-keys; DELETE /v1/auth/api-keys/{key_id} | Owner session, Origin and CSRF proof; token shown only at creation |
| POST /v1/enrollment/pairings; GET /v1/enrollment/pairings/{pairing_id} | Owner creates or views a five-minute, one-use pairing |
| POST /v1/enrollment/pairings/{pairing_id}/claim; POST /v1/enrollment/pairings/{pairing_id}/prove | Phone claims pairing and proves its P-256 key through bounded challenge bodies |
| POST /v1/enrollment/pairings/{pairing_id}/approve; POST /v1/enrollment/pairings/{pairing_id}/cancel | Owner compares code and fingerprint, then approves or cancels with CSRF proof |
| POST /v1/enrollment/devices/{device_id}/challenge; POST /v1/enrollment/devices/authenticate | One-use device-key proof; no socket credential is issued |
| DELETE /v1/enrollment/devices/{device_id} | Owner revokes a device with CSRF proof |
| GET /v1/enrollment/devices?before={device_id} | Owner-only cursor page of enrolled device UUIDs, names, revocation status, and `active_socket_lease`; tenant scoped and no-store |
| GET /owner/devices | Same-origin owner sign-in and enrollment page; manual code and fingerprint comparison, CSRF-protected writes, no pairing token in a URL |
| GET /v1/device-stream | Native WebSocket challenge-response with the enrolled P-256 key and writer-owned session epoch. An opt-in controlled-test extension requires a one-shot phone readiness frame and an allowlisted recipient digest. |
| POST /v1/alpha/messages; GET /v1/alpha/messages/{id}; POST /v1/alpha/messages/{id}/cancel | Mounted only with explicit synthetic-alpha account and recipient allowlists. Bearer API key, tenant/device scope and idempotency are required. The server builds a fixed test body from a short case ID; no caller-supplied arbitrary plaintext or recipient appears in the response. Authenticated acceptance attempts are limited to 60 per account and 600 globally per 60 seconds across API keys, devices and API sites. Valid retries also spend attempts; cancellation does not refund them. Exhaustion returns 429 with Retry-After: 60, while budget storage failure returns 503 before message storage. Status and cancellation remain available. This is separate from the planned sealed-content API. |

`active_socket_lease` is an observation of the authoritative writer's current
authenticated device session. It is true only while the lease is unexpired,
the session deployment epoch is current, the hosting site is enabled and not
draining, and the device, key, and account remain active. Reconnection replaces
the device's prior session with a higher connection epoch. A dropped socket can
remain represented until its 90-second lease expires; the page is a snapshot,
not a continuous connection monitor. Approval/revocation and this lease are
separate fields. Neither field establishes Android SMS permission, SIM state,
carrier service, or radio send readiness. The owner API returns 503 rather than
rendering a standby's potentially stale lease state.

## Planned API v1 outline

The following routes remain design targets, not current server behavior.

| Method/path | Contract |
|---|---|
| POST /v1/messages | Header `Authorization: Bearer`, required `Idempotency-Key`; returns 202 and message ID |
| GET /v1/messages/{id} | Tenant-bound metadata, envelope, event timeline according to scope |
| GET /v1/messages | Cursor list; metadata filters; no server plaintext search |
| POST /v1/messages/{id}/cancel | 409 once execution grant/submission makes cancellation uncertain |
| GET /v1/devices | Health, SIM, queue, last event, supported capabilities |
| POST /v1/webhooks | Strict HTTPS URL and egress validation; scoped admin action |
| GET /v1/usage | Quotas, reservations, refunds, reset times, clear units |
| POST /v1/billing/checkout | Server chooses price; owner-only; idempotent |
| POST /v1/billing/portal | Returns Stripe-hosted portal session URL; no arbitrary iframe |
| POST /v1/billing/stripe-events | Raw-body signature validation; dedupe; fast durable acknowledgment |
| GET /healthz; GET /readyz | Minimal public liveness; private detailed readiness |

Public sealed send example (shape only; **not valid ciphertext**):

```json
{
  "device_id": "device_01",
  "to": "+12025550123",
  "expires_at": "2026-09-23T19:15:00Z",
  "envelope": {
    "v": 1,
    "suite": "REVIEWED_SUITE_ID",
    "keyset_version": 3,
    "nonce": "BASE64URL",
    "ciphertext": "BASE64URL",
    "wraps": [{"key_id": "device_key_01", "enc": "BASE64URL", "ct": "BASE64URL"}]
  }
}
```

The SDK accepts readable message text in the customer's process and encrypts it locally. Public REST does not silently accept plaintext under the sealed promise. A future plaintext convenience mode would require an explicit separate product decision and separate claims. No account-wide API key on a phone, no API key in URL/query, and no secrets in QR examples or logs.

Owner browser pages require JavaScript for sign-in. The credential forms use POST as a defensive native fallback; the JSON-only auth endpoints reject form-encoded submissions without creating a session. The device and billing dashboards deny framing. Billing refresh removes the previous snapshot immediately, and an older response cannot restore account data after a newer refresh has failed.

## Android acceptance surface

User-initiated gateway mode, persistent visible notification with Pause, explicit SMS permissions, optional default-SMS role only if implementing the required messaging UI, pairing approval, SIM selection, local history/queue, foreground/background state and diagnostics. The current Android SDK levels are pinned in [the app build](../android/app/build.gradle.kts).

Use P-256 device signing keys in Android Keystore, with capability-tested StrongBox preference and explicit fallback metadata. Content encryption keys are distinct. Android documents a limited StrongBox algorithm set; portable Ed25519 hardware storage cannot be assumed. [Keystore](https://developer.android.com/privacy-and-security/keystore)

Android background execution depends on platform and device policy. `dataSync` is not a perpetual-connection loophole on modern Android. Periodic WorkManager is recovery work, not a real-time heartbeat. APK sideloading does not remove operating-system restrictions. The gateway targets dedicated devices; any wake-only push option would carry no message content. [Timeouts](https://developer.android.com/develop/background-work/services/fgs/timeout) · [WorkManager](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work) · [Play permissions](https://support.google.com/googleplay/android-developer/answer/10208820)

## Webhooks, billing, operations

Webhook stable event ID, creation timestamp, delivery timestamp, attempt ID, ciphertext envelope; HMAC-SHA256 signature over `timestamp + '.' + raw_body`, strict replay tolerance, receiver dedupe. Retry schedule proposal: 1m, 5m, 15m, 1h, 6h, 24h (six retries after initial); endpoint paused after 72 hours of sustained failure, UI/email notice, manual replay within retention. HTTP 2xx is acknowledgment; reject redirects. Bound connect/read timeouts and response bytes. Resolve DNS at connect, validate all chosen IPv4/IPv6 addresses, pin the validated address for the request with correct TLS hostname, block loopback/private/link-local/metadata and rebinding; isolate the worker at network level.

Stripe Checkout and hosted Customer Portal; signed raw-body events, unique event records, reconciliation jobs, and test-mode lifecycle tests. Server-side price allowlist; no client-controlled entitlement flags. [Stripe webhooks](https://docs.stripe.com/webhooks)

Performance measurements should distinguish synthetic sockets, actual connected phones, and end-recipient delivery. API acknowledgment and online dispatch exclude radio and carrier latency.
