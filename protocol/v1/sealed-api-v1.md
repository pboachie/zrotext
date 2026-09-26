# Sealed API v1 contract

**Proposal only, no route exists.** This document and the companion
[OpenAPI 3.1.0 document](openapi/sealed-v1.json) define the proposed HTTP
surface for the sealed API, derived from the ZT-009 decisions
recorded 2026-09-26 ([decision log Q4/Q6/Q8/Q9/Q11](../drafts/zt-009-decision-log.md)).
They are task 21: contract first, implementation later. Slice 1 pinned the
sealed message plane (outbound submission and inbound upload); this revision
adds slice 2, the read-only devices surface, the webhook endpoint-management
and delivery/event surface, and the usage metering query. **The sealed
runtime remains disabled**: no production client may emit or accept a
profile-01/02 envelope, no server route is mounted for any endpoint described
here, and nothing in this document authorizes one. Every response below is a
specified behavior for a future implementation to satisfy, not a behavior
that exists today.

## Purpose

The sealed message plane carries customer message content as opaque binary
envelopes that only the customer's keys can open. The relay stores and
dispatches exact bytes; it never decrypts, never translates, and never accepts
a plaintext alternative. The two message-plane endpoints (slice 1) are sealed
outbound submission and sealed inbound upload. The slice 2 resource groups —
devices, webhooks and usage — are account-scoped metadata, ciphertext fanout
and metering counters only: none of them carries message content, recipients
or plaintext.

## Endpoints

The two message-plane operations accept ONLY the exact raw-binary content type
`application/vnd.zrotext.sealed.v1`. The request body is one complete sealed
envelope: at least 426 bytes, at most 34,213 bytes for outbound kind 01 and
34,082 bytes for inbound kind 02, bounded by the 36,864-byte pre-allocation
cap. Every response is JSON metadata with `Cache-Control: no-store` and never
echoes envelope bytes. The machine-readable surface, including the full error
taxonomy, is the [OpenAPI document](openapi/sealed-v1.json); the semantics
below trace each rule to its recorded decision.

### `POST /v1/sealed/messages` — sealed outbound submission

The caller submits one sealed outbound envelope for device dispatch. The relay
verifies the owner-pinned manifest chain, the allowed device signing key and
scope, and the device signature over the exact unsigned bytes, and compares
the protected account/device/line/manifest fields with the authenticated
identity and database state before any effect (Q7). Acceptance (`202`) means
durable storage of the exact bytes and queueing toward the bound device; it
never means carrier submission.

Idempotency is the SHA-256 digest of the **unsigned** envelope bytes (Q6):
replaying byte-identical unsigned content returns the stored message identity
with `created: false` and dispatches nothing new. No caller-supplied
`idempotency-key` header is accepted. A client-allocated identity already
stored under a different digest fails with `409 idempotency_conflict`.

### `POST /v1/sealed/inbound-events` — sealed inbound upload

This is the separate sealed inbound route required by Q8. It writes the
separate `sealed_inbound_events` store (see
[sealed-inbound-prerequisites.md](sealed-inbound-prerequisites.md)) and is
never routed through the M1 outbound-attempt inbound pilot. The phone
allocates one stable 16-byte `event_id` for the normalized logical SMS,
journals text, event ID and a positive device-local sequence **before**
sealing, and retries replay the exact envelope bytes. The server compares the
`(account, device, event_id)` identity and the `(device, device_sequence)`
replay fence against the unsigned digest:

| Arrival | Result |
| --- | --- |
| New event, in order | `202` with `created: true` |
| Identical replay: same `(account, device, event_id)` and same unsigned digest | `202` with `created: false` (no-op) |
| Same `event_id`, different unsigned digest | `409 event_id_conflict` |
| Reused `(device, device_sequence)` under a different event | `409 sequence_conflict` |
| Out-of-order arrival inside the seven-day observed-time window | `202` accepted |
| Observed time outside the seven-day window | `400 stale_event` |

Tombstone retention is an operational constraint of this contract: event-ID
and device-sequence tombstones must be retained **at least eight days** after
first acceptance (Q8). Deleting an accepted row without a separate durable
event-ID and device-sequence high-water fence would permit replay; ciphertext
may be purged earlier, the fence may not.

## Devices (proposed)

`GET /v1/sealed/devices` and `GET /v1/sealed/devices/{device_id}` are a
read-only projection of the owner enrollment view onto the sealed API-key
plane, gated by the existing `devices:read` scope. Each device carries
`device_id`, the owner-assigned `display_name`, `revoked`, the
`active_socket_lease` snapshot observation, and `lines`: the device's
sealed-purpose line bindings as `line_id`, `binding_generation` and `state`
(`pending`/`active`/`revoked`). The list pages by cursor exactly like the
owner route `GET /v1/enrollment/devices`: pass the returned `next_cursor` as
`before`; `next_cursor` is null after the last page.

Design boundaries of this surface:

- **Read-only.** Enrollment, owner approval, re-keying and revocation stay on
  the owner-session enrollment routes; the sealed surface cannot mutate trust
  state because the Q1/Q4 ceremonies are out-of-band owner actions. A single
  device is fetched by ID, and an unknown device and another account's device
  are both `404 not_found`.
- **No telephony identifiers.** No SIM identifier, phone number, ICCID, IMSI,
  Android subscription ID or key material appears in any field. A phone line
  is a stable owner-assigned identity, never a slot or subscription ID.
- **`active_socket_lease` is a snapshot, not a monitor.** It observes the
  authoritative writer's authenticated device session (unexpired lease,
  current session epoch, enabled site) and can stay represented for up to 90
  seconds after a dropped socket. It establishes neither SMS permission, SIM
  state, carrier service nor radio readiness, and sealed-mode eligibility
  (Android API 31+, Q5) is a property the owner verifies at enrollment — this
  surface reports stored state only.

## Webhooks (proposed)

The webhook surface projects the owner-session lifecycle
([webhook-endpoints.md](webhook-endpoints.md)) onto API-key authentication:
reads need `webhooks:read`, and create, replay, enable, disable and rotate
need `webhooks:manage`. The lifecycle rules are the owner contract's rules:
create returns a disabled endpoint plus the 32-byte `signing_secret_b64url`
exactly once (only an AES-256-GCM ciphertext bound to account, endpoint and
key version is stored; there is no retrieval route); at most eight endpoints
per account (`409 endpoint_limit`); enable revalidates the URL and the
secret's decryptability; disable and rotate permanently retire pending,
leased and replayable failed deliveries; delivery history pages by
`limit` (1–20) and `before`/`next_before` with per-attempt audit metadata and
no payload, secret, receiver response body, recipient or content; and manual
replay requires a caller-generated UUIDv4 `Idempotency-Key`, an enabled
endpoint, and a delivery that is `dead` with `terminal_reason` `failed` after
seven completed transport failures, with at most three generations per
delivery (`409 replay_not_eligible` / `replay_limit`).

Delivery and event semantics under the sealed profile:

- **Ciphertext-only fanout.** The sender POSTs one
  `SealedWebhookEventBody` per accepted sealed inbound event: JSON metadata
  (`v`, `type` `sealed.inbound_event`, `event_id`, `delivery_id`,
  `account_id`, `device_id`, `observed_at_ms`) plus `envelope_b64` — the
  exact stored sealed envelope bytes — and `unsigned_digest_b64`, the
  SHA-256 digest of the unsigned envelope bytes that identifies the
  admission. The relay never decrypts, never synthesizes plaintext, and never
  substitutes synthetic-alpha content (Q11). No route sends a test webhook.
- **Signature and replay tolerance.** Deliveries carry `x-zrotext-timestamp`
  (ASCII Unix seconds) and `x-zrotext-signature`
  (`v1=` + lowercase hex of HMAC-SHA256 over `timestamp || '.' ||` the exact
  raw body, keyed by the endpoint signing secret). Receivers enforce a
  five-minute timestamp window and deduplicate `event_id` across every
  generation, because a timed-out attempt may already have reached them.
- **Bounded retries and pause.** HTTP 2xx acknowledges; redirects are
  rejected; connect/read timeouts are bounded. The retry schedule per
  generation is 1m, 5m, 15m, 1h, 6h, 24h (seven attempts); 72 hours of
  sustained transport failure pauses the endpoint (`paused_at_ms`,
  `failure_started_at_ms` visible in the list) while pending deliveries stay
  queued; enable resumes them. Actual sending stays behind the separate
  operational sender gate.
- **Sealed outbound dispatch-status fanout is not defined here.** Only
  accepted sealed inbound events fan out in this slice; status events for
  outbound envelopes are deferred with the message status queries.

## Usage (proposed)

`GET /v1/sealed/usage` (existing `billing:read` scope) returns the current
UTC calendar-month metering snapshot from the durable usage core
(`usage_periods` and `usage_ledger`): `metric`, `period_start`,
`period_end` (the exclusive reset boundary), `limit_units`,
`reserved_units`, `refunded_units` and the derived `used_units`
(`reserved − refunded`). Sealed outbound acceptance meters exactly one unit
per accepted sealed envelope, reserved in the same transaction as admission;
an idempotent digest replay reuses the original reservation and never
reserves a second unit, even across a month boundary. Refunds exist only
through the existing pre-grant cancellation/expiry path and are written
against the original period — whether sealed messages expose cancellation at
all is deferred with the message status queries. Units are integer message
counts, never currency or pricing. History queries beyond the current period
and per-device or per-line breakdowns are deferred.

## Error taxonomy

Responses use the existing message-route error shape: a JSON object with one
lowercase snake_case `code` and nothing else. The freshness failures trace to
Q4:

| Code | Status | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | The bytes are not a bounded, exactly parsed sealed envelope, or manifest-chain, signing-key/scope or device-signature verification failed. On resource routes: malformed IDs, cursors, page sizes, JSON bodies or a missing/invalid replay `Idempotency-Key`. |
| `invalid_webhook_endpoint` | 400 | A webhook callback URL failed the strict HTTPS egress validator (create, or enable when the stored URL no longer passes). |
| `future_manifest` | 400 | The manifest's `issued_at` is more than five minutes ahead of trusted server time; resubmitting the same bytes will not help until a fresh manifest is pinned. |
| `stale_event` | 400 | Inbound observed time is outside the seven-day observed-time window. |
| `unauthorized` | 401 | Missing, malformed or unknown bearer credential. |
| `forbidden` | 403 | Credential not authorized for the tenant, line or device in the protected record; inactive line binding; revoked or wrong-role key; or a resource operation whose scope the credential lacks. |
| `not_found` | 404 | Resource routes: no such device, endpoint, delivery or cursor in this account. Unknown and cross-account resources are indistinguishable. |
| `stale_manifest` | 403 | The active manifest has expired (lifetime beyond 24 hours, or past its exclusive expiry). Outbound is blocked fail-closed; inbound devices quarantine events locally until a fresh manifest, and the server fails closed on an expired-manifest upload anyway. |
| `re_enrollment_required` | 403 | A device-clock rollback or a restored high-water store was detected; sealed acceptance stays refused until fresh owner-verified enrollment. |
| `idempotency_conflict` | 409 | Outbound: a client-allocated identity was already stored under a different unsigned digest. |
| `event_id_conflict` / `sequence_conflict` | 409 | Inbound conflicting replays under the Q8 fences; the stored event stays authoritative. |
| `endpoint_limit` | 409 | Webhook create: the account already has eight endpoints, including disabled ones. |
| `replay_not_eligible` / `replay_limit` | 409 | Webhook replay: the delivery is not an exhausted failed generation, the endpoint is disabled, or the `Idempotency-Key` was used for another delivery; or the delivery already used all three generations. |
| `unsupported_media_type` | 415 | The request did not use exactly `application/vnd.zrotext.sealed.v1`. A JSON body, a multipart body or any other content type is rejected and is never parsed as an envelope, translated to the synthetic-alpha route, or retried as plaintext. |
| `rate_limited` / `queue_full` / `quota_exceeded` | 429 | Sealed admission budget exceeded. |
| `billing_pending` / `unavailable` | 503 | Temporary storage or dispatch unavailability; retry later with the exact same bytes. |

These codes are response descriptions for a future implementation, not
implemented behavior. Nothing here is enforced today.

## Content constraints (Q9)

The plaintext inside the ciphertext is a strict UTF-8 body of **1–32,768
bytes** with **no BOM, no NUL, no Unicode normalization and no padding** in
v1. "No normalization" means visually identical strings can be distinct bytes.
Body length, recipient, timing and segment-count leakage is disclosed and
accepted; the phone refuses more than six segments before creating a submit
intent. The relay cannot check these constraints — it never sees the
plaintext — so they bind the sending client and the parsing profile, and a
future implementation must reject envelope-level bound violations at
admission.

## Authentication

The endpoints use the existing customer API-key authentication, not a new
auth model: an account API key issued by the owner API-key routes under
`/v1/auth` and sent as `Authorization: Bearer <key>`, exactly as the existing
message routes authenticate. Outbound submission requires the existing
message-send scope bound to the device named in the envelope's protected
record; inbound upload requires a credential authorized for the uploading
device, and the protected account, device and line fields must match the
authenticated identity and the active line-binding generation. The slice 2
resource operations reuse the existing scope set and add no new scopes:
devices list/status needs `devices:read`, webhook reads need
`webhooks:read`, webhook management (create, replay, enable, disable,
rotate) needs `webhooks:manage`, and the usage query needs `billing:read`.
API keys never unlock content: no scope grants decryption, plaintext access
or envelope bytes beyond the exact bytes a caller itself submitted. This HTTP
layer only names the tenant: the sealed manifest chain and the device
signature over the exact unsigned bytes carry the cryptographic authorization
(Q2, Q7).

## Boundaries

- **The sealed runtime stays disabled.** No server route exists for any
  endpoint in this contract; it enables nothing.
- **Synthetic alpha is separate** ([synthetic-alpha-stream.md](synthetic-alpha-stream.md)).
  Sealed credentials are not accepted on `/v1/alpha/*`, alpha credentials are
  not accepted on the sealed routes, and no sealed envelope is ever
  translated into a synthetic-alpha submission (Q11). No endpoint in this
  contract references an alpha path, and no webhook delivery carries
  synthetic-alpha content.
- **The general send plane stays closed.** The only existing send route is
  the allowlisted synthetic-alpha test route with a fixed body; sealed
  submission does not open general plaintext sending, and no downgrade flag
  or automatic plaintext retry exists anywhere in this contract (Q11). The
  devices, webhooks and usage operations are metadata, ciphertext-fanout and
  metering surfaces: none accepts or returns message content or recipients.
- **Still deferred:** sealed envelope status queries and cancellation for
  submitted messages, sealed outbound dispatch-status webhook fanout, usage
  history beyond the current period, per-device or per-line usage
  breakdowns, and any device enrollment or revocation through the sealed
  plane (those stay on the owner-session enrollment routes).

Before any route is enabled, the Q11 seeded synthetic canary sweep across
database, backups, logs, traces, exceptions, crash reports and webhook
retries remains a standing operational requirement, and the per-row evidence
gaps in the decision log stay open.
