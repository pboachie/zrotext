# Sealed API v1 message-plane contract

**Proposal only, no route exists.** This document and the companion
[OpenAPI 3.1.0 document](openapi/sealed-v1.json) define the proposed HTTP
surface for the sealed message plane, derived from the ZT-009 decisions
recorded 2026-09-26 ([decision log Q4/Q6/Q8/Q9/Q11](../drafts/zt-009-decision-log.md)).
They are task 21 slice 1: contract first, implementation later. **The sealed
runtime remains disabled**: no production client may emit or accept a
profile-01/02 envelope, no server route is mounted for either endpoint, and
nothing here authorizes one. Every response below is a specified behavior for
a future implementation to satisfy, not a behavior that exists today.

## Purpose

The sealed message plane carries customer message content as opaque binary
envelopes that only the customer's keys can open. The relay stores and
dispatches exact bytes; it never decrypts, never translates, and never accepts
a plaintext alternative. Two endpoints make up slice 1: sealed outbound
submission and sealed inbound upload. Sealed device, webhook and usage
endpoints are DEFERRED to later slices of task 21 and are intentionally absent
from this contract.

## Endpoints

Both operations accept ONLY the exact raw-binary content type
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

## Error taxonomy

Responses use the existing message-route error shape: a JSON object with one
lowercase snake_case `code` and nothing else. The freshness failures trace to
Q4:

| Code | Status | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | The bytes are not a bounded, exactly parsed sealed envelope, or manifest-chain, signing-key/scope or device-signature verification failed. |
| `future_manifest` | 400 | The manifest's `issued_at` is more than five minutes ahead of trusted server time; resubmitting the same bytes will not help until a fresh manifest is pinned. |
| `stale_event` | 400 | Inbound observed time is outside the seven-day observed-time window. |
| `unauthorized` | 401 | Missing, malformed or unknown bearer credential. |
| `forbidden` | 403 | Credential not authorized for the tenant, line or device in the protected record; inactive line binding; revoked or wrong-role key. |
| `stale_manifest` | 403 | The active manifest has expired (lifetime beyond 24 hours, or past its exclusive expiry). Outbound is blocked fail-closed; inbound devices quarantine events locally until a fresh manifest, and the server fails closed on an expired-manifest upload anyway. |
| `re_enrollment_required` | 403 | A device-clock rollback or a restored high-water store was detected; sealed acceptance stays refused until fresh owner-verified enrollment. |
| `idempotency_conflict` | 409 | Outbound: a client-allocated identity was already stored under a different unsigned digest. |
| `event_id_conflict` / `sequence_conflict` | 409 | Inbound conflicting replays under the Q8 fences; the stored event stays authoritative. |
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
authenticated identity and the active line-binding generation. This HTTP
layer only names the tenant: the sealed manifest chain and the device
signature over the exact unsigned bytes carry the cryptographic authorization
(Q2, Q7).

## Boundaries

- **The sealed runtime stays disabled.** No server route exists for either
  endpoint; this contract enables nothing.
- **Synthetic alpha is separate** ([synthetic-alpha-stream.md](synthetic-alpha-stream.md)).
  Sealed credentials are not accepted on `/v1/alpha/*`, alpha credentials are
  not accepted on the sealed routes, and no sealed envelope is ever
  translated into a synthetic-alpha submission (Q11). No endpoint in this
  contract references an alpha path.
- **The general send plane stays closed.** The only existing send route is
  the allowlisted synthetic-alpha test route with a fixed body; sealed
  submission does not open general plaintext sending, and no downgrade flag
  or automatic plaintext retry exists anywhere in this contract (Q11).
- **Devices, webhooks and usage are deferred** to later slices of task 21.
  Envelope status queries, sealed device management, sealed webhook fanout
  (which needs its own ciphertext-only event/delivery contract) and usage or
  metering endpoints are intentionally absent here.

Before any route is enabled, the Q11 seeded synthetic canary sweep across
database, backups, logs, traces, exceptions, crash reports and webhook
retries remains a standing operational requirement, and the per-row evidence
gaps in the decision log stay open.
