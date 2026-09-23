# Inbound pilot storage contract (ZT-008 foundation)

This describes a store API, **not an enabled device frame or public route**. The
Android inbound pilot in PR #25 keeps reply bodies in the phone's local vault;
it does not upload them. An opt-in device-stream frame carries signed metadata
only; Android upload, a customer-decryptable sealed envelope, and endpoint
management still need separate implementation and review. The webhook sender
is disabled by default. Synthetic/consented test content only.

`inbound::ingest` accepts an event only through an enrolled device's current
writer session. It checks the tenant/device, site and instance, connection and
deployment epochs, live lease, active key/account/site, device P-256 signature,
and a matching same-device outbound attempt with positive sent evidence.
Source fields are bounded: sequence is positive, timestamp is at most seven
days old or five minutes ahead, and multipart count is 1–6. An event ID replay
with an identical digest returns the existing event. Reusing an event ID with
different signed data or reusing a device sequence is rejected. The database
also uses composite tenant foreign keys.

The device signature is `SHA256withECDSA` over these exact bytes, in order:

```
ASCII "zrotext-inbound-v1\0"
account UUID (16 raw bytes)
device UUID (16 raw bytes)
event UUID (16 raw bytes)
sequence (signed 64-bit big-endian)
outbound message UUID (16 raw bytes)
outbound attempt UUID (16 raw bytes)
classification (1 captured_local, 2 sim_unverified,
                3 send_unverified, 4 encryption_unverified)
observed_at_ms (signed 64-bit big-endian)
part_count (signed 16-bit big-endian)
content kind (0 metadata_only, 1 opaque_pilot)
SHA-256(content ciphertext, or empty bytes for metadata_only)
```

`opaque_pilot` stores 32–8192 opaque bytes. It makes **no** claim that the bytes
follow a reviewed sealed-content envelope; it must not be exposed as a public
customer content API. No sender phone number or SMS body is a separate database
column. The Android local AES-GCM vault format is not a server upload format.

Migration 007 follows metering migration 006 and adds `inbound_events`,
`webhook_endpoints`, `webhook_deliveries`, and `webhook_attempts`. Endpoint rows
default disabled. Only KEK-encrypted signing secrets belong in the endpoint
table. Ingest atomically queues one delivery per currently enabled endpoint.
The same event cannot queue a second delivery for an endpoint.

The opt-in egress worker uses `claim_webhook`, `load_webhook_payload`, and
`finish_webhook`. A claim takes a 30-second lease with `SKIP LOCKED`; an expired
lease becomes a timeout. Success requires HTTP 2xx. Other transport failures
retry after 1 minute, 5 minutes, 15 minutes, 1 hour, 6 hours, then 24 hours;
the seventh failed attempt becomes dead. A policy rejection becomes dead
immediately. Every attempt has a durable row. The lease payload returns the
encrypted secret, not the plaintext secret. `WebhookSecretVault` seals a 32–256
byte endpoint signing secret with an externally supplied 32-byte AES-256-GCM
KEK, random 96-bit nonce, and authenticated account/endpoint/key-version
context. It rejects cross-tenant moves, version mismatch and tampering.

`WEBHOOK_DELIVERY_ENABLED` defaults to off. To start the worker, set it to
`true`, supply `WEBHOOK_KEK_VERSION` as a positive integer and
`WEBHOOK_KEK_B64` as a base64-encoded 32-byte key from an external secret
source. A missing or malformed key fails startup. Do not put the KEK or
endpoint signing secrets in source, images or SQL. This worker accepts one
key version at a time; pause delivery and reseal existing endpoint secrets
before a version change. Automated rotation is not implemented.

The JSON body has a stable `event_id`, delivery/account/device/message/attempt
IDs, classification, timestamp, part count, content kind, base64 opaque
ciphertext when present, event digest, and device signature. It contains no
separate phone number or plaintext SMS body. `x-zrotext-timestamp` is Unix
seconds. `x-zrotext-signature` is `v1=` plus lowercase hex HMAC-SHA256 over
ASCII timestamp, one dot, then the exact raw JSON body. Receivers must check
a short clock window and deduplicate `event_id`.

Before each HTTPS POST, the sender rejects local names/IP literals and
nonstandard ports, resolves DNS, rejects any unsafe address, pins the accepted
answer for that single request, disables redirects/proxies/automatic retries,
and bounds connection and request time. It does not read the response body.
Only HTTP 2xx is an acknowledgement. URL or unsafe-address failures dead
letter; unavailable DNS/transport and other HTTP statuses follow the bounded
retry schedule. The sender needs an independent network egress firewall in a
deployment; application validation alone is not a complete SSRF boundary.

No endpoint API, secret rotation, manual replay route, Android upload frame,
or customer-decryptable sealed-content protocol is wired. These are separate
gates before public inbound/webhook use.
