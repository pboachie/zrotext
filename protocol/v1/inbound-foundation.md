# Inbound pilot storage contract (ZT-008 foundation)

This describes a store API, **not an enabled device frame or public route**. The
Android inbound pilot in PR #25 keeps reply bodies in the phone's local vault;
it does not upload them. A device-stream frame, customer-decryptable sealed
envelope, endpoint management, KEK, and SSRF-safe webhook sender still need
separate implementation and review. Synthetic/consented test content only.

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

The future egress worker may use `claim_webhook`, `load_webhook_payload`, and
`finish_webhook`. A claim takes a 30-second lease with `SKIP LOCKED`; an expired
lease becomes a timeout. Success requires HTTP 2xx. Other transport failures
retry after 1 minute, 5 minutes, 15 minutes, 1 hour, 6 hours, then 24 hours;
the seventh failed attempt becomes dead. A policy rejection becomes dead
immediately. Every attempt has a durable row. The lease payload returns the
encrypted secret, not the plaintext secret.

Before a worker can be enabled it must implement operational KEK decryption,
HMAC over `timestamp + '.' + raw_body`, replay window and stable event ID,
HTTPS URL/redirect/DNS/connection-address SSRF checks, response-size/time
bounds, isolated egress, endpoint creation/rotation and manual replay policy.
No network sender or endpoint API is wired in this foundation.
