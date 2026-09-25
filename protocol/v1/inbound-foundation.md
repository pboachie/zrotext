# Inbound storage contract

This describes the inbound store API. The Android local vault keeps reply bodies on the phone; an opt-in device-stream frame carries signed metadata only. A customer-decryptable sealed envelope is a separate proposed format. Owner endpoint management is described in [webhook-endpoints.md](webhook-endpoints.md). The webhook sender is disabled by default; use synthetic or consented test content.

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
                3 send_unverified, 4 encryption_unverified,
                5 opt_out, 6 opt_out_review, 7 opt_in)
observed_at_ms (signed 64-bit big-endian)
part_count (signed 16-bit big-endian)
content kind (0 metadata_only, 1 opaque_pilot)
SHA-256(content ciphertext, or empty bytes for metadata_only)
```

`opaque_pilot` stores 32–8192 opaque bytes. It makes **no** claim that the bytes
follow a reviewed sealed-content envelope; it must not be exposed as a public
customer content API. No sender phone number or SMS body is a separate database
column. The Android local AES-GCM vault format is not a server upload format.
Migration 029 adds account-scoped recipient suppression. The three opt action
codes carry no plaintext. Their sender is the writer's E.164 recipient from
the authenticated source attempt. START and UNSTOP produce code 7 only when
the phone recognizes the entire trimmed reply; an older action or a reply
from a different outbound-attempt window cannot clear a later opt-out.

The Android Room journal also records a metadata-only local withdrawal for a
recognized STOP or likely opt-out even when no outbound reply window matches.
It stores keyed sender and PDU dedupe tokens, a stable local event UUID and
independent durable sequence, the action, time and any observed subscription
index; it keeps the local recipient block across restarts. The normalized
sender is stored as Keystore AES-GCM ciphertext with AAD bound to the dedupe
token only when the current line can be attributed. If sealing or attribution
fails, the block still persists and the action has no recoverable sender for
later upload. Pre-migration actions likewise have no recoverable sender or sequence. A
verified line ID and binding generation are attached only if a separately
authenticated activation has been installed and the incoming subscription is
the sole observed active subscription at capture time. On Android API 29+, the
app also requires the public card ID to match the approved local binding.
API 30+ queries the complete active subscription list, including hidden
opportunistic subscriptions. API 28 and devices with an unknown card ID keep
the STOP local. Existing subscription-only bindings migrate with no card ID;
they require renewed owner approval before any line-bound attribution or upload.
An explicit foreground Android
mode can prepare and retry a signed `line_opt_out` device-stream frame for a
matching current line and SIM observation. It checks the SIM before decrypting
the sender and again before send, persists the exact signature before sending,
and acknowledges the local row only after writer confirmation.
Unattributed, unsealed, or stale-binding local-only actions are skipped by the
upload queue; their local recipient blocks remain active.
The Android app still has no production activation route, and the writer's
line opt-out transport gate defaults off, so ordinary deployments leave these
rows local.
An unattributed STOP still blocks local sends. START never clears that block;
the existing reply-window START acknowledgement does not prove the source
line or binding generation. Android subscription indexes may be reused after
a SIM swap. The public card ID is a local continuity signal, not carrier
ownership proof; an eSIM profile change on the same card can keep that ID.
API 29 may hide opportunistic subscriptions from the app's active list.

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
source. The same key pair can mount owner endpoint management while delivery
remains off. A missing or malformed key fails startup if delivery is enabled;
an incomplete key pair always fails startup. Do not put the KEK or
endpoint signing secrets in source, images or SQL. The worker can read an
active and a secondary KEK version during an online, two-site rewrap. Follow
the [coordinated rotation procedure](../../docs/WEBHOOK-KEK-ROTATION.md)
before changing either site's active key; do not remove the old secondary key
until both sites and in-flight deliveries have drained.

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

Owner endpoint creation, listing, enable/disable and secret rotation are described in [webhook-endpoints.md](webhook-endpoints.md). Manual replay, Android upload and sealed content have separate contracts and implementation paths.
