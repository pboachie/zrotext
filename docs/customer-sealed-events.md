<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Customer-local opaque sealed events

`sdk/replies/sealed-events.mjs` supplies `SealedEventReceiver` and an unstarted
`createSealedEventServer(receiver, authenticate)` for the selected sealed delivery
candidate. Build the TypeScript SDK first (`cd sdk/typescript && npm ci
--ignore-scripts && npm run build`). The receiver uses Node's built-in SQLite;
the deployment needs a Node runtime supporting `node:sqlite`. Nothing launches
or exposes a listener automatically. Production ingress/TLS, private database
permissions, signing-secret delivery and deployment remain operator concerns.

Each durable database is fixed to one non-nil account, device and SMS-line UUID.
Construction requires a private database path, separate 32-byte webhook and
cursor secrets, and an independently authenticated synchronous `authority`
callback returning `active`, `accountId`, `deviceId`, `lineId`, `revision` and
`expiresAtMs`. The callback must derive these from current trusted owner-selected
scope, not webhook text, an agent prompt, or an API key with unrelated access.
Unavailable, expired, changed or revoked authority fails closed on ingestion,
replay, resume and export; each mutation rechecks current authority before
commit. This callback is a customer integration boundary, not a supplied relay
reader-grant service. It confers no content-reading or sending permission.

`ingest(rawBytes, headers)` authenticates HMAC-SHA256 over Unix-second timestamp,
a dot, and the exact raw body, with a five-minute timestamp window. It accepts
only the nine-field `sealed.inbound_event` contract. Canonical base64, bounded
profile-02 syntax, selected account/device/line, event identity, observed time
and recomputed unsigned SHA-256 must agree. HMAC authenticates the endpoint's
sender; syntax and digest consistency do **not** establish device origin,
manifest acceptance, selected-reader authorization, or successful decryption.
There is no private-key, plaintext, reader callback or automatic decryption API.

An event identity and unsigned/full-envelope fingerprints commit atomically in
SQLite WAL with `synchronous=FULL`. The ledger stores neither envelope bytes,
peer, plaintext nor signing secrets. Restart and retries return `created:false`
for the same exact event, even when `delivery_id` changes; changed ciphertext
or signature under a retained identity conflicts. The metadata ledger defaults
to 4096 entries and eight-day retention (configurable 1–4096 entries and 8–30
days). A full ledger refuses new events rather than evicting live replay fences.
Captures older than seven days are refused. These bounded fences do not promise
indefinite deduplication after retention, backup rollback or deliberate database
replacement. Actual power-loss and customer-filesystem durability are unverified.

`page({consumerId,cursor,limit})` returns at most twenty metadata records with
`content:{kind:'unavailable'}` and `approval:false`. HMAC-protected cursors bind
the database instance, consumer and authority revision, expire after five
minutes and refuse retained-history gaps. They are read checkpoints, not effect
reservations. `exportMetadata()` exports at most the configured retained-entry
cap, requiring current authority. `deny()` persists irreversible denial;
`erase()` deletes retained references and leaves the denied scope tombstone.
Withdrawal requested during an authority callback is locally latched; if the
event transaction rolls back, denial and requested erasure are persisted in a
separate transaction. Storage failure leaves the current receiver denied and
must be resolved before relying on a reopened database tombstone. Owners must
separately erase backups and previously exported records. Reopening
a denied database fails closed; deleting it to reset authority is not supported.

The reused bounded HTTP transport accepts signed `POST /webhook` and separately
authenticated `GET /events`. It sets no-store responses, bounds raw bodies to
64 KiB, headers to 8 KiB and concurrency to four, and uses redacted errors.
`POST /consume` always refuses: this event contains no legacy message/attempt,
reply classification or STOP semantics. It must never be relabeled as
`inbound.message`, owner approval, a recipe reply, or a send instruction. Standalone
users call `expire()` periodically; the listener does so while idle.

The relay still requires independent default-false
`SEALED_WEBHOOK_DELIVERY_ENABLED` and confirmed endpoint selection. No gate,
provider, webhook or radio is activated by this SDK. General unsolicited-upload
consent, manual generational replay, selected-content decryption, agent reply
correlation, hosted deployment, physical devices and carrier delivery remain
outside this bounded implementation.
