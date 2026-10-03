# Selected opaque conversation-event delivery

This candidate connects existing authenticated conversation capture to a
separate customer outbox. It does not enable capture, provision a reader,
decrypt content, or activate sending. Existing conversation, sealed admission,
account-route and operational sender gates retain their defaults. The independent
`SEALED_WEBHOOK_DELIVERY_ENABLED` gate defaults to false: the selection route is
absent (404) and workers leave sealed deliveries untouched. Both this runtime
gate and each endpoint's explicit encrypted-transfer selection are required.

After configuring and enabling an HTTPS webhook endpoint, the owner explicitly
selects encrypted transfer with
`POST /v1/webhooks/{endpoint_id}/sealed-events`:

```json
{"enabled":true,"encrypted_transfer_confirmed":true,"disclosure_version":"sealed-events-v1"}
```

The existing owner-session, HTTPS origin and double-submit CSRF checks apply.
Unknown fields and API-key substitution are refused. This transfers existing
opaque bytes for the approved reader; it creates no key or reader authority.
Disabling selection or the endpoint, or rotating its secret, atomically removes
its sealed outbox and attempts. Re-enabling affects future captures only.

Verified capture stores exact event bytes and immutable interval provenance,
charges the existing budget and enqueues selected enabled endpoints in one
transaction. Enqueue failure rolls back all three. The account cap is five
selected endpoints and 10,000 pending or leased deliveries. Exact event replay
never adopts new endpoints, duplicates delivery, recreates purged metadata or
rehydrates ciphertext. General uploads without interval provenance queue nothing.

The closed [schema](sealed-event-delivery.schema.json) and
[wire vector](vectors/sealed-event-delivery-01.json) preserve the nine fields in
[the sealed API](sealed-api-v1.md): `v`, `type=sealed.inbound_event`, `event_id`,
`delivery_id`, `account_id`, `device_id`, `observed_at_ms`, `envelope_b64`, and
`unsigned_digest_b64`. No plaintext, peer, part count or credential is added.
HMAC covers exact raw JSON. Receivers enforce the five-minute timestamp window
and deduplicate event identity on every uncertain or repeated attempt.

Each attempt checks current root and reader authority, immutable original
envelope provenance, live line generation, interval, originating owner session,
account, site and deployment. Locks follow manifest, account, interval/line,
endpoint, event and delivery order and remain held through the bounded attempt.
Withdrawal waits behind an already authorized send; a committed earlier
withdrawal prevents sending. Already sent bytes cannot be retracted.

DNS answers are validated and pinned. The existing platform TLS verifier
establishes TLS without signed headers or content. After that await, a fresh
database-clock check precedes the first signed request write, the irreversible
boundary. One deadline bounded by owner/reader expiry, the actual delivery lease
and ten seconds covers connection preparation, partial writes and status reads.
It never renews after waits. No proxy, redirect, resolver fallback, implicit HTTP
retry or response-body read is used. Response headers are bounded; malformed or
informational statuses fail. A network timeout may follow successful receipt.

HTTP 2xx is acknowledged only after the receipt transaction commits. Receipt
storage failure preserves the uncertain lease. Restart closes its attempt as
timeout and retries the same event and delivery identity. Seven attempts use
delays of one minute, five minutes, fifteen minutes, one hour, six hours and
twenty-four hours. Seventy-two hours of sustained transport failure pauses the
endpoint. Enabled selected endpoints continue bounded capture into pending work
while paused; pause blocks attempts, not acceptance. Enable resumes eligible
pending work. Authority refusal is terminal;
storage failure is not permission refusal. Manual generation replay and outbound
status fanout remain unavailable for this outbox.

Retention atomically removes attempts and outbox rows when source ciphertext is
purged; no second content copy exists. Interval withdrawal does the same.
Owner export adds `sealed_event_deliveries`: pages of twenty delivery metadata
records and at most seven attempts each, using `sealed_deliveries_after` as an
account-bound cursor. It contains no signing secret or ciphertext. Existing
conversation inventory supplies opaque event takeout. Account erasure deletes
attempts and deliveries before event, interval and endpoint parents.

Synthetic transaction and stream tests cover rollback, exact bytes, current
authority, withdrawal ordering, expiry before signed write, recovery and receipt
retry. They do not establish carrier delivery, customer deployment, provider
profile approval or production activation. General unsolicited upload consent
remains unavailable.

The reply adapter remains specific to legacy inbound events. The separate
customer-local `sdk/replies/sealed-events.mjs` receiver accepts the exact sealed
wire contract and exposes opaque metadata only. See
[customer sealed events](../../docs/customer-sealed-events.md). It verifies
raw-body HMAC, recomputes the unsigned envelope digest and matches the selected
account/device/line plus event/observed claims using the existing bounded
profile-02 parser. Neither the parser nor webhook HMAC verifies device origin,
an accepted manifest, current reader authority or AEAD content. Assistant
plaintext access remains unavailable. These events carry no legacy message,
attempt or classification fields; receivers must not fabricate them.

Worker lane preference alternates per caller, including batches of one, with
empty-lane fallback and an unchanged total batch bound. The legacy-only worker
API remains unchanged. Controlled ephemeral TLS tests use an explicit synthetic
trust root without changing operating-system trust; they establish handshake
and application-write boundaries, not live customer delivery.

Disabling an endpoint also clears its encrypted-transfer selection atomically.
A legacy re-enable does not renew that selection: a fresh confirmed opt-in is
required, subject to the account's five selected-endpoint cap. Pausing and
resuming an enabled endpoint preserves its existing selection.
