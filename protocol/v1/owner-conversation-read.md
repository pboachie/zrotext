# Owner conversation consent and encrypted reads

Implemented as an **unmounted prerequisite**, not an available phone/browser
conversation. `http_owner_conversations::router` is not registered by the
server. It introduces no runtime flag, radio grant, device upload or send path.

The router uses owner session cookies. API bearer authorization is refused,
including requests that also carry cookies. Mutations require exact canonical
HTTPS Origin and the existing session-bound CSRF cookie/header proof. Content
reads require that same CSRF proof without requiring Origin. Responses carry
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Selecting one conversation

`POST /v1/owner/conversation` accepts a bounded JSON object with `device_id`,
`line_id`, positive `binding_generation`, canonical `peer`,
`disclosure_version: "conversation-content-v1"` and
`content_transfer_confirmed: true`. Unknown fields are rejected. A future UI
must show the actual approved content-transfer disclosure before this action;
the boolean alone is not evidence that a disclosure was presented.

Admission checks the live owner session, active device key, explicitly approved
sealed line, current generation and both activation proofs. One account has
one selected conversation. An active selection cannot be overwritten: withdraw
first, then confirm a new selection. Success is 204; malformed consent is 400,
refused authority is 403 and an existing active selection is 409.

`DELETE /v1/owner/conversation` withdraws the selection and removes its plaintext
peer immediately. It remains usable after device or line revocation. Existing
ciphertext is not deleted by withdrawal. Re-enabling starts a new recorded-time
interval and does not restore access to events timestamped in the old interval.

## Reading protected content

`GET /v1/owner/conversation/events/{event_id}` returns the exact stored verified
candidate-02 envelope with media type `application/vnd.zrotext.sealed.v1`.
Only UUIDs appear in URLs. The server does not decrypt content or export keys.
The event must belong to the owner account, selected device/line/generation,
and selected peer, with both observed and received timestamps at or after
selection. Purged, wrong-peer and unavailable events return 404. Device/key or
line revocation fails closed. Owner role/session/expiry is rechecked after
later lock waits, before content leaves the transaction. At most one bounded
envelope is returned per request.

The sealed-ingest verifier and immutable stored envelope are the cryptographic
admission boundary; this reader parses the already-verified envelope again to
check its selectors. Synthetic tests use signed fixture envelopes with opaque
test ciphertext. They do not prove browser decryption or carrier behavior.

## Mandatory integration gates

- Bind phone capture and server ingest to the same consent interval. Timestamp
  filters do **not** prove post-consent capture: an ahead-of-time phone clock
  can timestamp a queued pre-consent event after selection.
- Enforce current browser recipient-key/trust authority, including revocation,
  before mounting this reader. Browser key custody and secure decryption are
  not implemented by this module.
- Integrate phone-local separate consent and line/SIM continuity, durable
  protected upload, inbound event discovery/pagination, safe text rendering,
  exact-confirmed owner-session send and unknown-outcome handling.
- Reconcile the hosted disclosure, retention configuration, backup deletion
  and export/erasure behavior. The new small consent record cascades with its
  account/membership; existing line/trust tombstones can already block complete
  account erasure. Active consent peer is plaintext metadata; withdrawal clears
  it. Existing sealed-content retention still applies to stored envelopes.
- Verify supported-device capabilities, independent security review, controlled
  physical-device evidence and release custody before claiming feature readiness.

No Google Play eligibility or approval is established by this prerequisite.
