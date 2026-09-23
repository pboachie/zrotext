# Private synthetic-alpha stream extension (in progress)

The authenticated [device stream](device-stream.md) can issue an experimental
single-recipient grant only when the deployment explicitly enables the
synthetic alpha runtime, account and recipient allowlists, and writer dispatch
authority. This is for a controlled test message with a fixed body; it is not
the public customer message protocol. The Android stream client has an opt-in
one-attempt grant, evidence-outbox and radio path. No live WSS or carrier send
has been verified.

All frames are UTF-8 JSON with `v: 1`, exact field sets, and a 4 KiB limit.
The authenticated socket determines the account and device. It never accepts
those identities from a radio event frame.

## One-shot phone readiness

A heartbeat-only phone receives no grant. The test client requires a
local, deliberate one-send arm action and sends this frame only after an
authenticated session and local recipient approval:

```json
{"v":1,"type":"alpha_ready","connection_epoch":1,"recipient_digest":"BASE64URL_NO_PAD_SHA256"}
```

The digest is SHA-256 of the exact locally approved E.164 recipient. The hub
checks the current session and account/recipient allowlists. It consumes this
readiness on the first grant and will not accept a second readiness frame on
that socket. If no matching queued message arrives within five minutes, the
readiness expires and a fresh, manually armed session is required.

## Grant

After one-shot readiness, a current session, and a writer-owned claim for the
matching recipient digest, the hub may send:

```json
{"v":1,"type":"synthetic_grant","message_id":"UUID","attempt_id":"UUID","device_id":"UUID","generation":1,"connection_epoch":1,"deployment_epoch":1,"recipient_digest":"BASE64URL_NO_PAD_SHA256","expires_at_ms":0,"recipient_e164":"+15555550101","body":"ZROtext synthetic test: case_1"}
```

`expires_at_ms` is the writer's grant deadline in Unix milliseconds, not the
message expiry. The digest is SHA-256 of the exact E.164 recipient bytes. The
server checks the current deployment epoch, site, session lease, device,
grant fence, recipient allowlist, and fixed body immediately before sending.
Only one unresolved grant can occupy a device. A second grant is paced at
least 60 seconds after the previous one, including across reconnects.

The phone checks the authenticated session epoch, device ID, positive
generation and deadline, digest, selected SIM, fixed body shape, and its own
locally approved recipient before any radio call. It persists the attempt ID
and one-use radio start before calling `SmsManager`. It never retries a radio call
for the same attempt after an ambiguous return or crash.

## Evidence and acknowledgement

The phone sends one durable event at a time and keeps its `event_id` until the
hub acknowledges it:

```json
{"v":1,"type":"radio_event","connection_epoch":1,"event_id":"UUID","message_id":"UUID","attempt_id":"UUID","evidence":"durable_submit_intent","observed_at_ms":0}
```

Allowed evidence values are `durable_submit_intent`, `proven_no_submit`,
`sent_callback_ok`, `sent_callback_failed`, `delivery_callback_ok`,
`delivery_timeout`, `crash_without_callback`, and `callback_conflict`. A
contradictory callback emits one durable `callback_conflict` event after a
writer-acknowledged submit intent. The writer records `unknown` and retains
the device fence even if earlier evidence said `submitted` or `delivered`.
Sent callback events also
include zero-based `segment_index` and `segment_count` (1–6). No other event
includes segment fields. The phone must reserve the attempt in its durable
local journal, then receive an acknowledgement for `durable_submit_intent`
before calling the radio API. The phone may report
`proven_no_submit` only before any possible radio invocation.

After the writer commits evidence, the hub replies:

```json
{"v":1,"type":"radio_event_ack","event_id":"UUID","state":"submitting","submit_permitted":true}
```

The ack means durable server storage, not carrier submission or delivery.
`submit_permitted` is true only for a `durable_submit_intent` whose grant,
session epoch, writer authority, and deadline remain current after commit.
The phone may call the radio only after receiving that true value and
rechecking the grant deadline and selected SIM. A replay after expiry or a
writer change can be acknowledged with `submit_permitted: false`; it cannot
authorize a late radio call.
After reconnect, the phone can resend the same event ID and identical fields;
the writer returns its prior state. Reusing an event ID with changed evidence
is rejected. An expired grant, socket loss, or absent callback never permits
an automatic second radio attempt. The server keeps an unresolved grant fenced
for reconciliation rather than treating silence as proof of no submission.

The writer's recovery sweep records `grant_timeout` when no submit intent
arrives before the 30-second grant deadline. It records
`sent_callback_timeout` after two minutes without further sent-callback
evidence on a submitting attempt. Both move the message and attempt to
`unknown`, retain the device fence, and never authorize another radio call.
These are server-authored timeline events, not phone event values. A late sent
callback may reconcile `unknown` to `submitted` or `failed`. Queued messages
whose expiry passes before any grant become `expired` in the same recovery
worker. A `submitted` message without a delivery receipt becomes
`delivery_unknown` after 24 hours; a later receipt can still resolve it to
`delivered`.

This extension does not yet provide inbound SMS, delivery-failure
classification, sealed content, or a live tested send/reply path.
