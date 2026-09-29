# Device stream v1: authenticated session

This is the authenticated phone-to-hub handshake. A public endpoint must use
WSS. The Android client requires an approved device UUID and a `wss://` URL
ending in `/v1/device-stream`. A dedicated Android phone completed an
authenticated session and fresh proof after a disposable local TLS proxy
close; a separate revocation probe stopped the client. The guarded
[synthetic-alpha extension](synthetic-alpha-stream.md) completed one
separately authorized outbound test SMS with positive sent and delivery
callbacks. These bounded tests do not establish production TLS or general
carrier reliability.

1. Phone sends `{"v":1,"type":"hello","device_id":"UUID"}`.
2. Hub returns `{"v":1,"type":"challenge","challenge_id":"UUID","account_id":"UUID","device_id":"UUID","nonce":"BASE64URL_NO_PAD"}`. The nonce is 32 opaque bytes derived from the hub's enrollment pepper, the account, the device, and the challenge UUID; the challenge UUID also carries the issuance time, so a challenge is verifiable for 60 seconds. No database row is written and no per-device budget is spent at this step.
3. Phone signs the exact byte string below with its enrolled, non-exportable
   P-256 Android Keystore key using `SHA256withECDSA`. The signature is DER.
   It returns `{"v":1,"type":"proof","challenge_id":"UUID","account_id":"UUID","device_id":"UUID","nonce":"BASE64URL_NO_PAD","signature_der":"BASE64URL_NO_PAD"}`.
4. The writer re-derives the nonce from the pepper, rejects challenges past
   their window, checks the enrolled key, active device/account, enabled
   site, and deployment epoch, and increments the
   device session epoch. Hub returns
   `{"v":1,"type":"session","connection_epoch":1,"heartbeat_seconds":30}`.
5. Phone sends `{"v":1,"type":"heartbeat"}` every 30 seconds. The hub
   renews the writer-owned lease only while that epoch remains current and
   replies `{"v":1,"type":"heartbeat_ack","connection_epoch":1}`.

Signed bytes are ASCII `zrotext-device-auth-v1` followed by a single zero
byte, the raw 16-byte account UUID, raw 16-byte device UUID, raw 16-byte
challenge UUID, and the raw 32-byte nonce. UUID bytes use network order.
The JSON text itself is not signed. Both clients must reject a changed
challenge ID, account, device, nonce, version, or epoch. Base64url values
have no padding. Client frames reject unknown fields; frames are limited to
4 KiB and the hello/proof steps to 10 seconds each. The whole handshake, from
the upgrade request until the proof is verified, is limited to 15 seconds.
A hub answers the upgrade with HTTP 503 while its handshake or session
capacity is full; unauthenticated sockets do not use session capacity.

Challenge issuance and proof verification each spend an anonymous PostgreSQL
request budget of 300 attempts globally per 60 seconds, across all hub
instances. When it is exhausted, a hello naming an enrolled, live device and
a proof that verifies are still admitted through a separate verified budget
of 3,000 attempts per 60 seconds that made-up device IDs and failed proofs
never reach. One device ID may use at most 60 hellos per 60 seconds of the
verified budget, so traffic naming one known device ID can delay only that
device, never the others. There is deliberately no anonymous per-device
budget: the device ID is public, so a counter keyed to it could be spent by
anyone who knows it and would let an unauthenticated caller keep the enrolled
phone's handshake refused without any other traffic. The hub closes the
socket with code `1013` (Try Again Later) when
both budgets for a step are exhausted or its storage is unavailable; the
phone retries with backoff and the window rolls over within a minute.
A proof must echo the challenge issued on the same connection; a proof for
any other challenge, including one from an earlier connection, closes the
socket with a policy violation. Reconnecting or switching transports
does not reset a budget. Established
session heartbeats do not consume these handshake budgets.

The hub renews the lease in PostgreSQL on the first heartbeat of a session
and then at most once every 15 seconds (half of `heartbeat_seconds`); a
heartbeat that arrives sooner is acknowledged with the same
`heartbeat_ack` frame without a storage round trip. Independently, the hub
checks session status against PostgreSQL at most 10 seconds apart, so a
revoked or fenced session closes within that check even when its latest
heartbeat was acknowledged from memory. A successful lease renewal or
`device_status` write checks the same conditions, so it counts as one of
these checks and the next standalone check is due 10 seconds after it. More than 60 heartbeats within one
minute close the session with `1008` (Policy Violation). A new valid
connection fences the older epoch; release of an old socket cannot clear the newer lease. A drained,
disabled, revoked, or writer-isolated hub closes its session. The phone stops
its foreground heartbeat on authentication, trust, or protocol rejection.
Before a session is established, the hub closes with `1008` (Policy Violation)
for a malformed frame, invalid proof, or unknown or revoked device. It closes
with `1013` for database failures, admission budget refusal, an exceeded
handshake deadline, full session capacity, a draining site, or an unavailable
writer. The phone retries `1011`, `1012`, and `1013` with
bounded backoff even before a session; `1008` and unknown pre-session codes
stop the foreground service. A pre-session close without a code is treated as
a rejection.
While the manually started foreground service remains alive, transport loss,
an established session's close, or a heartbeat timeout can retry with bounded
backoff and a fresh challenge proof and epoch. A manual synthetic-SMS arm or
inbound-upload opt-in is consumed before retry; a reconnect is heartbeat-only.

After authentication, the writer closes with `4409` when a submitted
`radio_event` or `inbound_event` is permanently invalid for the current
session. This includes a stale attempt fence after the writer has retired an
old event ID. The phone durably quarantines that one local row and reconnects
for heartbeat-only service; it never interprets the rejection as permission
to send an SMS. A writer-side storage failure closes with `1013` and leaves
the row eligible for retry. For older writers that close without a code, three
immediate authenticated closes while the same row is outstanding trigger the
same quarantine. If the phone cannot persist quarantine, it pauses the
foreground service for repair.
An inbound reply that arrives before its matching positive sent callback is
available at the writer receives `1013`, so the signed inbound row can retry
after the radio callback is uploaded. A missing or foreign attempt remains a
permanent rejection.

Every queued radio event and inbound upload is bound at capture to the
account UUID, device UUID, and a SHA-256 hash of the WSS origin. A session
filters on all three values. Re-pairing or changing the server quarantines
unacknowledged rows from another identity before an upload pump selects them.
Pre-upgrade rows without an identity remain local and are never sent by a new
session. The hash is a routing guard, not a trust anchor or a replacement for
TLS verification.

Pause, force-stop, service/process stop, and reboot do not self-start the
client. A Samsung loopback proxy-close/reconnect probe passed. Neither a
session nor a heartbeat authorizes SMS.

## Opt-in inbound metadata pilot (Android client)

A distinct, default-off `line_opt_out` frame accepts signed STOP/review
metadata without an outbound attempt when `LINE_OPT_OUT_ENABLED=true`. It
requires a current active line binding and never clears suppression or sends
an SMS. See [the line-bound opt-out contract](line-opt-out-contract.md).

Default-off `sms_line_challenge`, `sms_line_proof`, `sms_line_proof_ack`, and
`sms_line_activated` frames carry SMS line activation when
`SMS_LINE_ACTIVATION_ENABLED=true`. They bind a line to this device only after
the owner approves the device's signed declaration; none authorizes an SMS. The
hub polls the exchange every 3 s while frames are flowing and every 30 s while
the device has no open exchange; opening a challenge on the same hub instance
wakes the sockets immediately, and another instance's sockets see it within one
idle poll. See
[the SMS line activation contract](sms-line-activation-contract.md).

The Android app exposes a separate **Start inbound metadata pilot** action. It
is off by default. The hub must separately enable `INBOUND_PILOT_ENABLED=true`.
After authenticated session setup, the phone sends previously captured
`captured_local`, `opt_out`, `opt_out_review`, and `opt_in` events from a
trusted reply window. It does not transmit the sender address, SMS body, PDU,
or the local AES-GCM vault ciphertext. This pilot does not expose reply content
to customers and has not passed a live WSS interoperability test.

The client frame is
`{"v":1,"type":"inbound_event","connection_epoch":1,"event_id":"UUID","sequence":1,"message_id":"UUID","attempt_id":"UUID","classification":"captured_local","observed_at_ms":1700000000000,"part_count":1,"signature_der":"BASE64URL_NO_PAD"}`.
An optional, unsigned `"device_sent_at_ms"` carries the phone clock when the
frame is sent. The hub stores it only within a day of its own clock. Before an
owner opt-out hold is released, it also requires the START, corrected by the
phone's measured offset, to be more than a minute after the hold; it never
loosens the five-minute margin. It is outside the signature, the event digest
and replay identity. Send it only to a
hub that accepts it, because older hubs reject unknown fields.
The enrolled P-256 key signs the `zrotext-inbound-v1` domain-separated bytes
described by the server inbound foundation, with content kind 0 and SHA-256 of
empty bytes. Room reserves a positive auto-incremented sequence for each
captured event and persists its DER signature before the first send. One frame
is outstanding at a time; it replays after 30 seconds without acknowledgment
or immediately in a newly authenticated session. Only a matching
`{"v":1,"type":"inbound_event_ack","event_id":"UUID","created":true,"queued_deliveries":0}`
marks the row acknowledged locally. Observations older than six days remain
local because the hub rejects them after seven days. Android never interprets
this acknowledgment as authorization to send an SMS.

Phone-side retention runs at app start and daily: acknowledged or quarantined
radio events, inbound events and uploads, terminal SMS attempts and
acknowledged STOP upload records older than seven days are deleted with their
children, and an inbound event's locally encrypted body is nulled in the same
transaction as its acknowledgment. Anything unacknowledged or ambiguous, and
every local STOP block (`local_recipient_suppressions`, binding-less
withdrawal records), is never pruned.

## PROPOSED optional frame: `sealed_execution_grant` v1 (roadmap #539)

**Status: PROPOSED.** This versioned, optional extension is a design proposal
for review. No hub emits either frame below, no client offers the negotiation,
the Android executor that consumes the grant is dormant (nothing calls it), and
the sealed runtime stays disabled end to end. The schema and shared vectors are
[`vectors/sealed-execution-grant.schema.json`](vectors/sealed-execution-grant.schema.json)
and [`vectors/sealed-execution-grant-01.json`](vectors/sealed-execution-grant-01.json).

### Negotiation and old clients

The frame is optional metadata on the existing stream, negotiated like the
[device preconditions](device-preconditions.md): a phone that implements and
has enabled sealed dispatch would offer the combined token
`zrotext-device-status-v2+sealed-dispatch-v1` ahead of its existing
`Sec-WebSocket-Protocol` offer, and a hub may send the frame only on a session
where it selected that token. No current phone offers it and no hub selects
it. The hub must never send the frame on any other session, and the server
has no emitter for it in any flag state; a later server slice may add one only
dormant and default-off behind the existing sealed flags
(`SEALED_ADMISSION_ENABLED`).

A phone that did not negotiate the extension must ignore the frame. From this
change on, the Android client drops a `sealed_execution_grant` frame unparsed,
with no Keystore use, no journal row and no session teardown. Clients released
before this change treat any unknown frame type as a protocol error and close
the session; that is fail-closed (no decrypt, no journal, no radio) but not
silent, which is why the hub must never send the frame without negotiation.

### Grant frame (hub to phone)

One frame per attempt, inside the authenticated session:

```json
{"v":1,"type":"sealed_execution_grant","grant_version":1,
 "account_id":"UUID","device_id":"UUID","line_id":"UUID",
 "message_id":"UUID","attempt_id":"UUID",
 "connection_epoch":1,"deployment_epoch":1,
 "binding_generation":1,"attempt_generation":1,
 "reader_role":1,"reader_key_id":"BASE64URL_32_BYTES",
 "envelope_sha256":"BASE64URL_32_BYTES","unsigned_sha256":"BASE64URL_32_BYTES",
 "expires_at_ms":1700000015000,"segment_count":1}
```

`grant_version` versions the grant independently of the stream's `v`. Fields
are exact: unknown or missing fields, non-integer numbers, non-canonical
(uppercase) UUIDs, padded or wrong-width base64url and any `grant_version`
other than 1 reject the whole frame. The frame carries no recipient, body,
envelope bytes or key material. `reader_role` is the profile-02 wrap role the
grant authorizes; `reader_key_id` is the key ID of that reader.
`segment_count` is the most SMS parts the grant authorizes.

Sealed envelopes are 426..34,213 bytes against this stream's 4,096-byte frame
budget, so the envelope bytes never ride the stream. The phone fetches the
exact bytes by digest over the authenticated HTTPS API, outside this stream.
Binary WebSocket frames (this stream rejects them) and chunked base64 text
frames (more frames and a larger replay surface) were considered and rejected
for v1. The fetch route is part of this proposal and is not specified or
implemented yet.

### Phone rules (binding)

The phone never decrypts unless every check passes, in this order, each
fail-closed:

1. The fetched envelope passes the sealed-v1 profile-02 outbound parser
   (length caps, profile and kind bytes, protected length, wraps) before the
   grant is consulted, so a malformed envelope never consumes a grant.
2. The grant binds, against the authenticated session, the active local line
   binding, the phone's own Keystore payload key and the routing identity the
   envelope claims: account, device, line and binding generation, message
   (non-zero attempt), `reader_role` = 1 (device payload; the archive and
   integration roles are refused), `reader_key_id` = the phone's own key and
   the envelope's device wrap, connection and deployment epochs, the SHA-256
   of the exact fetched bytes, a trusted-time expiry in the future and at most
   35 seconds ahead, and 1..6 segments.
3. Only then does the phone enter the existing candidate preparation: it
   authenticates the envelope signature and manifest authority against the
   grant's message, journals the attempt in `sealed_preparations` before the
   Keystore HPKE open, enforces the plaintext rules (strict UTF-8,
   1..32,768 bytes, no BOM, no NUL), and holds the text only in a one-use
   zeroizing holder. Every key and plaintext buffer is cleared after use.
4. A text needing more parts than `segment_count` is cleared and its journal
   row aborted before any submit intent exists.

A refusal yields no plaintext and no radio call, and a refusal at steps 1 or 2
writes no journal row. An expired grant is reported, never retried silently.
Journal-before-submit holds, an ambiguous radio outcome stays `unknown`, and
nothing auto-resends. No key material, plaintext or envelope bytes enter logs,
the evidence journal or status reports; the journal keeps identities and
digests only.

### Refusal report (phone to hub)

```json
{"v":1,"type":"sealed_execution_refusal","grant_version":1,
 "attempt_id":"UUID","connection_epoch":1,"reason":"expired"}
```

`reason` is one fixed code from the schema. The report names only the attempt
and epoch: no digest, key ID, envelope or content. The hub treats a refused
attempt as not sent and never re-grants it silently.

## Optional reported preconditions

New peers may negotiate [privacy-minimal Android preconditions](device-preconditions.md)
at WebSocket upgrade. The original handshake and heartbeat frames stay unchanged;
no report proves radio readiness or authorizes a send.
