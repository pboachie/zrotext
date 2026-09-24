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
2. Hub returns `{"v":1,"type":"challenge","challenge_id":"UUID","account_id":"UUID","device_id":"UUID","nonce":"BASE64URL_NO_PAD"}`. The nonce is 32 random bytes.
3. Phone signs the exact byte string below with its enrolled, non-exportable
   P-256 Android Keystore key using `SHA256withECDSA`. The signature is DER.
   It returns `{"v":1,"type":"proof","challenge_id":"UUID","account_id":"UUID","device_id":"UUID","nonce":"BASE64URL_NO_PAD","signature_der":"BASE64URL_NO_PAD"}`.
4. The writer consumes the challenge once, checks the enrolled key, active
   device/account, enabled site, and deployment epoch, and increments the
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

Challenge issuance and proof verification each share their PostgreSQL request
budget with the corresponding HTTP enrollment route: 30 attempts per device
and 300 attempts globally per 60 seconds, across all hub instances. The hub
closes the socket with code `1013` (Try Again Later) when a budget is
exhausted or its storage is unavailable.
Reconnecting or switching transports does not reset a budget. Established
session heartbeats do not consume these handshake budgets.

The hub checks session status against PostgreSQL on every heartbeat and at
most 10 seconds between heartbeats. A new valid connection fences the older
epoch; release of an old socket cannot clear the newer lease. A drained,
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

The Android app exposes a separate **Start inbound metadata pilot** action. It
is off by default. The hub must separately enable `INBOUND_PILOT_ENABLED=true`.
After authenticated session setup, the phone sends only previously captured
`captured_local` events. It does not transmit the sender address, SMS body, PDU,
or the local AES-GCM vault ciphertext. This pilot does not expose reply content
to customers and has not passed a live WSS interoperability test.

The client frame is
`{"v":1,"type":"inbound_event","connection_epoch":1,"event_id":"UUID","sequence":1,"message_id":"UUID","attempt_id":"UUID","classification":"captured_local","observed_at_ms":1700000000000,"part_count":1,"signature_der":"BASE64URL_NO_PAD"}`.
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
