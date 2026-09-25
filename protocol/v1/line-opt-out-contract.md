# Line-bound unsolicited opt-out contract

This is a restricted device-stream receive path, not a general send route.
The device-stream frame calls `inbound::unsolicited::ingest_line_opt_out` only
when `LINE_OPT_OUT_ENABLED=true`; the default is false.
It accepts a signed, metadata-only STOP or ambiguous opt-out review action
without requiring an outbound message or attempt. It never accepts START or
clears an existing suppression. No SMS body is uploaded or stored.

The action requires the current authenticated writer session, an active
owner-approved line binding at the signed generation, an unrevoked enrolled
device key, and a locally declared E.164 sender. The server cannot
independently verify that the carrier delivered an SMS from that sender or
that the selected physical SIM matches the line. The future phone producer
must make a fresh unambiguous SIM observation before capture and before
upload, and retain the same signed event for retries. A changed or uncertain
line mapping must pause upload and retain a local suppression for owner
handling. The line activation contract still lacks a production owner-key
provisioning ceremony and Android proof producer.

## Signed bytes

P-256 ECDSA/SHA-256 signs this exact byte string. UUIDs are 16 network-order
bytes, integers are fixed-width big-endian, and `recipient_e164` is ASCII
matching `+[1-9][0-9]{1,14}`. The DER signature must be canonical. There is
no JSON, normalization, optional field, outbound ID, or trailing data.

```text
ASCII("zrotext-line-opt-out-v1\0") ||
account_id[16] || device_id[16] || line_id[16] ||
binding_generation:i64 || event_id[16] || device_sequence:i64 ||
observed_at_ms:i64 || action:u8 || recipient_len:u8 || recipient_e164[recipient_len]

action = 01 STOP keyword, 02 conservative review block
```

Cross-client transcript vector: account
`11111111-1111-4111-8111-111111111111`, device
`22222222-2222-4222-8222-222222222222`, line
`33333333-3333-4333-8333-333333333333`, event
`44444444-4444-4444-8444-444444444444`, generation 7, sequence 42,
`observed_at_ms=1700000000000`, action 01 and recipient `+15551234567`
produce SHA-256 digest
`bd2e9c463936887cfa804c2a35ecf2be37004b9c6f2104f1f3e758a38fd5459a`
over the exact statement. Android and Rust independently assert this value.

The sequence space is independent of the attempt-bound inbound pilot's
sequence. A source event must be at most seven days old and at most five
minutes ahead of server time, and its timestamp must be after activation of
that line generation. The writer checks the line, device and deployment
session again before committing. A changed event under an existing ID or a
reused device sequence fails. An exact replay does not spend another storage
budget unit or change suppression.

The transaction locks the account row used by message acceptance, then
records the event and account-scoped recipient suppression atomically.
Migration 032 prevents a later attempt-bound STOP from replacing an active
unsolicited source with an attempt-bound source; an old-window START therefore
cannot clear this block. A future signed line-bound START/consent workflow
must be designed separately, including how to handle out-of-order actions.
No webhooks are queued for this event.

## Device-stream frame

After the enrolled device authenticates on `/v1/device-stream`, it may send
one UTF-8 JSON text frame of at most 4096 bytes per opt-out action:

```json
{"v":1,"type":"line_opt_out","connection_epoch":1,"event_id":"00000000-0000-4000-8000-000000000001","sequence":1,"line_id":"00000000-0000-4000-8000-000000000002","binding_generation":1,"action":"opt_out","recipient_e164":"+15551234567","observed_at_ms":1700000000000,"signature_der":"BASE64URL_NO_PAD"}
```

`action` is exactly `opt_out` (signed byte 01) or `opt_out_review`
(signed byte 02). `signature_der` is canonical unpadded base64url of the
device's DER signature over the bytes above. The account and device IDs come
from the authenticated session, not the JSON frame. Unknown fields, `opt_in`,
body fields, malformed signatures, noncanonical base64, stale connection
epochs, wrong line/generation, and disabled runtime yield no acknowledgement.
The server checks the writer session and line again inside the database
transaction. A disabled runtime or stale epoch closes with WebSocket code
1008; invalid signed evidence closes with 4409; transient storage/budget
failure closes with 1013. The phone retains its local STOP and signed upload
row whenever no matching acknowledgement is received.

After commit the server replies:

```json
{"v":1,"type":"line_opt_out_ack","event_id":"00000000-0000-4000-8000-000000000001","created":true}
```

`created=false` means an exact replay already committed. The client must
match `event_id` before retiring its upload row. There is no
`suppression_cleared`, webhook count, START, outbound attempt, or SMS body in
this contract. A new socket session may retry the exact same signed event.
