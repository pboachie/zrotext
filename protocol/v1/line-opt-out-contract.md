# Internal line-bound unsolicited opt-out contract

This is a server prerequisite, not a device-stream frame or a general send
route. `inbound::unsolicited::ingest_line_opt_out` has no transport caller.
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
No webhooks are queued for this internal event.
