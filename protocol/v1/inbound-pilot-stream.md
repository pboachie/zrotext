# Inbound metadata pilot frame

This opt-in extension to `/v1/device-stream` is for consented pilot devices.
The server accepts it only when `INBOUND_PILOT_ENABLED=true`, and the default
is off. It carries no reply body, sender phone number, or content ciphertext.
It requires the authenticated writer session from `device-stream.md` and
migrations 007 and 023. It does not authorize an SMS send.

The device sends one UTF-8 JSON text frame, at most 4096 bytes:

```json
{"v":1,"type":"inbound_event","connection_epoch":1,"event_id":"00000000-0000-4000-8000-000000000001","sequence":1,"message_id":"00000000-0000-4000-8000-000000000002","attempt_id":"00000000-0000-4000-8000-000000000003","classification":"captured_local","observed_at_ms":1700000000000,"part_count":1,"signature_der":"BASE64URL_NO_PAD"}
```

`classification` also parses `sim_unverified`, `send_unverified`,
`encryption_unverified`, `opt_out`, `opt_out_review`, and `opt_in`. The Android
uploader sends `captured_local` and the three opt action values only after a
trusted reply window. The server assumes `metadata_only` content kind. The P-256
DER signature uses the exact `signed_event_bytes` layout in
`inbound-foundation.md`, including content kind 0 and SHA-256 of empty bytes.
Base64url must be canonical with no padding. Unknown fields, stale epochs,
invalid signatures, unrecognized source attempts, and disabled pilot runtime
close the socket. Device state must retain the same event ID, sequence and
signature until acknowledged.

After transaction commit, the server replies:

```json
{"v":1,"type":"inbound_event_ack","event_id":"00000000-0000-4000-8000-000000000001","created":true,"queued_deliveries":0}
```

`created=false` means an exact idempotent replay; it does not queue a second
delivery. The client must match the outstanding event ID before removing its
local upload item. `queued_deliveries` counts enabled endpoints at ingest
time; zero is valid. Optional `suppression_cleared=true` is returned only when a signed
`opt_in` event transitions an existing active suppression to inactive; the
phone may then clear its older local block. Absent means false, preserving the
older acknowledgement shape. This frame is a metadata transport pilot, not a reviewed
sealed-content protocol or a public webhook release.
