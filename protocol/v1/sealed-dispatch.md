<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Dormant sealed dispatch version 1

This optional implementation remains disabled by default. It does not approve
the candidate-02 cryptographic live profile, activate Android execution, or prove
carrier delivery. Nonempty HPKE info/AAD approval and device integration remain
separate prerequisites.

`SEALED_DISPATCH_ENABLED=true` additionally requires enabled dispatch and the
existing synthetic-alpha account and recipient policy. A device must explicitly
negotiate `zrotext-device-status-v2+sealed-dispatch-v1` and authenticate through
the existing enrollment-key challenge. Legacy subprotocols receive no sealed
grant. The extension also accepts the existing version-2 device-status reports.

The device sends one `sealed_ready` frame naming version 1, its current connection
epoch, approved line binding generation, and its exact role-1 payload reader key
ID. Readiness expires after the existing alpha readiness window and authorizes
at most one grant on that connection. Reconnecting does not remove an existing
attempt fence or authorize an uncertain resend.

Admission can supply `x-zrotext-sealed-segment-limit` with exactly one ASCII digit
from 1 through 6. It is an authenticated, immutable maximum, not an estimate of
encrypted plaintext. Exact replay must preserve it. Old messages without this
declaration remain ineligible for execution. The grant's existing `segment_count`
field carries this maximum; the device must refuse prepared content above it.

Grant issuance reuses delivery claims, metering reservation, suppression and
one-use attempt fences in a single transaction. It revalidates the independent
root pin, current signed manifest and role-1 key, writer, session, approved active
line binding, and expiry. The frame contains no message body or recipient and
binds the SHA-256 of the exact admitted ciphertext. Acceptance remains distinct
from submission intent and radio evidence.

`POST /v1/sealed/dispatch/envelope` accepts a bounded JSON object containing the
complete grant and `signature_der`: canonical unpadded base64url DER P-256
signature by the enrolled device signing key. No owner API token, URL parameter,
or digest alone authorizes retrieval. The signed transcript is the UTF-8 bytes
`ZT/sealed-envelope-fetch/v1` followed by NUL; four single-byte values (wire
version, grant version, reader role, segment maximum); account, device, line,
message and attempt UUIDs in network byte order; connection, deployment, binding,
attempt generation and expiry as positive signed 64-bit big-endian integers;
then reader key ID, exact-envelope digest and unsigned-envelope digest as their
decoded 32-byte values. Schemas and the synthetic exact transcript vector live
in `vectors/sealed-dispatch.schema.json` and `vectors/sealed-dispatch-01.json`.

Successful retrieval returns the exact opaque admitted bytes with content type
`application/vnd.zrotext.sealed.v1` and `Cache-Control: no-store`. Current account,
device, session, line, manifest and attempt authority are checked again. Replays
can retrieve the same bytes only while the unconsumed grant remains current.
Cross-account, wrong digest, revoked, expired and consumed identities receive
the same refusal without plaintext or message-existence details. Submission
intent consumes the existing fence; historical callbacks and uncertain outcomes
retain the established reconciliation model and never trigger automatic resend.
