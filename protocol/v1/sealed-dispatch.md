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

Grant, retrieval and first-intent transactions lock the device before its
session, matching enrollment revocation. Revocation that wins the device lock
can remove the session without a reverse lock dependency; subsequent authority
checks refuse new execution while historical exact receipts remain reconcilable.

## Sealed session time sampling (opt-in stream v2)

The explicit `zrotext-device-status-v2+sealed-dispatch-v2` subprotocol adds
`sealed_session_request` and `sealed_session` frames after ordinary device
session authentication. Sealed v1 remains available with its existing behavior;
grant version 1 and the envelope-fetch signature transcript are unchanged.
The default dispatch gates remain disabled.

A request carries version 1, the current connection epoch and a fresh nonzero
UUID challenge. The reply echoes that challenge and binds account, device,
connection/deployment epochs and an independent socket-local session UUID to a
fresh database UTC millisecond sample. The sample is captured after the live
session check. It supplies time and session identity, not manifest trust or
permission to send. The socket UUID remains stable across resampling.

The server refuses reused challenges, samples less than five seconds apart,
and more than 64 accepted challenges per socket. Reconnect establishes a new
session and nonce history; no nonce is evicted to reopen replay. V2 requires a
successful initial sample before `sealed_ready`. Resampling never renews the
existing 300-second readiness deadline. The phone must bind each response to
its outstanding challenge and authenticated socket, bound round-trip time to
two seconds, and anchor a conservative upper UTC bound using monotonic time.
Stale time, a changed session or an ambiguous request cannot authorize radio
submission. Session-time frames never derive their clock from a grant or the
phone wall clock. The synthetic frame contract is in `vectors/sealed-session-02.json`.
