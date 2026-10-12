# Complete selected-line v2 exchange proposal

This additive draft specifies the complete selected-subscription declaration
codec and the coordinated Android/server runtime continuation. The codec and
storage prerequisites alone do not mount these routes or enable a phone. Runtime
implementation, independent review, executed database/socket acceptance and
physical-device acceptance remain separate. The v1 transcript, negotiation and
single-subscription refusal keep their existing meaning. There is no implicit
upgrade from a v1 challenge, status report or cached observation.

## Admission and trust

The device must negotiate exactly one matching WebSocket subprotocol:

| Scope | Exact selected token |
|---|---|
| SMS line v2 with status v2 | `zrotext-device-status-v2-line-activation-v2` |
| SEALED dispatch v2, status v2 and line v2 | `zrotext-sealed-dispatch-v2-device-status-v2-line-activation-v2` |

The actual authenticated server lease stores line activation version 2 for that
socket epoch. A JSON version, token substring, offered-but-unselected token,
combined token string or status-v2 session alone supplies no v2 authority. A new
legacy connection keeps version 1; same-epoch version mutation must fail closed.
SMS and SEALED purposes have distinct keys, transcripts and feature admission.
This exchange does not elect payload profile03 or provide its durable adapter.

The complete-set observation is a signed **device declaration**, including a
concealed digest and selected physical/eSIM identity. It is not independent
hardware attestation. Android API 33+ must obtain a complete current subscription
set and a private live selected lease. Count equality, a reused subscription ID,
a restored journal, an installed receipt or a signature cannot recreate that
lease. Unknown/changed set, profile, port, monitor lifetime or observer epoch
must stop proof generation and later use until fresh authorized preparation.

## Wire representation

All frames are closed JSON objects, at most 4096 UTF-8 bytes. Reject duplicate
keys before materializing a map, unknown/missing fields, nulls, arrays, nonfinite
numbers and floating-point/exponent numeric tokens. `v` is the integer token 2.
UUIDs are canonical lowercase, hyphenated, non-nil values. `generation` and every
present `connection_epoch` are canonical positive decimal strings in
1..9223372036854775807, with no sign, whitespace or leading zero. `expires_at_ms`
is a positive integer numeric token in that range, not a string. Receivers must
preserve exact values; floating-point conversion loses large epochs/generations.

Base64url is unpadded and canonical after decode/re-encode. A nonce or digest is
32 bytes; the observation is 121 bytes. ECDSA signatures must decode to canonical
P-256 DER with nonzero scalars in range, 8..80 bytes. The
[schema](line-activation.schema.json) checks closed field shapes and scalar
bounds; raw-token checks, DER validity, observation semantics, signatures,
authentication and current authority require their separate consumers.

Receiver-specific safety gates may be stricter than this common shape grammar.
The Android SEALED challenge consumer also refuses a zero nonce and expiry above
`Long.MAX_VALUE - ACK_GRACE_MS`, preserving its bounded receipt clock arithmetic.
Those checks do not add a universal nonzero rule to the codec's opaque nonce or
complete-set digest. A syntactically recognized frame is still restricted to its
allowed direction and the actual negotiated consumer.

In the following table, every frame also contains `type`, `v`, and `challenge_id`.
Replace `<purpose>` with `sms` or `sealed` exactly. Every SEALED frame contains
`connection_epoch`; SMS contains it **only in the device proof**.

| Direction and type | Additional exact fields |
|---|---|
| Server → device: `<purpose>_line_challenge_v2` | `account_id`, `line_id`, `device_id`, `generation`, `nonce`, `expires_at_ms` |
| Device → server: `<purpose>_line_proof_v2` | `connection_epoch`, `observation_b64url`, `signature_der` |
| Server → device: `<purpose>_line_proof_ack_v2` | `accepted` boolean |
| Server → device: `<purpose>_line_activated_v2` | `account_id`, `line_id`, `device_id`, `generation`, `device_statement_sha256`, `device_signature_sha256` |
| Device → server: `sealed_line_installed_v2` | `account_id`, `line_id`, `device_id`, `generation`, `device_statement_sha256`, `device_signature_sha256` |
| Server → device: `sealed_line_install_ack_v2` | `accepted` boolean |

There is no SMS installed frame or install ACK. A false ACK grants no authority.
A transport send, timeout or lost response establishes neither rollback nor
successful local installation. Device input must match the authenticated socket
epoch and the exact pending or accepted tuple, not caller-supplied account claims.

## Exact signed bytes

Integers below use fixed-width big-endian encoding; UUIDs are 16 network-order
bytes. There is no JSON serialization, padding or optional/trailing data in a
statement. SMS purpose code is 1; SEALED is 2. The domains include a final zero
byte. `PREFIX` is `ZTSMS` for SMS and `ZTSE` for SEALED.

```text
device_statement = ASCII("PREFIX/line/device-confirm/v2\0") ||
  version:u8(2) || purpose:u8 ||
  account_id[16] || line_id[16] || device_id[16] || generation:i64 ||
  challenge_id[16] || nonce[32] || observation[121]

owner_statement = ASCII("PREFIX/line/owner-approve/v2\0") ||
  device_statement || SHA-256(canonical_device_signature_der)
```

Each signature uses P-256 ECDSA/SHA-256 over its complete statement. The device
uses the enrolled device key and the owner uses the distinct active approval
key for this purpose. DER byte changes affect the owner statement and receipt
digest, even if they purportedly represent an equivalent signature. The activated
receipt carries SHA-256 of the exact device statement and SHA-256 of its exact
canonical DER separately. They are not the combined audit confirmation digest.

The observation layout is fixed:

| Byte offset | Field | Encoding and structural bound |
|---|---|---|
| 0 | Android API level | u16, at least 33 |
| 2 | Complete active subscription count | u16, 1..256; not an observed hardware maximum |
| 4 | Selected subscription ID | i32, nonnegative |
| 8 | Selected kind | u8: 1 physical, 2 embedded |
| 9 | Selected card token | non-nil UUID |
| 25 | Selected profile token | non-nil UUID, distinct identity from a shared card |
| 41 | Selected port index | i32, nonnegative |
| 45 | Selected slot index | i32, nonnegative |
| 49 | Monitor lifetime ID | non-nil UUID |
| 65 | Observer epoch | i64, positive |
| 73 | Selected lease ID | non-nil UUID |
| 89 | Complete-set digest | 32 opaque bytes |

The codec's structural bounds do not certify the declared set or its digest.
The Android issuer owns completeness and currentness; server checks must retain
that distinction rather than promoting declaration equality into radio authority.

## Owner exchange and mutation fences

The runtime continuation uses explicit purpose-specific v2 owner routes. SMS
open input is `{device_id, opening_id}`; approval input is
`{owner_signature_der_b64url}`. The opening ID supplies exact retry identity.
SEALED registered open input is
`{expected_session_id, device_id, registration_id}`; view input is
`{expected_session_id}`; approval adds `owner_signature_der_b64url` to that view
input. The SEALED registration supplies its opening identity. These are closed
objects with canonical UUID/DER strings. No caller-selected account, protocol,
nonce, generation or lease can replace authenticated stored values.

Authenticate owner role, session, Origin and CSRF before reading mutation bodies.
Retain the existing MFA and registration gates. Bind the initiating owner session,
purpose, opening/registration, challenge, nonce, exact binding generation, actual
negotiated device lease, enrolled device signer and purpose-specific approval key.
Recheck expiry and current authority after lock waits and immediately before a
mutation commits. Revoked or changed keys/device/owner session, site/deployment,
generation, purpose, observation or signature must refuse activation. A v1 proof
cannot consume a v2 challenge or vice versa.

Unapproved retries require the original tuple, nonce, initiating owner and still
live original lease/time. Immutable observation storage contains observation,
DER, statement/signature/confirmation digests and proof-lease provenance. It must
not retain a nonce-containing statement as an immutable substitute for the
separately governed pending nonce. The owner signs the exact returned statement,
after comparing the intended device and line, rather than accepting opaque
device JSON as authority.

## Installation, retry and retirement

SEALED local installation binds the entire activated tuple and both separate
digests. A journal can hold an exact pending receipt for later delivery, but that
receipt is a durable disposition only. It does not recover a live selected lease,
grant permission, reconstruct the nonce or authorize a new signature.

The server commits the accepted SEALED installation receipt and pending nonce
removal atomically before sending a positive install ACK. An exact retry may
confirm that same accepted receipt on a currently authenticated v2 lease, active
generation and enrolled signer; it cannot change the receipt or revive the nonce.
Changed correlation fields/digests, legacy negotiation, revoked authority or a
different purpose must fail closed. Lost responses remain uncertain until this
exact supported reconciliation; there is no blind new activation or SMS resend.

SMS has no invented installed state. The runtime continuation's bounded
900-second ACK/retry window and denial-only nonce retirement do not declare
delivery, deletion of audit history or successful local installation. SEALED
expired/unactivated cleanup must preserve accepted receipt history and cannot
clear or recreate a nonce needed by an unresolved live transition.

The [vectors](vectors/line-activation.json) include ten frame shapes and eleven
encoding answers shared with the Rust codec, including physical/eSIM selection,
two eSIM ports on one card, a peer replacement, count 256 and i64 boundaries.
Their DER `r=1,s=1` is a concatenation fixture, **not a valid signature over the
statements**. Protocol tests exercise framing and encoding; authenticated socket,
database rollback/replay, Android issuer/installation and carrier tests must
validate the actual runtime separately. No vector establishes Play readiness.
