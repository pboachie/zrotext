# Android capture allocator bootstrap proof component

`CaptureBootstrap03` implements public association and proof bytes only. It does
not generate a key, open or close a server attempt, verify a genuine original
enrollment/history, initialize a counter, persist phase reservations, restore a
capture handle or enable an upload. The actual protected bootstrap journal,
current authenticated actor, server first-ever factory, explicit foreground
recovery and shipping ingress integration remain required and are unfinished.

The new standalone `profile03-capture-bootstrap.schema.json` describes closed
transport shapes. Earlier capture, reviewed-intent and envelope formats remain
unchanged. The published signed vector has six distinct synthetic public signing
keys and real signatures. Its origin commitments are deliberately opaque synthetic
values; they do not stand in for actual signed registration/activation/election
history, hardware backing, a server receipt or a zero-history witness.

## Fixed bytes

All UUIDs are nonnil raw RFC4122 bytes. Integers are positive big-endian signed63.
All fixed32 fields must be nonzero. Signing-key IDs use exactly
`SHA256("ZTSE/key/v1" || NUL || 01 || 01 || uncompressedP256Point65)`.

| Core521 offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | `ZTCB 01 03 03 00` |
| 8 | 160 | account, device, bootstrap, opening, actual server attempt, original registration, old binding, accepted binding, election challenge, line UUIDs |
| 168 | 32 | old binding generation, higher accepted binding generation, vault generation1, selection epoch1 |
| 200 | 256 | bootstrap nonce SHA256, enrolled signing ID, canary signing ID, original root fingerprint, original election bundle SHA256, original registration evidence SHA256, original activation evidence SHA256, server attempt nonce SHA256 |
| 456 | 65 | actual on-curve uncompressed canary point |

`Association473` is exactly Core521 with only bytes72..87 (the actual attempt
UUID) and bytes424..455 (its nonce commitment) removed. It is immutable preparation
data and has no signing or acceptance API. There is no accepted473/601 proof
format. The original bootstrap nonce and actual server attempt nonce remain raw
32-byte values in their retained commands; each occupies a SHA256 commitment in
the proof. The attempt is an independently reserved source record, not a value
that a packet may choose for itself.

`L(label,payload)` is ASCII label, NUL, u32BE payload length, exact payload. The
enrolled device signature is strict raw64 low-S P256 over
`L("ZTSE/conversation/capture-bootstrap/device-attempt/v1", Core521)`.
The canary signature uses the distinct domain
`L("ZTSE/conversation/capture-bootstrap/canary-attempt/v1", Core521 || SHA256(exactDevice64))`.
Bundle649 is Core521, device64, canary64. Both raw scalar ranges and low-S form
are checked before public signature verification.

The canary point/ID must differ from enrollment and every independently verified
known original/current root, original SEALED approval, and role04/05 signing
identity. A caller-supplied list is not authenticated history. Actual phone code
must also check its new purpose-specific alias, nonexportability and TEE/StrongBox
metadata; two signatures cannot prove a hardware alias or remote attestation.
API28–30 refusal is required at the eventual hardware boundary. This codec alone
has no AndroidKeyStore operation or API-level authority.

## Recovery and lifetime obligations

An actual first-ever opening fixes account/enrolled-device identity and original
association before canary generation. A disabled counter0 becomes usable only
after the exact same protected local state and actual existing canary match an
authenticated immutable server receipt. Empty local tables and server maximum
sequence are never initialization or recovery evidence. Positive global03
sequences span lines, bindings, roots, reconnects, Stop and content redaction.

Each hardware call must have its own durable reservation before entry. An unknown
result never regenerates automatically. A separate explicit foreground recovery
may reserve a genuinely new server attempt over the same473 association and same
disabled0/canary, after a permanent authenticated direct predecessor closure.
Old521 cores, signature burns, returned proofs and packets remain unchanged. A new
attempt proof cannot validate an old proof as its own; a downloaded phase or
`not_found` response cannot authorize another signing call.

One server-open attempt is retained per opening. Exact same-command retry/status
returns original bytes/times without allocating or closing again. A phone with an
uncovered local unknown must reconcile that exact command instead of using
latest-only status. Sixteen genuinely new explicit recovery commands per
account/device in a fixed24h window across connections is an allocation budget,
not a lifetime-history cap. Ordinary request admission still applies to retry
and status. The real storage/budget implementation is separate from this schema.

Opening, original signed evidence, attempts, closures, accepted receipt and
first-ever fence survive line/device/personal-content erasure until account
erasure. Late metadata reconciliation uses the genuinely current same-enrolled
actor and original retained origin; it does not require an old physical lease or
restore one. A historical nested opening has no current epoch. Outer actual socket
epoch is a JSON integer; historical times are decimal strings. A receipt for an
accepted successor is distinct from status of a queried old attempt and must be
compared by exact IDs and hashes before any local historical completion.

The hardware canary establishes existence continuity, not monotonic freshness of
the Room counter. Existing backup and transfer exclusions remain required.
Ordinary crash/loss and partial missing-state refusal are the supported baseline;
privileged restoration of an older otherwise-valid complete Room snapshot is not
detected by this component. No hardware monotonic counter is claimed.
