# Original line signature evidence

`sdk/typescript/src/original-line-evidence03.ts` verifies historical original
line signatures for the coordinated profile03 setup. It is a library component;
no dashboard, server route or phone installation is mounted by this change.

`verifyOriginalRegistrationSignatures03` takes the exact existing canonical
`RegistrationEvidence03` bytes. The caller supplies the independently compared
root fingerprint, paired phone signing point, canonical HTTPS origin and exact
account, device, line and original binding generation. The verifier checks the
original RootLineRegister transcript, root pin, key fingerprints, both original
low-S raw signatures and the original registration window. Its original user
and owner-session IDs remain historical after a later authorized sign-in.
Present time may be after that original window; historical verification does
not extend it or require another registration.

`verifyOriginalActivationSignatures03` requires the actual registration result
from this module, the exact old binding and selected reader IDs, and a trusted
observation time that has not regressed. It checks the original sealed-purpose
v2 statement, complete-set observation framing, both original signing points,
device and owner signatures, and the owner's hash of the exact device DER.
It derives the existing `OldBindingIdentity03` commitment from those originals.
Caller buffers are copied before asynchronous work; returned records contain
immutable strings and counters. A copied registration result is refused.

Original v2 signatures retain their existing canonical DER policy, including
valid high-S signatures. Their bytes are never normalized before hashing or
owner verification. Profile03 election signatures remain separate raw low-S
signatures; accepting original v2 history does not loosen that policy.

The activation wrapper uses the framed domain
`ZTSE/line/payload-profile/activation-evidence/v1\0`, followed by a big-endian
unsigned32 payload length and this exact payload:

1. Registration UUID16 and old-binding UUID16.
2. Original device point65 and owner-approval point65.
3. Exact device statement255, unsigned16 DER length and original device DER.
4. Exact owner statement314, unsigned16 DER length and original owner DER.
5. Original accepted milliseconds, unsigned64 in the positive signed64 range.

The registration wrapper reuses the existing Rust canonical contract without
changing any transcript or signature domain. Both wrappers require exact EOF.
No original transcript can be reconstructed from its digest. A missing original
requires refusal; this library neither backfills history nor creates a root.

These results establish mathematical signature and integrity checks only.
Completed/accepted checkpoints are attributed to the server and are not signed
database-acceptance attestations. The observer must independently authenticate
the accepted election and its old-binding commitment, verify the selected
manifest and enrolled reader, and establish current owner/device/lease and
installed-line permission. Neither downloaded timestamps, a verified original
signature nor these local records authorize a send or claim a physical SIM.
