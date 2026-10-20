# Explicit reviewed intent03 V2 component

This source component for #1623 adds separate TypeScript `*03V2` APIs to
`reviewed-intent03.ts`. It does not mount an admission route, browser composer,
receiver, database writer or radio effect. The original ZTRI01 APIs and vectors
retain their historical bytes and signature domain.

V2 uses `ZTRI || 02 || 03 || 03 || 00`. It retains the original eight UUIDs and
eight positive signed63 u64be counters at offsets8..200. Vault generation and
account-selection epoch must each equal1. At offsets200..520 it retains the
first ten original commitments, ending with the exact final signed-envelope
SHA256 and exact unsigned-envelope SHA256. There is no body hash, placeholder,
optional body field or alternative plaintext commitment. The peer/recipient/
ceiling tail begins at520, exactly32 bytes before the historical V1 tail.

The exact length is `523 + peer_length + 33 * recipient_count`, hence592..803.
Peer grammar, exact one-device/one-archive plus up to six integration readers,
canonical ordering, strict low-S role5 ECDSA signature and ceiling1..6 stay
mandatory. The distinct signature domain is
`L("zrotext/conversation/reviewed-send03/v2", exact_V2_intent)`, where L is ASCII
label, NUL, u32be length and bytes. There is no version/domain fallback.

`prepareReviewedIntent03V2` accepts the exact encrypted envelope and the same
private captured current context. It neither accepts nor computes plaintext
metadata. The actual composer must seal the owner's reviewed body and preserve
the exact routing, ciphertext and one-use signing journal. Envelope03 body/wrap
domains, Grant03's25 fields and Fetch03's362-byte transcript are unchanged.

The component validates genuine manifest/election handles, original scope,
current selected keys, real envelope and intent signatures, review lifetime up
to30 seconds and message lifetime up to900 seconds. The original review/admission
clock cannot become a later effect clock. A private verified V2 handle cannot be
substituted for a V1 handle or forged from its copied public projection. None of
these local checks establishes HTTP authentication, a held database read,
original installed interval proofs, quota, commit, key custody or radio consent.

The [decoded structural schema](../v1/reviewed-intent03-v2.schema.json) describes
hex bytes and exact decimal strings for interoperability, not HTTP admission.
It cannot prove signatures, recipient sorting/uniqueness, cross-field times or
current authority. The [shared signed vectors](../v1/vectors/reviewed-intent03-v2.json)
cover592/803 bounds and signed63 counters; raw vector fields do not establish
an accepted election, original interval or encrypted body. Separate SDK tests
use actual root/manifest/election proofs, composer HPKE/AES-GCM opening and
both real signatures.

Before first corrected production composition, new V1 admission, grant effects
and fetch execution must refuse explicitly. V1 exact original-user status and
history remain passive; old pending/UNKNOWN records must not be translated,
re-signed, requeued or rearmed. Versioned storage and coupled historical content
redaction require their separate reviewed migration. This component implements
neither that storage transition nor runtime/release qualification.
