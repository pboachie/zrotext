# Candidate historical contact commitment producer

The dormant TypeScript module `contact-content-producer` produces the existing
contact field and mutation wire formats. It accepts an application-supplied
existing nonextractable private ECDSA P256 CryptoKey with signing usage. It
does not recover or import root secrets, create keys, seal/open plaintext, query
a trust store, persist, submit, install or grant current contact permission.

`produceContactFieldCommitment01` accepts a genuine verified contact reader
statement, independently intended account/origin/root fingerprint/contact/routing
identity, kind/revision/request and already encrypted encapsulation/ciphertext.
It derives reader/root/manifest identity from the genuine private statement
accessor. Caller structural identity objects cannot substitute for that brand.
It validates the encapsulation curve using maintained WebCrypto, signs the exact
existing field transcript and passes every output through the existing verifier.

The field signature input is ASCII `ZT/contact-field/commitment/v1` (30bytes),
one NUL byte, u32 big-endian unsigned length and the exact unsigned field bytes.
The full domain length is31bytes. The existing field header is246bytes; the
encapsulation, ciphertext length and ciphertext remain in the signed unsigned
body. No header, HPKE binding, format or existing verifier changes here.

`produceContactMutationTransition01` accepts the genuine next statement,
independent expected scope/legacy generation, exact unsigned mutation, genuine
previous transition and its genuine previous statement (both null for creation
or conversion), and at most two genuine replacement fields. It binds the prior
statement digest/account/root/manifest identity to the actual prior mutation.
Before signing it checks exact predecessor CAS, monotone reader/manifest scope,
retained slots and exact new field kind/request/revision/digest commitments.
Duplicate or unused fields, cleared resurrection and invalid MAX updates refuse.

The mutation signature input is ASCII `ZT/contact-field/mutation/v1` (28bytes),
one NUL byte, u32 big-endian304 and the exact304-byte unsigned mutation. The full
domain length is29bytes. Signed mutation width is368bytes. Own signatures are
canonicalized low-S using the maintained helper; received signatures are still
strictly verified without normalization. The existing mutation verifier and
private transition verifier must both succeed before publication.

Each result is `produced_historical_integrity`, with copied signed bytes and the
genuine historical field/transition result from the existing maintained verifier.
An actual wrong root key fails that verification and yields no result. Matching
signatures prove mathematical key possession, not that the key came from an
accepted recovery/custody procedure or that a current owner approved a ceremony.

Inputs use closed data objects and are copied before the first asynchronous
operation. Genuine accessor copies are reconstructed as plain encoder input;
private-brand JSON restoration is refused. Native key getters validate the
runtime CryptoKey without invoking an arbitrary object's getters. The standard
WebCrypto operation receives the actual key, never a caller signing callback.

At most four unresolved operations exist in this module instance. Each outward
operation has one absolute ten-second monotonic deadline and an AbortSignal;
abort or timeout settles outward refusal while its unresolved cryptographic
work retains admission until settlement. All late rejections are observed and
late results cannot be published. Owned unsigned/signature buffers are cleared
on refusal/settlement; returned verification brands may retain their public
ciphertext snapshots by the existing verifier contract. There is no claim of
engine cancellation, key revocation, hardware custody or complete compiler/
third-party buffer zeroization. The caller owns its original key and bytes.

A previously held genuine historical statement may survive later history
pruning; this pure module cannot detect or attest stored-history availability.
Accepted local history and independently current root/reader/owner authority are
separate boundaries. Actual product root recovery, account-only current writer
authorization, contact reader custody, reader statement issuance, durable signed
CAS/deletion high-water, legacy conversion and mounted encrypted contacts remain
unavailable through this module. It does not satisfy the complete contact
encryption or pilot-exit acceptance criterion by itself.
