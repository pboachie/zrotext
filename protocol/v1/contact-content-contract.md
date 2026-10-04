# Dormant contact content integrity, version 1

ZTCO01 and ZTCM01 are candidate binary formats for historical contact field and
mutation verification. They depend on a genuinely verified ZTKA01 contact reader
statement and its already accepted generation-one manifest history. These pure
codecs do not install a reader, establish current permission, attest a write time,
select a current server head, or provide storage, signing, encryption, decryption,
key custody, rollback protection, or a contact API. Ordinary contact names and
notes still use the existing server vault until a separate reviewed runtime cut.

All integers below are unsigned big-endian. Positive integers are restricted to
1 through 2^63-1; explicitly permitted zero values are called out below. UUIDs
are exactly 16 nonzero bytes. Digests and key identifiers are exactly 32 nonzero
bytes unless a particular zero sentinel is specified. There is no alternate text
encoding in these wire formats. Unknown tags, trailing bytes, scalar aliases,
compressed points, and noncanonical slot representations are refused.

## Field envelope

The header H is exactly 246 bytes. Kind 1 is name; kind 2 is notes.

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 4 | ASCII `ZTCO` |
| 4 | 1 | Version 1 |
| 5 | 1 | Field kind 1 or 2 |
| 6 | 16 | Account UUID |
| 22 | 16 | Contact UUID |
| 38 | 8 | Seal revision |
| 46 | 8 | Trust generation, exactly 1 |
| 54 | 8 | Accepted manifest version |
| 62 | 8 | Declared reader generation |
| 70 | 32 | Reader key identifier |
| 102 | 32 | Accepted manifest semantic digest |
| 134 | 32 | SHA-256 of the complete signed ZTKA01 statement |
| 166 | 32 | SHA-256 of the exact routing identifier UTF-8 bytes |
| 198 | 16 | Mutation request UUID |
| 214 | 32 | Root writer identifier from that statement |
| 246 | 65 | Uncompressed P-256 encapsulation point |
| 311 | 4 | Ciphertext length C |
| 315 | C | Ciphertext, including its 16-byte AEAD tag |
| 315+C | 64 | Canonical low-S root ECDSA signature, raw r || s |

For name, C is 17..272 and signed size is 396..651 bytes. For notes, C is
17..2064 and signed size is 396..2443 bytes. Unsigned size is 315+C; signed size
is 379+C. A synchronous unsigned encoder validates framing only; it does not
claim curve membership or trust. Signed parsing validates encapsulation curve
membership using the maintained P-256 implementation (WebCrypto in the SDK).

The reserved HPKE suite is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
Its proposed info is ASCII `ZT/contact-field/hpke/v1` (24 bytes), one NUL byte,
then H; AAD is exactly H. The verifier does not seal or open this envelope.
Opaque ciphertext cannot attest valid UTF-8 or plaintext limits. A future
custody implementation must independently enforce name 1..256 UTF-8 bytes and
notes 1..2048 UTF-8 bytes after opening.

The field signature transcript is ASCII `ZT/contact-field/commitment/v1`
(30 bytes), one NUL byte, u32 unsigned size, then every unsigned field byte.
It includes the encapsulation, length, and ciphertext. The field digest is
SHA-256 of every signed field byte, including the canonical signature.

Verification requires the exact account, routing digest, contact UUID, manifest
version/digest, statement digest, reader generation/identifier, generation-one
root writer identity, and signature key committed by the supplied private
ZTKA01 verification brand. The expected contact and routing digest are separate
caller inputs. No public manifest projection can substitute for that brand.

## Mutation statement

The unsigned mutation is exactly 304 bytes; its signed form is exactly 368 bytes.
Operation 1 is create, 2 is update, and 3 is explicit legacy conversion.

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 4 | ASCII `ZTCM` |
| 4 | 1 | Version 1 |
| 5 | 1 | Operation 1, 2, or 3 |
| 6 | 16 | Account UUID |
| 22 | 16 | Contact UUID |
| 38 | 8 | Expected client revision |
| 46 | 8 | Successor client revision |
| 54 | 16 | Request UUID |
| 70 | 32 | Previous complete signed mutation digest |
| 102 | 8 | Trust generation, exactly 1 |
| 110 | 8 | Accepted manifest version |
| 118 | 32 | Accepted manifest semantic digest |
| 150 | 32 | Complete signed ZTKA01 statement digest |
| 182 | 32 | Exact routing identifier UTF-8 digest |
| 214 | 8 | Expected legacy row generation |
| 222 | 41 | Name slot |
| 263 | 41 | Notes slot |
| 304 | 64 | Canonical low-S root ECDSA signature, raw r || s |

Each slot is one tag byte, u64 seal revision, and 32 field-digest bytes. Tag 0
means clear and requires all following 40 bytes to be zero. Tag 1 means present
and requires a positive seal revision no greater than the successor revision,
and a nonzero complete signed field digest. Other tags are refused.

The mutation signature transcript is ASCII `ZT/contact-field/mutation/v1`
(28 bytes), one NUL byte, u32 value 304, then all 304 unsigned bytes. The mutation
digest is SHA-256 of all 368 signed bytes. The root writer and signature point
are derived from the exact committed ZTKA01 brand; no redundant writer field
permits certificate substitution.

Create requires expected revision 0, successor 1, previous digest all zero,
and legacy generation 0. Legacy conversion requires the same genesis shape
but a positive legacy generation equal to a separately supplied expectation.
That expectation is a historical consistency check, not proof that an installed
server row was locked or converted. Update requires a positive expected revision
below 2^63-1, successor exactly expected+1, nonzero previous digest, and legacy
generation 0. Saturated revision has no ordinary successor in this grammar.
Future owner erasure must not require manufacturing a signed successor.

## Compound continuity

The predecessor is either null for create/conversion or the private brand of a
previous verified compound transition. A standalone mutation, cloned object,
JSON checkpoint, server-provided revision, or caller-declared high-water is not
a predecessor. The successor binds the exact previous signed mutation digest
and revision. Account, contact, routing digest, origin, independently compared
root fingerprint, and trust generation remain equal.

Manifest versions and declared reader generations cannot decrease. Equal
manifest version requires equal semantic digest. Equal reader generation
requires the same reader identifier and point. A larger declared reader
generation can refer to a different genuinely accepted role-2 reader statement;
this is historical evidence and does not install or authorize that reader.

At most two replacement fields are supplied, with distinct kinds and no unused
or extra fields. A present slot sealed at the successor revision requires the
exact matching verified field, same slot kind, complete field digest, request
UUID, successor revision, account/contact/routing scope, manifest tuple,
statement digest, reader identity/generation, and root writer identity. A present
slot sealed earlier must equal the immediate predecessor's complete slot and
carry its previously verified field. Only this exact retained slot can carry a
different historical reader. A clear slot consumes no supplied field. Once a
slot is cleared or replaced, an older digest cannot reappear as a retained slot;
restoration requires a new signed field at the new successor/request identity.

## Pure API and ownership

The SDK exports `encodeContactFieldUnsigned01`, `encodeContactMutationUnsigned01`,
async `parseContactField01`, `parseContactMutation01`, async
`verifyContactField01`, async `verifyContactMutation01`, and
`verifyContactTransition01`. Separate identity accessors return defensive owned
copies for their private historical brands. Inputs are captured before awaits;
replacement arrays and objects are closed data shapes without caller getters.

Rust exports the inert `contact_content_contract` module, corresponding framing,
parsing, field/mutation verification and transition functions, private verified
constructors, owned identity copies, and redacted Debug implementations. Neither
implementation accepts a fabricated verified transition or adds runtime callers.

The shared synthetic vectors contain genuine canonical signatures, actual HPKE
ciphertext, and genuinely accepted reader replacement history. They contain no
private key material. The JSON schema checks closed representation, hex widths
and control aliases; cryptographic and transition validation occurs in the code.

Current-head selection, trusted independent client high-water acceptance,
current-only ciphertext storage, deletion tombstones, explicit legacy conversion,
ciphertext takeout, owner-only custody, and purpose-specific runtime consent
remain separate acceptance work. Historical validity does not identify the
latest contact state, make retained ciphertext currently readable, authorize
automation, or resolve an unknown financial submission. Existing consent
withdrawal and unknown-liability protections remain necessary at their real
runtime boundaries.
