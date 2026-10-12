# Server profile03 wire verification component

The independent `sealed_dispatch::wire03` component implements the closed syntax
and device-signature portion of the [proposed profile03 dispatch contract](sealed-dispatch-03-candidate.md).
It is a pure prerequisite, not a mounted profile03 service or negotiated capability.
Existing dispatch codecs, routes, grant issuers and profile02 behavior are unchanged.

`GrantFrame03::parse` accepts raw JSON bytes with exactly the 25 required fields.
`ReadyFrame03::parse` accepts the complete 15-field readiness object, including
`v` and `type`. `Fetch03::parse` accepts only `grant` and `signature_der` and checks
the nested grant with the same rules. Input is nonempty and bounded to 4096 bytes.
A streaming map-only boundary covers all three outer objects and Fetch's
nested grant. It forwards the original map access to closed deserialization,
preserving decoded duplicate, missing, unknown, null and wrong-type checks
without collapsing members into an intermediate value. Complete positional
arrays are refused as well as scalar inputs and trailing JSON. UUID values must be nonzero,
lowercase, hyphenated and round-trip exactly. Digests are canonical 43-character
unpadded base64url encodings of 32 bytes. Integers retain the complete positive
signed-storage range; fractional/exponent aliases, numeric strings and overflow
are refused. Profiles, headers, reader role and segment bounds are explicit.

Validated frame wrappers have private construction and return borrowed, owned
typed claims. Cloning or editing a detached claims value cannot manufacture or
change a validated frame or proof. Grant/readiness JSON serialization preserves
the checked values; JSON property order and formatting do not determine signatures.
A future builder can supply explicit fields through the same raw JSON validation.
There is no conversion from the existing grant or an inferred profile/default.

`GrantFrame03::fetch_transcript` produces exactly 362 bytes: the 28-byte
`ZT/sealed-envelope-fetch/v3\0` domain, six profile/role/count bytes, five raw UUIDs,
seven big-endian storage integers and six decoded digests in the normative order.
`Fetch03` requires canonical unpadded DER encoding, 8–71 decoded bytes, minimal
positive P-256 scalar integers, canonical sequence length, no trailing bytes and
low-S before signature verification. Received signatures are never normalized
for acceptance. The receiver checks a round-trip of the parsed DER and compares
its raw scalars with their low-S form; only an already-low-S signature proceeds.

`Fetch03::verify` checks P-256/SHA-256 over that exact transcript using an explicit
caller-selected enrolled-device public key. `VerifiedFetchProof03` is evidence
of that signature only. The codec does not authenticate key selection, consult
a clock, compare current manifest/election/session/binding authority, issue a
grant, fetch ciphertext, consume an attempt or authorize a radio effect.
Readiness claims are unsigned and cannot select trusted current authority.

Ordinary module tests consume the actual public profile03 Grant/Ready/transcript
and device-signature vector. They cover generated positive proofs, all signed
variable fields, wrong keys and old domains, the complete closed field sets,
integer/UUID/digest boundaries, malformed DER and a genuine high-S twin within
the length bound. These are pure software component checks. The public vector's
opaque envelope identities are synthetic, not an accepted production envelope.
No PostgreSQL or device fixture is required for these normally discovered tests.
Independent review found that the initial ten passing tests omitted complete
positional arrays accepted by derived struct deserialization. The corrected
map-only boundary has explicit valid Grant25, Ready15, Fetch2 and nested-grant
array refusal controls. The corrected eleven-test group and three existing wire tests
passed separately with zero failures or ignored tests; initial execution evidence
remains preserved separately with its incomplete object-shape coverage.

Authenticated integration remains separate. Generic dispatch and the confirmed
conversation execution writer must both obtain durable accepted/current election
and current binding authority, persist/compare every grant field and original
provenance under the retained transaction fences, recheck clocks after waits,
and preserve exact replay, unresolved attempts and one-use effect permission.
Current authority must not come from request or readiness metadata. Actual HTTP
and socket ingress, negotiation, durable schema/adapters, Android journal and
maintained receiver composition are not supplied by this codec. Unsupported
profile03 must not fall back to profile02, plaintext or another provider.
Runtime, authenticated onboarding, device/carrier and Play readiness remain
unqualified by this component.
