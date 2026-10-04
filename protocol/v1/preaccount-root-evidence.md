# Pre-account root evidence

This is a pure cryptographic codec, verifier and offline `unlock`-only signing
primitive. It proves that the independently intended root signed exact bounded
stage commitments. It authenticates no stage credential, consumes no challenge,
creates no account or session, configures no issuer, accepts no custody, installs
no manifest or reader, and grants no current execution permission. There is no
server, browser or CLI staging workflow. Existing root enrollment and recovery
protocols keep their owner-session meanings.

The domains are `ZTSE/preaccount-intent/v1\0` and
`ZTSE/preaccount-root/v1\0`, each with a literal final NUL. Algorithms and purpose
are fixed: P256 ECDSA/SHA256, root possession of an exact proposed pre-account
birth intent. They are not caller-selectable. No arbitrary-transcript signer or
private-key export exists. Signing APIs compile only with the existing `unlock`
feature; codec and verifier compile without it. The server never enables unlock.

## Closed intent

Integers are unsigned big-endian. IDs are nonzero16-byte values; allocation and
times are1..i64::MAX. Origin is the existing canonical ASCII HTTPS serialization,
1..512 bytes, without normalization. A one-byte origin is only a framing floor,
not a valid HTTPS positive example. RootPin02 is exact94 bytes, generation1,
the intended account and an on-curve canonical uncompressed P256 public point.
Digests are exact32-byte commitments, not evidence of accepted source or policy.

Intent `I` is exact354+N bytes,355..866:

| Offset | Width | Field |
|---:|---:|---|
|0|1|version1|
|1|1|purpose1: pre-account birth-intent root possession|
|2|16|installation epoch|
|18|8|allocation number|
|26|16|prospective account|
|42|16|prospective owner user|
|58|16|explicit birth approval ID|
|74|2|origin length N|
|76|N|canonical origin|
|76+N|94|genesis RootPin02|
|170+N|32|independently intended root fingerprint|
|202+N|16|encrypted backup bundle ID|
|218+N|32|encrypted backup digest|
|250+N|32|public recovery card digest|
|282+N|32|managed-enrollment plan commitment|
|314+N|32|operator policy commitment|
|346+N|8|birth intent deadline|

The maintained `ZTSE/root-pin/v2\0` fingerprint must match the pin and intended
account. The backup, card, plan and policy commitments are opaque here. Their
source bytes, meaningful key/reader/workload/manifest bindings, independent
selection, current availability and accepted custody/issuer remain caller
obligations. Public backup/card signatures or matching hashes cannot establish
recovery, physical custody or policy eligibility.

`intent_digest = SHA256(intent_domain || u32(len(I)) || I)`.

## Closed challenge and evidence

Challenge `C` is exactly122 bytes:

| Offset | Width | Field |
|---:|---:|---|
|0|1|version1|
|1|1|purpose1|
|2|16|installation epoch|
|18|8|allocation number|
|26|32|intent digest|
|58|16|challenge ID|
|74|32|nonzero nonce|
|106|8|issued milliseconds|
|114|8|expiry milliseconds|

Epoch, allocation and digest match I. `issued < expires`, expiry minus issue is
at most300000ms, and expiry does not exceed the intent deadline. Externally
trusted positive time must satisfy `issued <= now < expires`.

The signed transcript is
`root_domain || u32(len(I)) || I || u32(122) || C`.
Signature is exact64-byte ECDSA `r || s`, valid scalars and strict low-S. Producers
canonicalize their own output; verification rejects high-S without normalization.
Evidence is `u16(len(I)) || I || C || signature64`, exact543..1054 bytes. Parsers
reject wrong tags, widths, aliases, invalid points and trailing bytes.

## Caller boundary

`ExpectedStageRoot` contains every independently intended Intent and Challenge
field. Deriving it from received evidence defeats independent comparison. All
fields must match, not just account and fingerprint. Typed public data and a
matching signature are not a private authenticated principal.

Unlock-only `ReviewedStageRoot::inspect` compares that full context and trusted
inspection time, then captures owned immutable public snapshots. Consuming
`sign` rechecks expiry, refuses signing time earlier than inspection, and checks
the supplied RootSecret's public point against the intended pin. Temporary
internal maintained P256 key values are scoped and drop-zeroized; there is no
caller-visible secret clone/serialization/scalar return, persistence or claim
that compiler/register copies are all scrubbed. The caller separately enforces
actual recovery/consent, process eligibility, key custody, cancellation and fresh
output time after any delay.

Default-available `verify` returns a privately constructed result whose kind is
`cryptographic_signed_evidence`, exposing only copied public identity metadata.
It makes no owner/session/stage/issuer/current-manifest conversion and consumes
no state. A future real caller must authenticate a stored stage credential,
reload exact one-use state and accepted policy/custody/workload evidence after
lock waits, enforce a trusted clock and transactionally consume the challenge.
Those APIs do not exist as part of this codec. Repeated fresh checks do not
prove jointly atomic OS/database authority.

## Synthetic shared vectors

`vectors/preaccount-root-evidence-01.json` contains genuine software signatures
from derivable synthetic root material already used by root-backup fixtures.
The primary intent commits the existing synthetic encrypted backup and public
card. Minimum/maximum origin-width variants use the same public commitments to
exercise framing and signature binding; they are not accepted custody bundles
for those alternate origins. No actual root, account, credential or provider is
used. Vectors also contain a freshly signed foreign approval, high-S signature,
valid old owner-session enrollment signature, wrong-domain signature and
wrong-root signature. Default tests verify evidence; explicit unlock tests
exercise the matched producer. Default workspace tests alone do not execute
unlock signing. This remains groundwork for a separately reviewed staging
ceremony, rather than an available account creation or installation path.
