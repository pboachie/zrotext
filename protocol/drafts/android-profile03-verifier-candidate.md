# Android profile03 public-verification component

**Experimental component; integrated profile03 and browser-to-phone SMS remain unavailable.**
Tracked in [#1067](https://github.com/pboachie/zrotext/issues/1067), deliberately
stacked on the [outbound SDK composer](https://github.com/pboachie/zrotext/pull/1064).
The [complete integration](https://github.com/pboachie/zrotext/issues/1054)
requires independently authenticated storage, current binding/session permission,
negotiated grants, durable journal and the maintained receiver before any effect.

`Draft03ManifestAuthority` and `Draft03OutboundEnvelope` are independent internal
types. Existing02 parsers, trust store, preparation, callers and corpora are unchanged.
There is no profile fallback, runtime switch, enrollment, key creation, provider
selection, HPKE open, body decrypt, transport, persistence or SMS path in this slice.
Public P-256 point/signature verification uses the existing Java primitives; this
does not introduce a JCA HPKE receiver or replace the selected Wolf implementation.

## Explicit original02 checkpoint

`Accepted02Checkpoint` is a trusted adapter INPUT descriptor, not a self-authenticating
proof or a current permission. It contains the original RootPin02, account, root
fingerprint, generation/version, unsigned digest, original anchor, exact signed-byte
hash and authenticated historical verification time. The real storage adapter
supplying these facts remains absent. Do not derive original anchor/time from the
existing02 authority object, received directory metadata or an OS clock, or decode
the private trust-store record to bypass that missing adapter.

`verifyFrom02` checks the exact retained evidence hash and reuses the existing02
verifier at the authenticated original checkpoint. It then verifies fresh Manifest03
as a same-root/account/generation N+1 successor with predecessor02 and the exact old
unsigned digest. Only generation1 with an explicitly accepted zero original anchor
is supported. An expired02 is HISTORY only; it never supplies current03 signer or
reader permission. Present comparison cannot precede the checkpoint.

This historical inspection API is broader than the SDK/Rust fresh02 creation subset:
their first-transition entry points need a fresh supplied02, while Android requires
the independent original checkpoint. The genuine SDK ciphertext vector exercises
their common fresh02 subset. No cross-platform claim is made for unsupported entry
points. Accepted historical proof and present permission must remain separate.

`verifySuccessor` requires a genuine prior03 instance, same root/account/generation,
N+1/predecessor03/exact old digest, nonregressing comparison and a fresh newly signed
manifest. An expired prior03 may continue history but cannot authorize current use.
`verifyCurrent` verifies a received signature and the same unsigned identity again.
An alternate valid low-s signature is semantic identity, not exact store replay,
permission to replace original bytes, an atomic fork choice or a durable high-water
advance. True03 genesis, rotation/later generations, downgrade and unknown profiles
are unsupported.

The exact Manifest03 grammar, strict root signature, role matrix, scope/subject
zeros, ordering, cardinality, point uniqueness and chain rules are defined in the
[manifest contract](zt-sealed-draft-03-manifest-candidate.md). Independently selected
outbound routing/readers are checked against fresh03 roles, including manifest,
signer and every selected reader validity through the message deadline. Private
constructors and owned input/output copies keep verified snapshots separate from
mutable caller bytes. These checks do not prove a live session or current election.

## Outbound ciphertext and exact context

The verifier accepts only exact outbound03/kind01/zero flags,557..34213 total bytes,
the protected routing/signing fields, canonical peer syntax, positive signed-storage
integers, bounded body ciphertext and ordered exact reader set. It verifies raw64
strict low-s ECDSA over `ZTSE/sign/v3` + NUL + u32be unsigned length + exact unsigned
bytes. Trusted comparison is checked before and after verification; regression,
expiry or changed public context refuses. No parser claim is itself authority.
The verified envelope retains its successful FINAL comparison time. Later `parts`
revalidation cannot precede that time, even if an older manifest instance remains
fresh. This is an instance-local floor, not a global/durable high-water or a record
of every subsequent accessor call.

Revalidated `parts` returns owned public ciphertext and contexts. With
`P3 = retained exact header03 || retained exact protected03`, device wrap inputs are:

- info = `ZTSE/wrap/v3` + NUL + P3 + role01 + key_id32;
- AAD = `ZTSE/wrap-aad/v3` + NUL + P3 + role01 + key_id32;
- body AAD = `ZTSE/body/v3` + NUL + P3.

HPKE info/AAD are nonempty and distinct, with no extra hash, padding or substitution.
The selected Wolf receiver remains unchanged and is not called by this component.
Old02 preparation types cannot consume the new verified envelope type.

## Tests and limits

`sealed-profile03-sdk-outbound-01.json` contains synthetic public manifests and an
actual envelope emitted by `composeSealedOutboundEnvelope03` with fresh random
material and locked HPKE. It contains no recipient scalar. Android independently
checks the signature, roles, routing, hashes and reconstructed contexts. This is
ciphertext/component evidence, not HPKE decryption, Android recipient custody,
live authorization or maintained-provider interoperability.

One shared corpus is inherited by the ordinary Robolectric JVM wrapper and an
AndroidJUnit4 wrapper. Existing Gradle source sets discover both and the protocol
vector. Ordinary CI executes JVM controls and compiles the device wrapper; it does
not execute that wrapper. Synthetic correctly signed malformed cases cover roles,
chain/forks, historical/current time separation, signatures/domains, framing,
routing, full deadlines, clock rechecks and owned snapshots. Synthetic framing
cases with opaque dummy ciphertext are explicitly not producer or HPKE evidence.

A focused ordinary Gradle run passed all twelve JVM controls with no failures or
skips and compiled the AndroidJUnit4 wrapper/shared corpus. Its existing native
preBuild rebuilt and checked the custody library for all four ABIs; the selected
task graph executed no CMake task. This did not execute device instrumentation,
HPKE open or body decryption. The earlier-source failing-baseline exercise has
not been run; the corrected cross-call clock assertion passed in the JVM corpus.

Actual one-use Grant03/signed Fetch03, authenticated original checkpoint/current
binding adapters, immutable Room journal-before-Wolf, maintained open, body lifetime,
submission/unknown reconciliation and reply flow remain integration dependencies.
Real-device/carrier acceptance and Play submission cannot follow from this slice.
