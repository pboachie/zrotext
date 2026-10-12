# Android payload-profile election03 proof component

This component verifies the public E500/bundle628 evidence in the
[candidate election03 contract](payload-profile-election-03.md), using the
existing genuine02 and03 manifest verifiers. It is deliberately limited to the
first02-to03 successor with generation1 and a retained zero32 original anchor.
It does not install a binding, authenticate a storage reader, issue or consume a
grant, open a body, or authorize SMS. Existing02, TrustStore, Room, activation,
DeviceSigning, custody, build and workflow sources are unchanged.

## Trusted inputs and owned evidence

`Draft03PayloadElectionProof.verifyHistorical02` requires retained exact signed02
bytes and the existing structural `Accepted02Checkpoint`, plus independently
retained `lastVerifiedMs` and `comparisonMs`. It checks the exact signed evidence
digest and genuinely verifies02 at the original checkpoint time and comparison
time. Original time <= last verified time <= comparison time; every time is a
positive signed64 `Long`. The returned private-constructor historical token owns
its bytes and genuine verifier output. It proves performed cryptographic checks,
not an independently authenticated owner channel, original genesis lineage,
durable acceptance or the supplied clocks' provenance.

`verifyAccepted` requires bundle628, an independent expected E500, that genuine
historical token, the exact accepted signed03 manifest, two independently selected
P-256 public points, and an `AcceptedRecord03` with these21 fields:

- account, device, line, old binding and new binding UUIDs;
- root fingerprint, original old-binding proof digest and selected reader key ID;
- vault generation, old/new binding generations, prior/accepted manifest versions
  and accepted time;
- prior/accepted semantic manifest digests and exact signed manifest SHA256 values;
- E SHA256, semantic election commitment and complete bundle SHA256.

Arrays have exact widths and nonzero identities/digests; integers remain exact
positive signed64 values, including those above JavaScript's safe Number range.
All byte inputs are bounded and copied before crypto. Structural containers and
copy-out accessors own their arrays. Callers must supply stable exclusively owned
snapshots during the initial copy: later mutation cannot change the result, but
concurrent writers during copying are not supported. No shallow data-class copy,
callback clock or hidden global high-water mark is used.

The new binding UUID is absent from E500. Its nonzero shape and equality to a
current tuple are checked; the future authenticated H2/H6 adapter must supply its
actual durable allocation and exact election mapping. Echoing E from a bundle as
the expected E does not establish independent challenge provenance. Original
owner/device session, enrollment/approval registry and selected reader permission
checks remain trusted adapter obligations, matching the Rust election verifier.
The old proof digest is compared as exact accepted evidence; it is not recreated
from a later activation or substituted for original activation protocol evidence.

## Exact cryptographic and temporal checks

The verifier requires header `ZTPE 03 01 02 03`, zero4 reserved bytes, exact E
equality, all accepted fields, nonzero challenge/nonce/origin/session digests,
strictly advancing binding generation (reservation gaps allowed) and manifest
version N+1 without overflow. It checks positive issued/expiry values, a lifetime
of at most300000ms, and accepted time in the half-open ceremony window. All u64
wire values must fit nonnegative signed64 storage before semantic comparisons.

The stricter common Rust/Android subset genuinely rechecks02 fresh at election
acceptance, then verifies the exact first03 successor at that acceptance time.
Acceptance must not precede the historical comparison floor. Parent Android's
broader expired02-history helper is unchanged. Recovery may occur after the
ceremony or old02 expires because these checks use authenticated recorded times;
historical success supplies no present permission.

Exact signed02, signed03, E and complete bundle hashes must match the accepted
record. The commitment is SHA256 of the contract's domain-separated, length-framed
E transcript. Manifest account, same root, generation, version, predecessor and
semantic digest must match. Received points must be uncompressed on-curve P-256;
their exact signing key IDs use `ZTSE/key/v1`, NUL and algorithm bytes0101.

Received device and owner proofs are raw64 with0<r<n and0<s<=floor(n/2), checked
before conversion to minimal positive DER for JCA verification. No received
signature is normalized. Device proof uses the exact device/v1 domain over E;
owner proof uses owner/v1 over E plus SHA256 of the exact received device raw64.
The owner approval key is independent of the root manifest signing key.

## Fresh comparison is a separate boundary

`proof.requireCurrent` requires a genuine03 manifest, a structural trusted present
`CurrentAuthority03` selection and positive `nowMs`. Its16 fields are profile,
manifest profile, account/device/line/binding UUIDs, binding generation, selected
reader ID, root fingerprint, vault generation, manifest version/digest, election
commitment/bundle SHA256, comparison time and permission expiry.

Both profiles must be03. Now must be at least accepted time, present comparison
time and the genuine manifest's captured comparison floor, and strictly before
present permission expiry. The exact installed selection/election tuple must
match the accepted proof. The manifest is freshly reverified with the existing
genuine current verifier; same root/account/generation and exact current semantic
position must match. Later genuine03 successors are allowed. An alternate valid
current root signature can prove the same semantic identity; it cannot replace
the exact original signed acceptance evidence or stored election bundle.

The private-constructor returned comparison is evidence only. It authenticates
neither the structural input's origin nor atomicity with the manifest, and it
does not supply a lock, CAS, replay consumption, installation ACK or permission
capability. A fresh authenticated caller/session and a same-installed-state
current reader remain necessary for each later effect. Historical ceremony
sessions never become later permissions, and repeat calls do not advance another
call's time floor or prevent independently supplied concurrent forks.

## Defined controls and execution status

Twelve shared JUnit groups reconstruct the existing public synthetic vector and
cover all21 accepted fields, independently expected E, correctly signed invalid
semantics, burned-generation gaps/full signed64 bounds, wrong keys/domains/points,
raw scalar ranges, mathematically valid high-s twins, owner's exact device-proof
digest, exact versus semantic signed evidence, checkpoint/time/anchor provenance,
root-signed successor failures, all16 present tuple fields, mutation ownership and
pure replay/fork limitations. Synthetic keys remain in test-process memory and
export no private scalar. No hardware key or real account/device data is used.

The ordinary Robolectric API34 wrapper and AndroidJUnit4 wrapper inherit that
corpus. Existing Gradle shared source/resource sets and ordinary CI discovery
need no changes. The first ordinary JVM execution compiled and ran all twelve
groups: eleven passed and the mutation-ownership group failed because its
accepted and current fixtures used independently randomized signed bundles.
The corrected fixture retains independent pristine evidence for the same exact
bundle before mutating inputs; production evidence equality is unchanged.
The corrected ordinary offline continuation passed all twelve JVM groups with
zero failures, errors or skips and compiled the AndroidJUnit4 device wrapper.
All four mandatory native custody ABI outputs were checked through the ordinary
preBuild task; their unchanged earlier release outputs were reused through normal
build fingerprints. Main Kotlin compilation was up-to-date; the corrected shared
test corpus and device wrapper compiled in the continuation. The run completed
44 actionable tasks:14 executed and30 up-to-date, with no CMake task selected.
Both the original eleven-pass/one-failure attempt and the successful continuation
are retained. Instrumentation, full Android/lint, runtime and SMS remain unrun.

H6 still needs actual authenticated election transport, same-Room installed03
state, old-generation CAS, exact evidence retention, installation ACK and fresh
permission/current-state reads. One-use grant/fetch, journal-before-Wolf, dynamic
SDK ciphertext opening, submit/reply, UNKNOWN handling and the useful Play SMS
workflow remain separate integrations. This component has no runtime mount and
provides no profile fallback after refusal.
