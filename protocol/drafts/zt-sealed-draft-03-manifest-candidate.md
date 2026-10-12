# Proposed Manifest03 and authenticated same-root successor

**Proposed contract; no production profile 03 implementation or capability is available.**
This contract/vector slice is tracked in [#1055](https://github.com/pboachie/zrotext/issues/1055).
The actual SDK → server → current grant/signed fetch → durable Android journal → maintained
receiver integration remains open in [#1054](https://github.com/pboachie/zrotext/issues/1054).
Synthetic signatures, software HPKE component checks and byte vectors do not establish
current session authority, durable transactions, Android interoperability or release readiness.
Existing profile 02 bytes, APIs and tests stay unchanged. Never retry another profile or provider
after refusal. Envelope profiles, line-activation transcript versions and grant versions are separate.

All binary integers are unsigned big-endian and bounded to signed-storage range where specified.
Identity UUIDs are nonzero raw16, except mandatory zero manifest role-subject slots.
`L(label, payload)` takes an ASCII label WITHOUT a NUL, appends exactly one NUL byte, then u32be payload length and exact payload. The label argument itself must contain no NUL.
Manifest, envelope and election object signatures are raw64 P-256/SHA256, strict scalar-range
and low-s checked before verification; received signatures are never normalized. **Fetch03 is
the explicit exception: its device proof is strict canonical DER, as specified in the dispatch contract.**


| Offset | Bytes | Field |
|---|---:|---|
| 0..5 | 5 | ASCII ZTMA then 03 (manifest format) |
| 5..6 | 1 | envelope_profile = 03 |
| 6..7 | 1 | predecessor_profile = 00, 02 or 03, under the trusted cases below |
| 7..23 | 16 | account_id |
| 23..31 | 8 | vault_generation |
| 31..39 | 8 | keyset_version |
| 39..47 | 8 | issued_ms |
| 47..55 | 8 | expires_ms |
| 55..87 | 32 | previous_manifest_digest |
| 87..152 | 65 | uncompressed on-curve root_public_point |
| 152..153 | 1 | key_count, 1..64 |
| 153..153+149*n | 149*n | ordered role records |
| 153+149*n..217+149*n | 64 | root signature |

Unsigned length is 153+149*n, total length 217+149*n, bounds 366..9753. Record bytes and exact role/scope/subject/order/cardinality/point-reuse checks remain the existing 149-byte Manifest02 matrix, including role 06 same-root active record covering the whole signed interval, exactly one active archive role 02, role 01 exact selected device/line, role 05 exact owner-approved line, active direction-specific readers and strict key intervals. This is a specification reuse, not permission to parse 03 with existing offset helpers. The signature transcript is `L("ZTSE/manifest/v3", unsigned03)`. Semantic digest is SHA256(unsigned03), including BOTH new discriminator bytes.

The trusted verifier entry point must require a typed predecessor state chosen from durable authenticated state, never from received predecessor_profile alone:

1. **CrossFrom02:** previously accepted profile=02, exact account/root pin/fingerprint/generation/version N/digest D and retained signed Manifest02 bytes. Require received predecessor_profile=02, same account/root/generation, version exactly N+1 without overflow and previous_manifest_digest=D. Independently reverify the predecessor's original owner signature/pin and semantic identity using its accepted historical checkpoint, not new key lists; current use still requires live authority/time checks. Manifest03's valid root signature explicitly authorizes the cross-profile successor. This Manifest03 IS the successor certificate; no redundant independently accepted transition object is introduced.
2. **After03:** accepted profile=03 and exact predecessor N/D. Require predecessor_profile=03, same account/root/generation, exact N+1 and D.
3. **Current03:** require exact stored profile=03, account/root/generation/version/digest and retained signed bytes' semantic identity. Received predecessor_profile must match the stored signed object. Different unsigned bytes at the same version are a fork. Alternate valid low-s root signatures over identical unsigned bytes are the same CRYPTOGRAPHIC manifest identity, not necessarily the same transport/store replay. Existing042 exact signed-byte immutability remains: do not replace persisted signed bytes, weaken same-version evidence checks, or grant idempotent transport success merely because unsigned digest matches. An alternate signature may be verified as semantic identity without installing it; current store replay continues to enforce its exact original evidence. Neither case advances high-water.
4. **True Genesis03 contract case:** independently authenticated RootPin02, generation=1, version=1, predecessor_profile=00, previous digest zero, and an atomic durable proof that no authority or prior enrollment/high-water exists for this account. Absent local client state is not proof of absent server authority. No existing 02 account may use this branch. Later-generation roots need a separately reviewed real rotation/anchor contract and are unsupported here.

The proposed first production cut supports CrossFrom02/After03/Current03 only. Truly new account 03 setup is explicitly unsupported until the independent enrollment/absence transaction and owner client are implemented; no fabricated 02 messages or prior activity is required. A genesis03 vector is a verifier-contract test, not evidence of a working new-account setup route. Existing 02 setup can continue unchanged where independently supported.

Manifest freshness remains issued>0, expires>issued, lifetime<=86,400,000ms, issued<=trusted_now+300,000ms, trusted_now<expires, signed-storage bounds and no trusted-time high-water regression. Same-root profile upgrade does not reset root generation, anchor, chain, trusted clock or revocation state. A 03 current authority refuses any 02 successor/current installation; read-only historical 02 verification is separately typed and cannot construct current ExpectedContext03. The one-account authority row needs an explicit immutable-transitioned profile discriminator and preserved previous signed checkpoint; merely enlarging its byte-length CHECK is unsafe.


## Required role matrix

Each 149-byte record is role1 || key_id32 || point[65] || device16 || line16 || scope_u16 ||
valid_from_u64 || valid_until_u64 || state1. All points are on-curve uncompressed P-256,
IDs match the role algorithm, points never repeat, and records sort strictly(role,key_id).

| Role | Scope | Device subject | Line subject |
|---|---|---|---|
|01 payload ECDH|0004|nonzero selected device|nonzero selected line|
|02 archive ECDH|000c|zero|zero|
|03 integration ECDH|0004,0008,000c|zero|zero|
|04 device event ECDSA|0002|nonzero selected device|nonzero selected line|
|05 integration ECDSA|0001|zero|nonzero owner-approved line|
|06 owner root ECDSA|0000|zero|zero|

State01 is active,02 revoked, all others refused. Intervals satisfy from<=until; authorization
requires active and from<=trusted_now<until. Exactly one role 06 matches the root header,
is active and covers the manifest interval. Exactly one active role 02 archive is required.
No other role/scope/subject is accepted, even if root-signed. One-record syntactic minimum
cannot satisfy owner/archive cardinality. The verifier's typed result is not live permission:
current durable authority, authenticated session and immutable elected binding remain mandatory.

The original02 snapshot is independently verified as historical public authority; it must not be
installed through03 context, selected using03 readers, or used with a caller-chosen old clock to
authorize current effects. Persist exact evidence under existing immutability/replay policies.
Actual authority publication/enrollment/storage adapters are deferred under #1054.

## Pure server cryptographic component

`crates/server/src/sealed_manifest03` verifies bounded generation-one CrossFrom02,
Successor03 and Current03 evidence in the ordinary server library. It does not
install an authority row, route, capability or envelope admission path. The
original profile02 verifier and its callers remain unchanged.

Its explicit authenticated02 checkpoint includes the actual retained anchor and
original acceptance/current comparison checkpoints. The legacy Rust02 result
does not retain that anchor or original comparison time. The new component
independently reverifies exact signed02 against the supplied stored identity,
captures the supplied anchor unchanged and refuses nonzero anchors; it never
manufactures a zero anchor or infers genesis from a later predecessor digest.
The checkpoint input is trusted adapter context, not a self-authenticating wire
object. The real H2 reader/archive/currentness adapter remains unimplemented.

Only fresh supplied02 is supported for the first upgrade. An expired03 result
can be chain history for a fresh successor but cannot supply current permission.
Alternate valid signatures can establish semantic current identity without
replacing original stored evidence. No global clock, durable ancestry, atomic
fork selection, enrollment, rotation or true genesis03 acceptance is supplied.
