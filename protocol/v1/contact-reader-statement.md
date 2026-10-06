# Dormant contact reader statement

ZTKA01 is a pure candidate signed-statement contract for the first foundation
under #789 and #634. Its codec does not install contact access, prove private-key
possession, provide custody, seal/open fields, sign, authorize a current owner,
or perform storage/network effects. Names/notes currently still use the server
vault. Contact field/mutation envelopes and actual client intake remain separate.

The only result is `historical_integrity`: the exact canonical statement has an
authentic owner-root signature and matches already accepted generation-one
manifest history and an independently compared expected genesis fingerprint.
There is no `allowed`, `current`, lease, grant or installation result. A valid
old signature cannot prove the latest contact revision or deletion state.

## Exact framing

All integers use big-endian network order. UUIDs are nonzero canonical 16 bytes;
digests/key IDs are nonzero 32 bytes. Positive integers are at most i64::MAX.
The origin is exact canonical HTTPS ASCII, 9..512 bytes, without userinfo,
path/query/fragment, host-case/default-port aliases or normalization fallback.

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 4 | ASCII ZTKA |
| 4 | 1 | Version 1 |
| 5 | 1 | Declared capability 3 (seal/open intent only) |
| 6 | 16 | Authorization UUID |
| 22 | 16 | Account UUID |
| 38 | 2 | Origin byte length N |
| 40 | N | Exact origin |
| 40+N | 8 | Trust generation, exactly 1 in this cut |
| 48+N | 8 | Accepted manifest version |
| 56+N | 8 | Declared reader generation |
| 64+N | 32 | Independently expected genesis root fingerprint |
| 96+N | 32 | Manifest semantic digest |
| 128+N | 32 | Exact role-2 archive reader ID |
| 160+N | 65 | Uncompressed P-256 reader point |
| 225+N | 8 | Declared issued milliseconds |
| 233+N | 8 | Declared until milliseconds |
| 241+N | 64 | Canonical low-s fixed-width P-256 ECDSA signature |

Unsigned length is 241+N, signed length 305+N (314..817). No alternate lengths,
versions, capabilities, trailing bytes or optional fields are accepted. The
signature covers ASCII `ZT/contact-reader/authorization/v1`, NUL, unsigned length
as u32, and all exact unsigned bytes, using maintained ECDSA/SHA-256. DER/high-s
aliases and signatures from other domains fail. Statement identity is SHA-256
of complete signed bytes; manifest identity remains its unsigned semantic digest.

The synchronous unsigned encoder checks SEC1 framing only. It does not prove
actual point membership or trust. The TypeScript parser is asynchronous and uses
maintained WebCrypto importKey for curve validity; Rust parsing uses maintained
P-256 validation synchronously. Both parsers validate exact reader key identity
using `ZTSE/key/v1`, NUL, algorithm bytes 0x0010 and the exact point. Neither parser
verifies a signature or creates the privately branded verified result.

## Accepted history and declared time

The sole comparison mode is `declared_issued_ms`. The certificate's signed issued
time is a statement consistency point, not a trusted observation of when it was
signed, installed or accepted. It must be at or after the manifest's issued time
and within the selected active reader/root record bounds. Until must be later
than issued, at most 24 hours later, and no later than manifest/reader/root expiry.
There is no added certificate skew allowance.

Exact role-2 scope 12 and role-6 scope 0 records come from the maintained verified
snapshot, never mutable public manifest projections. The root record must be
the accepted root and the reader ID/point must match exactly. Inspecting those
public records does not widen their scopes or grant contact access. Generation
two, unaccepted history, a chain gap or unknown root transition is refused.

Expected account/origin/root fingerprint must originate outside a malicious
relay projection. The existing genesis fingerprint is SHA-256 of
`ZTSE/root-pin/v2`, NUL, and exact 94-byte ZTRP02/account/generation-one/root point.
The codec cannot establish that the caller independently compared it or durably
accepted a manifest checkpoint. It reuses that trust input without enrolling it.

Expired retained statements can prove historical integrity with accepted history;
they do not restore today's reader authority. Current admission and custody,
final database time, installed certificate identity and independent contact
high-water/deletion checkpoints are required by later reviewed runtime cuts.

## API and evidence boundary

TypeScript parsing captures bounded bytes before its first await. Verification
captures statement and expected identity, selects actual branded public records,
verifies exact signature, then returns an opaque immutable privately branded
result. Its identity accessor refuses manual/cloned results and returns defensive
copies. Rust verified constructors are private and Debug omits identities/bytes.
Errors do not serialize source identities. Public inert library exports create
no runtime caller, permission, contact routing or decryption operation.

The accompanying schema describes closed synthetic vector representations; it
does not replace binary, signature, curve, manifest or independent trust checks.
Shared vectors and ordinary SDK/Rust tests exercise canonical bytes/digests,
signature/role/identity/domain/bounds substitutions, mutable projections and
historical/current confusion. This is protocol/library evidence, not installed
storage, key custody, client-encrypted contacts, opaque export, owner UI or pilot
acceptance. No dependency, handler, migration or provider call is introduced.
