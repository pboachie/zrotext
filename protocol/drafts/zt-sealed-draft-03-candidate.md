# Proposed sealed envelope profile 03

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

## Exact grammar and limits

```
magic[4] = ASCII ZTSE
profile:u8 = 03
kind:u8 = 01 outbound | 02 inbound
flags:u16 = 0000
protected_len:u16
protected[protected_len]
body_nonce[12]
body_ct_len:u32 = 17..32784
body_ct[body_ct_len]
wrap_count:u8 = outbound 2..8 | inbound 1..7
wrap[wrap_count] = role:u8 || key_id[32] || enc[65] || hpke_ct[48]
signature[64]
EOF
```

The common protected prefix is exactly 144 bytes:
`account_id[16] || message_id[16] || device_id[16] || line_id[16] ||
keyset_version:u64 || manifest_digest[32] || signer_key_id[32] || created_or_observed_ms:u64`.
Outbound appends `expires_ms:u64 || intent:u8(01 SEND_SMS) || peer_len:u8 || peer`.
Inbound appends `event_id[16] || local_sequence:u64 || peer_len:u8 || peer`;
message_id must equal event_id. All identity UUIDs are nonzero. Version, times and sequence
are positive, at most2^63-1. The outbound signed lifetime is positive and at most900000ms.
Freshness/currentness and inbound age enforcement remain production-adapter dependencies.

Peer is exact ASCII E.164 syntax: plus followed by2..15 digits, first digit nonzero,
length3..16, no whitespace or normalization. Synthetic vectors contain no real phone data.
Protected length is exactly 154+peer_len outbound (157..170),169+peer_len inbound (172..185).
The 10-byte header includes protected_len. `P3 = exact_header03 || exact_protected03`.
Body plaintext is1..32768 bytes of strict UTF8 with no BOM or NUL. Ciphertext includes tag16.
Envelope bounds are557..34213 outbound and426..34082 inbound; refuse above 36864 before
parsing and enforce the tighter kind bounds. Check all length arithmetic before allocation,
require exact EOF, zero flags, valid on-curve uncompressed P-256 enc and no trailing bytes.

Wrap roles are01 device payload,02 account archive,03 approved integration. They are strictly
sorted by(role,key_id), no duplicate pair or implicit readers. Outbound has exactly one01 for
selected device/line, one02 and at most six03; inbound has no01, exactly one02 and up to six03.
The matching fresh verified Manifest03 authorizes every signer/reader and exact routing subject.
Envelope manifest_digest is SHA256 of exact unsigned Manifest03, not complete signed bytes.
The signer is active role 05 for outbound/exact line, role 04 for inbound/exact device and line;
scope, reader directions, revocation and lifetime checks use the manifest contract.


The bounded profile 02 envelope/protected/recipient field widths, field order, flags=0, integer bounds, inbound/outbound kind=02/01, reader counts, wrap lengths, body limits and canonical signing rules are retained byte for byte except header profile byte=03 and the following domains. Manifest version/digest fields reference verified Manifest03. No unknown profile is routed by inspecting a prefix.

- Signature: `L("ZTSE/sign/v3", unsigned_envelope03)`.
- Body AES-256-GCM AAD: `"ZTSE/body/v3\0" || exact_header03 || exact_protected03`.
- HPKE: unchanged RFC9180 base mode, P256/HKDF-SHA256/AES-128-GCM, enc=65, CEK=32, wrap ciphertext=48.
- HPKE info: `"ZTSE/wrap/v3\0" || exact_header03 || exact_protected03 || recipient_role:u8 || key_id[32]`.
- HPKE AAD: `"ZTSE/wrap-aad/v3\0" || exact_header03 || exact_protected03 || recipient_role:u8 || key_id[32]`.

Both HPKE inputs are nonempty and distinct by their exact domain bytes; no extra hash/substitution/padding is permitted. The unchanged selected Wolf receiver consumes these exact reconstructed inputs only after typed manifest, envelope, grant and binding validation. An empty-AAD or v2-domain wrap cannot be accepted as 03. Neither Wolf strictness nor 02 semantics is relaxed.


Fresh random CEK32, nonce12 and independent single-shot HPKE sender contexts are required
for each new message; retry the identical complete envelope rather than encrypt again. Signature
covers exact unsigned bytes through the final wrap, including nonce/ciphertext. P-256 signing
APIs hash the transcript exactly once. Key IDs retain SHA256(`ZTSE/key/v1\0 || algorithm_u16 ||
point[65]`), algorithm 0x0010 for roles01..03 and 0x0101 for04..06. Base HPKE alone does not authenticate
the sender. Verify bounded grammar, root/manifest/chain, routing and signature, then durable
binding/session/grant/replay and journal before any maintained receiver or radio effect.

## Integration dependencies

The existing SDK composer/server admission remain profile02. The selected strict Wolf receiver
is unchanged. No production03 composer, route, authority, storage guard, grant, Android parser,
journal adapter or receiver consumer is installed by these documents/tests. Actual pairing must
use the same freshly enrolled non-exportable Android recipient and exact persisted SDK bytes,
current negotiated one-use grant and signed fetch, and real durable journal before Wolf open.
No recipient scalar export, JCA substitute, software fallback, physical/carrier acceptance or
runtime enablement follows from these test-only contracts.

See [manifest](zt-sealed-draft-03-manifest-candidate.md),
[election](payload-profile-election-03.md) and [dispatch](sealed-dispatch-03-candidate.md).
