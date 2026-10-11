# Proposed closed profile03 grant and signed-fetch contract

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


This is a separate new closed wire grammar, not a modification to existing grant_version=1 or line transcript protocol_version=2. Proposed negotiated protocol is `zrotext-device-status-v2+sealed-dispatch-v3`. New closed GrantFrame03 has EVERY existing GrantFrame field, with v=1, type=`sealed_execution_grant`, grant_version=3, reader_role=1, segment_count 1..6, and required additional fields envelope_profile=3, manifest_profile=3, trust_generation, manifest_version, manifest_digest, root_fingerprint, election_digest. All numbers are positive signed-storage-range values; all digest strings are canonical 43-character unpadded base64url, decoded32. UUID textual JSON must be exactly canonical lowercase hyphenated36 characters, parse to a nonzero UUID, and round-trip to that identical spelling; signature transcript uses raw16. Uppercase, brace, compact, URN and alternative spellings are refused. No unknown/missing fields, nullable profile, inferred default or unbound extension.

Fetch03 is closed `{grant: GrantFrame03, signature_der: canonical_base64url_DER}`. DER uses strict canonical minimal positive INTEGER r/s, canonical SEQUENCE length, no trailing bytes, valid P-256 scalar ranges and low-s BEFORE verification; total8..71 bytes (high-s/max72-byte forms refused). Base64url is unpadded and must round-trip exactly. This preserves the current strict device enrollment signature convention under the new transcript; proof signs the EXACT transcript below, never the v1 transcript. Ready03 is closed with grant_version=3, envelope_profile=3, manifest_profile=3, connection_epoch, deployment_epoch, line_id, binding_generation, reader_key_id, trust_generation, manifest_version, manifest_digest, root_fingerprint and election_digest. The authenticated session already pins account/device; all fields must match its durable current03 binding/authority. Old readiness cannot mint03 grants. Client inability yields explicit unsupported_profile before enqueue/fetch/effect, no auto-retry02/plaintext.

Fetch transcript bytes, in this exact order:

1. ASCII `ZT/sealed-envelope-fetch/v3\0`.
2. Six bytes: v, grant_version, envelope_profile, manifest_profile, reader_role, segment_count = 01 03 03 03 01 count.
3. Five raw UUIDs: account_id, device_id, line_id, message_id, attempt_id.
4. Seven u64be: connection_epoch, deployment_epoch, binding_generation, attempt_generation, expires_at_ms, trust_generation, manifest_version.
5. Six decoded digests: reader_key_id, envelope_sha256, unsigned_sha256, manifest_digest, root_fingerprint, election_digest.

Transcript length is domain-byte-length +334. JSON property order never determines signature bytes. Grant may not outlive any original binding/session/manifest/signer/reader/dispatch deadline. Signed fetch remains one-use/exact-replay according to the retained current grant/fence transaction; fetching does not itself prove submission or renew grant. Every added field must be persisted and compared to current authority, session and exact envelope at server fetch and Android validation. Existing02 grant shape/transcript/vector remains byte identical.

This fixes the finite wire format. Full source consumers, HTTP endpoint naming/error mapping, session-binding adapter serialization and one-use fetch transaction integration remain owner handoff work below; the first contract cut must NOT advertise the negotiated protocol as available.

### Complete closed GrantFrame03 field set

There are exactly 25 required fields. No field from another grant version is
accepted implicitly. JSON property order has no meaning for the signature.

| Required field(s) | Type and rule |
|---|---|
| `v` | integer 1 |
| `type` | exact string `sealed_execution_grant` |
| `grant_version` | integer 3 |
| `envelope_profile`, `manifest_profile` | integer 3 each |
| `reader_role` | integer 1 |
| `segment_count` | integer 1..6 |
| `account_id`, `device_id`, `line_id`, `message_id`, `attempt_id` | nonzero canonical lowercase hyphenated 36-character UUID |
| `connection_epoch`, `deployment_epoch`, `binding_generation`, `attempt_generation`, `expires_at_ms`, `trust_generation`, `manifest_version` | positive integral value, at most 2^63-1; reject fractional, rounded or out-of-range values |
| `reader_key_id`, `envelope_sha256`, `unsigned_sha256`, `manifest_digest`, `root_fingerprint`, `election_digest` | canonical unpadded base64url encoding of exactly 32 bytes, exact round-trip |

The vector's numeric values fit the JavaScript safe-integer subset. The test-only
Node encoder rejects already-rounded or unsafe Number values; Python also checks
the full signed-storage boundary. A production JSON adapter must preserve the
integer exactly before signing or comparing it; no production adapter is supplied.

### Complete closed Ready03 wire object

Ready03 has exactly these 15 required fields, including its frame header; there is
no implicit header inherited from a caller or another grant version:

| Required field(s) | Type and rule |
|---|---|
| `v` | integer 1 |
| `type` | exact string `sealed_ready` |
| `grant_version`, `envelope_profile`, `manifest_profile` | integer 3 each |
| `connection_epoch`, `deployment_epoch`, `binding_generation`, `trust_generation`, `manifest_version` | positive integral value, at most 2^63-1, preserved exactly; Node test JSON subset requires safe integers |
| `line_id` | nonzero canonical lowercase hyphenated 36-character UUID |
| `reader_key_id`, `manifest_digest`, `root_fingerprint`, `election_digest` | exact canonical unpadded base64url encoding of 32 bytes |

Missing, unknown, null, wrong-type and noncanonical fields fail closed. JSON numeric
strings are not substitutes for numeric fields. Readiness is not signed election
or grant authority: the future authenticated session adapter must independently
compare account/device identity, current line/binding/reader, manifest/election and
all session/deployment fences before issuing a grant. These live comparisons and
one-use consumption remain unimplemented. The synthetic Ready03 vector and tests
exercise only this closed wire grammar.


## Required execution ordering

Real SDK03 composition and authenticated server admission persist exact ciphertext. The device
negotiates03 using its current authenticated session and elected binding, receives the actual
one-use grant, signs Fetch03 and obtains the byte-identical persisted envelope through current
server fences. Android independently verifies root/manifest/chain, local line/binding/session,
grant/digests/time and envelope, then commits the real durable preparation journal BEFORE
calling the unchanged strict Wolf receiver. Plaintext/body/segment checks and safe close/abort
follow; cryptographic acceptance never authorizes a duplicate radio attempt. Unknown effects
remain unknown. These consumers/transactions and maintained-provider integrated tests are NOT
implemented by this slice. Old capability/grant/profile must refuse03 rather than infer support.
