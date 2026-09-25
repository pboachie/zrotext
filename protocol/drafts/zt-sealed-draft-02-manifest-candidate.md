# ZT sealed profile 02: authorization and manifest candidate

**Unaccepted, test-only decision candidate, 2026-09-24.** This extends the [profile-02 envelope proposal](zt-sealed-draft-02-proposal.md) for ZT-009 Q1–Q4 and Q6–Q7. It does not change profile 01, connect a production route, or approve sealed mode. The [decision log](zt-009-decision-log.md) stays open. The small [TypeScript verifier](../../sdk/typescript/src/draft02-manifest.ts) exercises these bytes and policies. A separate [test-only IndexedDB adapter](../../sdk/typescript/src/draft02-trust-store.ts) persists its accepted state; neither component supplies production enrollment or trust recovery, an Android verifier, or a supported HPKE provider.

## Trusted genesis and local state (Q1)

The owner generates a P-256 authorization root in an owner-controlled client. The initial enrollment card/QR carries the exact 94-byte `RootPin02`:

```text
magic[4] = 5a 54 52 50                         # ZTRP
profile:u8 = 02
account_id[16]                                # nonzero
vault_generation:u64 = 1
root_public_point[65]                         # on-curve P-256
EOF
root_fingerprint[32] = SHA-256("ZTSE/root-pin/v2\0" || exact_94_bytes)
```

A receiving SDK/phone compares the **full fingerprint** through an authenticated owner-controlled channel distinct from the relay directory and the QR payload. This comparison binds account ID, generation and root point together; comparing a fingerprint delivered with the same untrusted QR would prove nothing. After comparison it pins the exact root point, account ID and generation. It must reject an unpinned directory response even when its manifest signature verifies. A relay-served browser alone cannot establish this trust against a malicious relay that can replace the browser code; the independently delivered owner client and recovery-card UX remain product decisions.

The pinned durable state is `{account_id, generation, root_point, version, semantic_manifest_digest, anchor_digest, last_trusted_time}`. For account genesis, `version=0`, digest and anchor are 32 zero bytes. Client code must persist an accepted state atomically **before** any envelope or radio effect. The test-only IndexedDB adapter writes this state with a read/write transaction and compare-and-update check: concurrent tabs starting from the same predecessor cannot both commit. It rejects a decreasing caller-supplied time and corrupt stored records. This is browser-local evidence only. IndexedDB deletion, eviction, or restoration of an older database can remove or roll back the pin, and the caller's clock is not independently trusted. Those cases still require independently authenticated re-enrollment or a freshness checkpoint before production effects.

## Exact Manifest02 bytes and identity (Q2, Q6, Q7)

All integers are unsigned big-endian, bounded to `0..2^63-1` for signed storage interoperability. No optional fields, JSON normalization, unknown roles/bits, padding or trailing bytes are permitted. `Manifest02` reuses the bounded draft-01 field order but has a distinct profile byte and signature domain:

```text
magic[4] = 5a 54 4d 41                         # ZTMA
profile:u8 = 02
account_id[16]
vault_generation:u64
keyset_version:u64
issued_ms:u64
expires_ms:u64
previous_manifest_digest[32]
root_public_point[65]                         # 04 || x[32] || y[32], on P-256
key_count:u8 = 1..64
key[key_count] = role:u8 || key_id[32] || public_point[65] ||
                 subject_device_id[16] || subject_line_id[16] || scope_bitmap:u16 ||
                 valid_from_ms:u64 || valid_until_ms:u64 || state:u8
signature[64] = fixed-width P-256 r[32] || s[32], canonical low-s
EOF
```

The unsigned prefix is exactly `151 + 149 * key_count` bytes. The complete object is exactly `215 + 149 * key_count`, 364..9,751 bytes; reject oversized input before reading the count. Records are strictly sorted by `(role, key_id)` and points may not repeat across any records or roles. Every point must be an on-curve uncompressed P-256 point. The existing candidate key ID stays `SHA-256("ZTSE/key/v1\0" || algorithm_u16 || public_point)`, where roles 01–03 use `0x0010` and roles 04–06 use `0x0101`.

The owner signs `"ZTSE/manifest/v2\0" || u32(unsigned_len) || exact_unsigned_bytes` with ECDSA P-256/SHA-256. The receiving verifier checks raw scalar ranges and `s <= floor(n/2)` **before** signature verification. Sender normalization maps a generated high `s` to `n-s`; a receiver never normalizes a received signature. The manifest's authorization identity is **`SHA-256(exact_unsigned_bytes)`**, not a hash of the signature. The complete signed bytes are retained as evidence. A second valid low-s signature over identical unsigned bytes is the same keyset; different unsigned bytes at the same generation/version are a fork. This avoids signature randomness or ECDSA malleability changing envelope or chain references. The existing draft-01 high-s fixture remains valid only under draft 01.

The exact semantic digest above is the profile-02 envelope `manifest_digest`, the next manifest's `previous_manifest_digest`, and the transition's `last_manifest_digest`. Profile-01 complete-signed-byte digest references are never silently reinterpreted; migration needs an explicit reviewed version transition.

### Candidate role and scope matrix

| Role | Meaning | Exact scope | Subjects | Operational rule |
|---|---|---:|---|---|
| `01` | selected device payload ECDH | `0x0004` outbound decrypt | nonzero exact device and line IDs | One outbound wrap for the selected device/line. |
| `02` | account archive ECDH | `0x000c` outbound and inbound decrypt | both zero | Exactly one active archive record and one outbound archive wrap. |
| `03` | approved integration ECDH | `0x0004`, `0x0008`, or `0x000c` | both zero | At most six explicit wraps, only in granted directions. |
| `04` | device event ECDSA | `0x0002` inbound sign | nonzero exact device and line IDs | Cannot sign outbound or a manifest. |
| `05` | integration ECDSA | `0x0001` outbound sign | zero device ID and nonzero exact line ID | May sign outbound only for its owner-approved line; cannot sign inbound or a manifest. |
| `06` | owner root ECDSA | `0x0000` | both zero | Exactly one, active, same point as root header; signs manifests and root transitions only. |

No other bit or role is valid. `state=01` is active; `02` is revoked. Every record has `valid_from_ms <= valid_until_ms`. A key authorizes an operation only while `state=01` and `valid_from_ms <= now < valid_until_ms`, and while the containing manifest is fresh. Revoked records may remain in the chain for audit but never authorize new effects. A root record must cover the whole manifest interval. Signer and recipient checks use both `(role, key_id)`; no key/point reuse across roles. The selected device/line must match the trusted live line binding and M1 grant at effect time; the parser's manifest checks alone do not prove that binding.

The earlier [ZT-009 decision proposal](zt-009-decision-proposal.md) suggested scope `0` for encryption records. This versioned candidate instead makes outbound/inbound decryption direction explicit with bits `0x0004` and `0x0008`. Neither proposal is accepted; selecting this matrix requires owner approval and regenerated cross-client vectors.

**Q2 founder choice (2026-09-24):** integration signing keys are restricted to owner-approved lines. Profile 02 uses the existing owner-signed `subject_line_id[16]` in each role-05 record as one exact allowed line; its `subject_device_id[16]` must be zero. A key approved for several lines needs a distinct signing key and signed record per line. The outbound verifier must compare the record line with the envelope's signed `line_id` before accepting its signature or any effect. Zero-line role-05 records are invalid, including when a root signs them. API-token scope cannot replace owner-signed line authority that an offline phone verifies. This choice does not yet define integration identity, recipient limits, registration, archive retention or the live M1 line/grant transaction; those remain open for production.

## Chain, rotation and loss (Q3)

Account genesis requires `generation=1`, `version=1`, and a zero `previous_manifest_digest` under the separately compared root pin. A normal successor has the same account/generation/root, `version = last_version + 1`, and `previous_manifest_digest = last semantic digest`. Exact same-version semantic-digest replay is idempotent; a different digest is a fork. Gaps, rollback and root substitution fail closed. The verifier accepts one successor at a time; transport must provide all missing predecessors and persist the new high-water atomically.

`RootTransition02` is separate from a manifest:

```text
magic[4] = 5a 54 52 54                         # ZTRT
profile:u8 = 02
account_id[16]
old_generation:u64
new_generation:u64 = old_generation + 1
old_root_public_point[65]
new_root_public_point[65]
last_manifest_digest[32]                      # semantic digest of pinned last manifest
issued_ms:u64
expires_ms:u64
old_root_signature[64]
new_root_signature[64]
EOF
```

The unsigned transition is exactly 215 bytes; the complete object is exactly 343. Both roots sign the same `"ZTSE/root-transition/v2\0" || u32(215) || exact_unsigned_bytes`, each with strict low-s raw ECDSA. The old signature authorizes continuity and the new signature proves possession. The owner initiation pins the **expected new root point** before accepting a transition. The signed window is at most 24 hours and must be current. The first manifest under the new root has the same account, `generation=old+1`, `version=1`, and `previous_manifest_digest = SHA-256(exact_unsigned_transition_bytes)`; the transition links that digest back to the old last semantic manifest digest. A duplicate or conflicting transition at the same generation must be surfaced as a fork, with local acceptance of only one atomically persisted result.

If every old root and recovery credential is lost, there is no cryptographic continuity proof. The candidate requires a visibly new out-of-band root enrollment on **every** client, with explicit history/recovery warnings. Account login or a directory claim must never silently reset the pin or increment generation. Whether such a reset retains the account ID, creates a new identity, and can recover old archive ciphertext is a founder decision; this test verifier implements only signed continuity, not lost-root reset.

## Freshness and revocation (Q4)

Candidate maximum manifest and transition lifetime is 24 hours: `0 < expires_ms - issued_ms <= 86,400,000`. `issued_ms` may be at most five minutes ahead of trusted local time, and `now < expires_ms`; expiry is exclusive. Key intervals are also exclusive at `valid_until_ms`. A withheld revocation may remain effective for nearly **24 hours plus clock uncertainty** if a client last accepted a just-issued manifest. A relay can always deny service; local high-water cannot prove a fresher manifest exists or prove cross-client consistency. After expiry, sealed outbound must stop and inbound must quarantine pending a fresh manifest. An independent witness/transparency or shorter period is needed if that exposure is unacceptable.

**Q4 founder choice:** accept the 24-hour offline/stale-key exposure and fail-closed expiry behavior, or select a shorter period and availability tradeoff. The test verifier only checks a supplied `now` and high-water; trusted clock, reboot/backup rollback defense, withheld-update detection and cross-client fork evidence remain unimplemented.

## Envelope authorization transcript (Q7)

The profile-02 header/protected bytes `P2`, HPKE `info`, empty HPKE AAD, nonempty body AAD and origin signature input remain exactly as in the [envelope proposal](zt-sealed-draft-02-proposal.md). This candidate adds these verification conditions before any effect:

1. Compare envelope account, `keyset_version` and `manifest_digest` to an accepted fresh owner-signed Manifest02; verify the exact received envelope signature using a currently active role-05 key with outbound scope whose signed `subject_line_id` equals the envelope's signed `line_id`. Profile-02 signatures should be low-s under this candidate. No root/archive/reader/device-auth key may substitute as outbound signer.
2. For outbound, require exactly one active role-01 wrap for the selected device/line, one active role-02 archive wrap, and zero to six distinct active role-03 wraps with outbound decrypt scope. Reject extra readers, wrong-role aliases, duplicate wraps, expired/revoked records and any owner-signed manifest whose semantic digest differs from the envelope.
3. Independently compare signed `device_id` and `line_id` with the current binding generation and live grant in the transaction that creates the SMS effect. The existing protected bytes do not carry binding generation, so the atomic database/session check is a Q7 release gate.
4. Retry an existing message only with the same exact envelope identity and durable replay/grant state. A cryptographically valid envelope never by itself authorizes another radio attempt.

The TypeScript `authorizeOutbound02` checks manifest/signer/reader claims **after** a caller has verified the envelope signature; it uses an internal defensive snapshot from `verifyManifest02`, not mutable returned bytes. The later [Android instrumentation proof](../../android/app/src/androidTest/java/org/zrotext/gateway/Draft02ManifestVerifier.kt) does verify browser-generated RootPin02/Manifest02/RootTransition02 and strict low-`s` outbound envelope signatures before a test-only Keystore open. Its pin and comparison fingerprint still arrive from the same test harness, and it has no durable trust or live grant store. A browser/Android/Rust profile-02 vector with independently authenticated enrollment, current line/grant state and replay persistence remains required.

For the candidate kind-02 inbound shape, test-only `authorizeInbound02` requires a verified manifest snapshot, an active role-04 signer bound to the exact device and line with inbound-sign scope, `message_id = event_id`, a positive signed-storage-range local sequence, exactly one active archive wrap and at most six distinct inbound-scoped integration wraps. It rejects role-05 outbound signers, device-payload wraps, wrong direction, revoked records, and changed manifest identity. The caller must independently verify the exact profile-02 envelope signature first. This helper does not parse or authenticate SMS PDUs, establish a live line binding, persist a sequence/replay tombstone, select an inbound age window, or enable an ingest route. Q7 and Q8 remain open.

## Evidence and open gates

The focused TypeScript tests cover a pinned genesis and successor, two independently signed identical manifests with the same semantic digest, forged owner signatures, changed signed bytes, high-s twin, stale/future/wrong-account manifests, rollback/fork/gap, malformed size, role/scope/subject/key-ID/point alias denial, selected-reader checks, wrong-line signer denial even with a valid selected-device reader, and dual-signed rotation with a linked new-generation manifest. A mutation test proves that caller changes to returned byte arrays cannot alter the helper's private verified authority. IndexedDB tests cover persistence across connections, mutation isolation, a same-predecessor concurrent commit, corrupt storage denial, monotonic caller time, and a persisted dual-signed root transition.

The browser→Android API 36 AVD proof independently parses and verifies the same candidate manifest and transition bytes, opens a valid envelope, and denies forged, stale, revoked, wrong-scope, wrong-line and forked authority. Separately generated synthetic public [genesis](../../sdk/typescript/test/vectors/draft02-genesis.json) and [rotation](../../sdk/typescript/test/vectors/draft02-rotation.json) vectors are accepted by TypeScript and a test-only Rust parser. For genesis, Rust independently checks the root fingerprint, exact unsigned digest, low-s owner signature, record IDs, roles and signer line, and rejects a wrong pin, high-s alias and changed record. For rotation, it independently checks both low-s root signatures over the exact 215-byte transition, old semantic digest, transition anchor, new-generation pin and linked first manifest; wrong new root, high-s aliases and broken anchor fail. The vector signing keys were generated ephemerally outside the repositories and were not retained. These Rust tests are bounded cross-language wire checks, not a production Rust sealed client or complete adversarial corpus. These tests do not exercise a physical phone, radio, production route, production trust store, or lost-root recovery ceremony.

Q1 owner-client/bootstrap UX, the remaining Q2 integration identity/registration/reader and key-loss rules, Q3 lost-root identity/recovery, and Q4 exposure/availability still need decisions. Q5 still needs a supported non-exportable Android HPKE provider contract. Q6 low-`s` policy acceptance and a broader cross-language adversarial corpus, and Q7 live grant/line/replay integration remain open. Q8–Q11 remain open. This candidate cannot justify production sealed-content claims.
