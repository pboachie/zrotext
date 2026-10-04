# Proposed managed-reader signed evidence

This dormant pure verifier checks signatures, exact bindings and accepted-history
interval consistency. It configures no issuer and grants no installed or current
authority. An assurance label is a signed claim, not evidence of truthful custody.
It provides no database, startup option, root installation, grant issuance, signing,
HPKE or runtime caller. The managed-AI runtime remains unavailable.

All integers are unsigned big-endian and positive, bounded to `2^63-1`, except
assurance labels `0..2`. IDs are nonzero 16-byte values; digests nonzero 32-byte
values. Points are exact 65-byte uncompressed on-curve P-256 points. Key IDs retain
`SHA256("ZTSE/key/v1\0" || algorithm_u16 || point)`: ECDH uses `0010`, signatures
use `0101`. Origin is exact canonical HTTPS ASCII, 9..512 bytes. Unknown tags,
flags, suites, padding, trailing bytes or normalized aliases refuse.

## Operator policy P

The unsigned object is `ZMPC || 01 || 01`, followed in order by:

```text
account[16]; origin_length:u16; origin[origin_length]
issuer[16]; issuer_key_id[32]; issuer_point[65]
policy[16]; policy_version:u64
recipient_role:u8=3; scope:u16=8; kem:u16=0010; kdf:u16=0001; aead:u16=0001
maximum_attestation_lifetime_ms:u64; retention_contract_digest[32]
valid_from_ms:u64; valid_until_ms:u64; minimum_assurance:u8; runtime_count:u8
runtime[runtime_count] = id[16] || evidence_contract_digest[32] || assurance:u8
```

There are 1..16 strictly ID-sorted distinct runtime records. Assurance is declared
software `0`, isolation `1` or hardware `2`; each record meets the minimum.
Maximum lifetime is 1..86,400,000 milliseconds. P is exactly
`228 + origin_length + 49 * runtime_count` bytes, 286..1524. Its digest is
`SHA256("ZT/managed-reader/operator-policy/v1\0" || u32(P.length) || P)`.

The verifier independently receives expected account, origin, policy ID/version
and this digest. Parsing P cannot authenticate deployment configuration. A hash
provided with P in the same untrusted request is not an operator pin. No configured
runtime issuer consumes this result.

## Enrollment E

The unsigned object is `ZMRE || 01 || 01`, followed in order by:

```text
enrollment[16]; account[16]; owner_user[16]; owner_session[16]; approval[16]
origin_length:u16; origin[origin_length]; issued_ms:u64; deadline_ms:u64
root_generation:u64=1; root_fingerprint[32]
predecessor_version:u64; predecessor_digest[32]
successor_version:u64; successor_digest[32]
reader_config[16]; reader_generation:u64; reader_key_id[32]; reader_point[65]
workload[16]; auth_point[65]; auth_key_id[32]
issuer[16]; policy[16]; policy_version:u64; policy_digest[32]
runtime[16]; evidence_digest[32]; scope:u16=8
recipient_from_ms:u64; recipient_until_ms:u64
```

E is exactly `596 + origin_length` bytes, 605..1108. The successor is exactly
predecessor plus one, with a different digest. A pure verification result does not
verify or install the proposed successor manifest. The root signature is detached
64-byte canonical low-S ECDSA P-256/SHA-256 over
`"ZT/managed-reader/enrollment/v1\0" || u32(E.length) || E`.
The semantic enrollment digest hashes that same transcript, excluding signature
randomness. The ceremony window is at most 60,000 milliseconds.

## Issuer attestation I

The unsigned object is `ZMCP || 01 || 01`, followed in order by:

```text
enrollment[16]; account[16]; root_generation:u64=1; root_fingerprint[32]
predecessor_version:u64; predecessor_digest[32]
reader_config[16]; reader_generation:u64; reader_key_id[32]; reader_point[65]
workload[16]; auth_key_id[32]; issuer[16]; policy[16]
policy_version:u64; policy_digest[32]; runtime[16]; raw_evidence_digest[32]
assurance:u8; issued_ms:u64; expires_ms:u64; scope:u16=8
recipient_from_ms:u64; recipient_until_ms:u64
```

I is exactly 442 bytes. Its detached canonical low-S signature uses the pinned
issuer point over `"ZT/managed-reader/custody-policy/v1\0" || u32(442) || I`.
E.evidence_digest is the hash of this transcript. It differs from
I.raw_evidence_digest, which commits to opaque evidence bytes and does not prove
their truth or availability. No cyclic commitment includes E's digest in I.

## Actual history and comparison

The input must contain a genuine privately constructed `VerifiedManifest`, a
94-byte generation-one RootPin02, independently compared fingerprint and selected
account-archive role-2 key ID. The maintained history helper supplies the actual
root point and validity, manifest identity/validity and active archive record.
RootPin02 contains account, generation and point; it has no expiry fields.
The maintained fingerprint parser ties this pin to the derived point and account.
No unrelated caller root-point/expiry tuple can substitute for this history.

The comparison time is an explicit external trust input. Accepted history proves
cryptographic consistency, not current installation or durable high-water. The
helper requires active role-2 scope-12 and root role-6 scope-zero records at that
time. E/I's predecessor must equal the actual accepted manifest. All E/I binding
fields must match; intended owner/workload/recipient IDs and points are supplied
independently. Issuer, workload-auth, recipient, root and archive points differ.
I/P evidence lifetime covers the exact recipient interval within actual root and
manifest validity. Neither an early comparison nor expired authority can pass.

The private result exposes copied public signed metadata and semantic identities
with redacted diagnostics. It is not a session, execution permit or live custody
proof. Request authentication/counters, production policy activation, issuer
evidence interpretation and managed task execution require separate implementation.
