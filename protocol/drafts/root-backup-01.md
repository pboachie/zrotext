# Generation-one encrypted root backup candidate

**Proposed, dormant codec.** This root-only format implements a bounded portion
of the accepted Q10 derivation in the [decision log](zt-009-decision-log.md).
It does not close Q1, Q3 or Q10, implement custody or make a client ready for use.
It depends on the [candidate enrollment](root-enrollment-01.md) identity rules.
No CLI, file I/O, terminal reveal, registration, reset, rotation or runtime caller
is included. It contains no archive keys and cannot recover message history.

## Inputs and outputs

`root_backup::seal` accepts a canonical P-256 scalar in a `RootSecret`, a
32-byte `RecoverySecret`, and independently supplied expected account, canonical
origin and full RootPin02 fingerprint. It checks the scalar-derived pin before
requesting randomness. Generation is exactly one. The caller must supply a
uniformly random recovery secret; the codec cannot establish its entropy and
does not accept a password as a substitute for that requirement.

Successful sealing returns only complete ciphertext and authenticated public
metadata. Each call requests fresh system randomness for a nonzero backup ID,
random vault key, salt and two nonces. A randomness failure, including failure
after partially filling a buffer, returns no partial backup. Existing backups
are immutable: there is no edit, rewrap, rotate or update function.

`open` accepts bytes, the recovery secret and the independently expected identity.
It returns a `RootSecret` only after verifying both AEAD tags, the explicit
header identity, scalar range and recomputed root fingerprint. Expected identity
must not be derived solely from untrusted backup metadata. Success establishes
neither freshness nor server registration or independent client trust.

## Header H

All integers are unsigned big-endian. No optional fields or padding are allowed.

| Offset | Field | Width |
|---:|---|---:|
| 0 | Magic `ZTRB` | 4 |
| 4 | Format `01` | 1 |
| 5 | Suite `01` (HKDF-SHA256 and AES-256-GCM) | 1 |
| 6 | Nonzero random backup ID | 16 |
| 22 | Nonzero account ID | 16 |
| 38 | Generation, exactly one | 8 |
| 46 | Full RootPin02 fingerprint | 32 |
| 78 | Origin byte length N | 2 |
| 80 | Exact canonical HTTPS origin | N |

H is exactly `80 + N` bytes. `1 <= N <= 512`, additionally constrained by the
enrollment contract's canonical origin rules. Aliases are rejected, not silently
normalized. The fingerprint binds the exact account, generation and uncompressed
P-256 root public point via the existing RootPin02 domain. Backup ID is a random
public identifier, not a freshness counter or anti-rollback proof.

## Complete object

Let `h = length(H)`:

| Offset | Field | Width |
|---:|---|---:|
| 0 | H | h |
| h | Public recovery salt | 32 |
| h + 32 | Vault-key wrapping nonce | 12 |
| h + 44 | Wrapped vault key, including GCM tag | 48 |
| h + 92 | Root-body nonce | 12 |
| h + 104 | Root ciphertext length, exactly 48 | 4 |
| h + 108 | Root ciphertext, including GCM tag | 48 |

Total length is exactly `236 + N`, at most 748 bytes. Reject oversized input
before parsing/allocation, all truncations/trailing bytes, unknown formats or
suites, zero IDs and inconsistent lengths. The public fields disclose account,
origin, generation and fingerprint; this is not metadata-hiding encryption.

## Cryptographic construction

The root scalar `d` is exactly 32-byte big-endian with `1 <= d < n` for P-256.
The recovery secret R and independently random vault key V are each 32 bytes.
The future custody layer supplies d and R; this codec generates V, salt, nonces
and backup ID using the operating system RNG, failing closed on RNG errors.

The Q10 wrapping derivation is unchanged:

```text
W = HKDF-SHA256(
    IKM = R,
    salt = recovery_salt,
    info = "ZTSE/vault-wrap/v1\0" || account_id || generation_u64be,
    L = 32
)
```

Each `\0` is one zero byte. AAD uses exact received/constructed bytes:

```text
wrap_aad = "ZTSE/vault-key-wrap/v1\0" || H || recovery_salt || wrap_nonce
wrapped_vault_key = AES-256-GCM(W, wrap_nonce, V, wrap_aad)

body_aad = "ZTSE/root-backup/v1\0" || H || recovery_salt || wrap_nonce ||
           wrapped_vault_key || body_nonce || u32be(48)
root_ciphertext = AES-256-GCM(V, body_nonce, d, body_aad)
```

Each ciphertext includes its 16-byte tag. The distinct AAD domains and exact
format above are candidate choices requiring independent review. A new seal uses
fresh V, salt, nonces and backup ID, even when R and d are unchanged. A caller
retrying persistence can reuse the exact completed ciphertext; it must not edit
its authenticated fields or rerun encryption with captured old random values.

After authenticated decryption, derive the public point from d, reconstruct the
generation-one RootPin02, and compare its fingerprint to the independently
expected value. A valid AEAD tag alone is insufficient to accept a malformed or
different scalar. Generation changes and old-root reset are unsupported.

## Secret handling and limitations

R, W, V and scalar buffers use zeroizing storage. In-place AEAD work buffers are
zeroized on success and error paths; enabled RustCrypto zeroization features
cover supported cipher/hash state. Secret wrappers have redacted Debug, no
Display/Clone/serialization implementation, and errors contain fixed messages
without input values. The returned root exposes borrowed bytes for deliberate
caller use; the caller must not copy them into logs or unprotected storage.

This is memory hygiene, not a guarantee against compiler/library temporaries,
swap, crash capture or a compromised host. No OS custody, filesystem permissions,
clipboard/terminal handling or publisher verification is provided. Independently
authenticated client delivery and secret-reveal UX remain prerequisites.

R alone cannot reconstruct a lost backup because V and d are random. A backup
without R is also insufficient. Login/password/MFA recovery cannot replace R or
the root. Copied old backup/secret pairs cannot be remotely revoked. Future root
rotation requires reviewed continuity and every client's trust policy; there is
no freshness, rollback or lost-all-keys escape hatch here. Root-only recovery is
not archive-key recovery; retained message history needs a separate vault format.

## Verification

Run `cargo test --locked -p zrotext-root-material root_backup::tests`. Tests cover
round-trip, redaction, entropy faults after partial fill, fresh entropy for each
seal, every-byte mutations, all truncations, extra/oversize bytes, identity/secret
mismatches, origin/scalar bounds and authenticated malformed/different roots.

The public [fixture](../v1/vectors/root-backup-01.json) contains ciphertext and
public pin/fingerprint only. Test code derives clearly synthetic secret inputs
from descriptive labels. Independent Node/OpenSSL HKDF and GCM code constructs
the same complete object and verifies both tags; the existing
`test_ztse_draft_vectors.py` CI discovery executes it. No actual owner root,
recovery secret or private-key file is generated by these tests.

Dependency justification: RustCrypto `hkdf` supplies the accepted standard KDF
without a handwritten implementation. Existing AES-GCM/HMAC/SHA-256 crates enable
their zeroization features; no CLI or custody dependency is introduced.

The implementation lives in the pure `zrotext-root-material` workspace crate.
The existing `zrotext_server::root_backup` path re-exports the same module and
types. Server compatibility tests open the unchanged ciphertext vector through
that path. The crate has no server, database or network dependency; extraction
does not add kit formats, CLI commands, file handling or custody.
