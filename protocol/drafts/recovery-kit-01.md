# Recovery token and public root card candidate

**Proposed pure formats, not custody or a recovery ceremony.** The
`zrotext-root-material::recovery_kit` module has no filesystem, terminal, network,
random generation or output operation. Its explicit exposure API is not
permission to reveal actual recovery material. Offline initialization, secure
storage, fresh-process restore, independently authenticated distribution and
online enrollment remain separate gates. Rotation, reset and archive recovery
are unsupported.

## Intended context

A `KitContext` consumes an independently intended `ExpectedIdentity`, exact
RootPin02 bytes and a nonzero 16-byte backup ID. It checks the existing canonical
HTTPS origin rules (1–512 ASCII bytes), nonzero 16-byte account identity, the
exact 94-byte genesis pin with generation one and an uncompressed valid P-256
point, and the full fingerprint. IDs use the existing binary identity rules;
this format adds no textual UUID parser or silent normalization.

Context construction does not prove an independent comparison. Do not derive
expected identity solely from a card or backup's own metadata. A future custody
flow must independently compare the full intended identity and verify both
backup AEAD tags before exposing or using a restored root.

## Secret token

The token contains a uniformly random 32-byte recovery secret supplied by the
caller. Neither this parser nor the backup codec can establish its entropy.
It is not a password or a mnemonic-derived key.

The exact 79-byte ASCII grammar is:

```text
"ZTRK1-" || group[0] || "-" || ... || group[12] || "-" || checksum_hex[8]
```

The thirteen groups each contain four uppercase RFC 4648 Base32 characters
(`A`–`Z`, `2`–`7`). Concatenate them to obtain the 52-character unpadded encoding
of exactly 32 bytes. The final symbol's four unused bits must be zero. There are
no aliases, lowercase letters, padding, whitespace, Unicode substitutions or
alternative separators. The last group occupies offsets 66–69, the final
separator offset 70, and the uppercase checksum offsets 71–78. Reject short,
extra or oversized input before allocating or decoding; require an exact
canonical re-encoding after decoding.

The checksum is the first four bytes of SHA-256, rendered as eight uppercase
hexadecimal characters, over this exact concatenation:

```text
ASCII "ZTSE/recovery-kit/v1" || NUL
|| account_id[16] || generation[u64be = 1] || backup_id[16]
|| full_root_fingerprint[32] || origin_length[u16be] || exact_origin[N]
|| recovery_secret[32]
```

This 32-bit checksum detects accidental transcription/context errors only.
Anyone with a candidate secret can recompute it; it is neither a MAC nor an
identity or backup-authentication proof. A correctly formed token with a
different secret must still fail authenticated backup opening. The 256-bit
secret and accepted vault KDF are unchanged.

## Secret handling

`RecoverySecret` and `RecoveryToken` own zeroizing storage and have fixed,
redacted Debug output. They do not implement Display, Clone, serialization or
implicit conversion to strings. Token formatting uses fixed zeroizing buffers
for Base32, checksum and token bytes; decoding zeroizes partially decoded bytes
on all error paths. `RecoveryToken::expose_ascii` is an explicit borrowed view
only; it performs no output. The caller must protect/zeroize borrowed input and
any deliberate copies. Errors contain fixed messages and never include input
bytes, field contents or decoder diagnostics.

The standard `data-encoding` dependency was already locked in the workspace; its
bounded encode/decode APIs avoid custom Base32 and ordinary temporary Strings.
Hash zeroization features remain enabled. These measures are memory hygiene,
not a guarantee against compiler/library temporaries, swap, crash capture or a
compromised host. Actual secret reveal and terminal privacy are not implemented.

## Public card

The public card contains no recovery secret or scalar. Its exact bytes are:

| Offset | Field | Width |
|---:|---|---:|
| 0 | ASCII `ZTRC` | 4 |
| 4 | Version `01` | 1 |
| 5 | Origin byte length N, unsigned big-endian | 2 |
| 7 | Exact canonical origin | N |
| 7 + N | Exact RootPin02 | 94 |
| 101 + N | SHA-256 of the exact encrypted backup | 32 |

Total length is exactly `133 + N`, at most 645 bytes. There is no padding,
optional field or extension. Reject unknown magic/version, bad length, invalid
origin/pin and trailing data. The decoder requires independently expected
identity and the expected digest of the actual encrypted backup; it validates
both before returning public fields. The digest binds bytes but does not prove
authenticity, freshness, independent comparison or publisher identity. No
public-card-to-trust conversion or automatic kit context constructor exists.

## Tests and limits

`cargo test --locked -p zrotext-root-material recovery_kit::tests` exercises
the shared synthetic vector, all token/card byte mutations and truncations,
pad bits, alphabet/case/separators, wrong context, maximum lengths, redaction,
and a valid-checksum token that fails backup AEAD authentication.

The [fixture](../v1/vectors/recovery-kit-01.json) is explicitly synthetic. Test
code derives its recovery bytes from a descriptive test label and reuses the
existing synthetic backup vector. The fixture stores only a one-way token digest,
not a literal token or recovery secret. Independent Python `base64`/`hashlib` code
reconstructs the complete token, context checksum, public card and backup digest
through existing protocol CI discovery. No actual owner kit or publisher key is
created, exported or stored by these operations.
