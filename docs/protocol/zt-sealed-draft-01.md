# ZT sealed content: byte profile draft 01

**Review candidate, 2026-09-23. No production client may emit or accept this profile yet.** This document gives reviewers concrete bytes to challenge. It is not an approved protocol, a crypto audit, or a claim that the current M1 alpha route is sealed. Changes after review require a new profile revision and new vectors; a parser must never guess a version or fall back to plaintext.

This profile covers one outbound SMS text and one normalized inbound SMS text. It does not encrypt the carrier leg, phone endpoints, visible routing metadata, or served dashboard JavaScript. See [SECURITY-DESIGN.md](../SECURITY-DESIGN.md) for the product claims and [ZT-009 review package](zt-009-review.md) for the remaining decisions and release gate.

## Primitive and key candidates

| Purpose | Draft selection | Encoding / limits |
|---|---|---|
| CEK wrapping | RFC 9180 HPKE base mode, DHKEM(P-256, HKDF-SHA256) `0x0010`, HKDF-SHA256 `0x0001`, AES-128-GCM `0x0001` | One fresh sender context and exactly one `Seal` per wrap; `enc` is 65-byte uncompressed P-256 point, `ct` is 32-byte CEK plus 16-byte tag. HPKE provides recipient confidentiality, not origin authentication. |
| Body | AES-256-GCM | Fresh random 32-byte CEK and 12-byte nonce for **each new message identity**; 16-byte tag appended to ciphertext. Retries replay the same complete envelope bytes. |
| Origin / manifest | ECDSA P-256 with SHA-256 | Public point `0x04 || x[32] || y[32]`; signature `r[32] || s[32]` big-endian. Android Keystore DER output needs strict conversion; malformed `r` or `s` is rejected. ECDSA malleability and low-`s` policy remain a review decision. |
| IDs | UUID and SHA-256 | UUIDs are 16 raw bytes in network order. Key ID is `SHA-256(ASCII("ZTSE/key/v1\0") || algorithm_u16 || public_point_65)`; `algorithm_u16 = 0x0010` for HPKE and `0x0101` for ECDSA. |

The HPKE suite IDs and point length come from [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-7). Browser ECDSA emits fixed-width `r || s` under [Web Crypto](https://www.w3.org/TR/webcrypto/#ecdsa), whereas Android's JCA signature is normally DER. This is a proposed interoperability choice, not a claim that an Android hardware-backed HPKE decapsulation path has been proven.

## Byte conventions and limits

- `||` means exact concatenation. `u8`, `u16`, `u32`, and `u64` are unsigned, fixed-width, big-endian. ASCII labels include the shown trailing zero byte. There is no Unicode normalization, case folding, JSON serialization, optional field, padding, or unrecognized extension in profile 01.
- `peer` is ASCII E.164: `+` followed by 2–15 decimal digits, first digit nonzero. Length is 3–16 bytes. No whitespace. The server treats it as visible routing metadata; the device must compare it before radio submission.
- A text body is 1–32,768 bytes of strict UTF-8 before encryption. No BOM or NUL. The phone rejects invalid UTF-8 and counts actual SMS segments with the selected SIM before a grant can lead to radio submission; the draft limit is six segments. The server cannot verify segment count from ciphertext.
- All lengths and counts are checked before allocation or cryptographic work. The complete envelope is at most 36,864 bytes. Unsupported versions, kinds, flags, trailing bytes, duplicate wraps, noncanonical ordering, invalid points, and inconsistent lengths are errors.
- Timestamp fields are Unix milliseconds in UTC. A sender must use a clock source and expiry policy approved in the final profile. A phone compares expiry with bounded server time offset before radio submission; a timestamp is not a replay defense by itself.

## Envelope grammar

The exact signed wire form is:

```text
magic[4]             = 5a 54 53 45                 # ASCII ZTSE
profile:u8           = 01
kind:u8              = 01 outbound | 02 inbound
flags:u16            = 0000
protected_len:u16    = byte length of Protected below
protected[protected_len]
body_nonce[12]
body_ct_len:u32       = 17..32784
body_ct[body_ct_len] = AES-GCM ciphertext || tag[16]
wrap_count:u8        = 1..8 (outbound 2..8; inbound 1..7)
wrap[wrap_count]     = role:u8 || key_id[32] || enc[65] || hpke_ct[48]
signature[64]        = ECDSA P-256/SHA-256 r[32] || s[32]
EOF                 # no trailing bytes
```

`Protected` is a fixed-order binary record, with kind-specific suffix. There are no field tags, so changing the layout requires a new profile byte. The common prefix is:

```text
account_id[16] || message_id[16] || device_id[16] || line_id[16] ||
keyset_version:u64 || manifest_digest[32] || signer_key_id[32] ||
created_or_observed_ms:u64
```

For `kind=01` append `expires_ms:u64 || intent:u8(=01 SEND_SMS) || peer_len:u8 || peer[peer_len]`. For `kind=02` append `event_id[16] || local_sequence:u64 || peer_len:u8 || peer[peer_len]`. Outbound `peer` is the destination; inbound `peer` is the observed sender. `line_id` is the account's registered, selected phone line identity and is separate from a mutable Android subscription index. Inbound content is emitted only after the device can identify this line unambiguously; otherwise it emits metadata-only evidence under a separate contract, never a guessed sealed SMS body.

The common prefix is exactly **144 bytes**. With `peer_len` in `3..16`, `protected_len` must equal **`154 + peer_len`** for outbound (`157..170` bytes), or **`169 + peer_len`** for inbound (`172..185` bytes). A parser rejects every other length even if the outer envelope's byte count is internally consistent. The generic wrap grammar admits `1..8` records, but kind rules narrow this to **`2..8` outbound** and **`1..7` inbound**.

`manifest_digest` is SHA-256 of the complete signed key manifest bytes. All UUIDs, line identity, sender key, recipient number, keyset version, intent, expiry and inbound event identity are therefore cryptographically bound. The account-scoped `message_id` is immutable for retries and is not the server's attempt ID. Inbound `event_id` plus `local_sequence` supports deduplication; exactly which durable phone journal allocates sequence numbers is a review item.

### Wraps and recipient set

Roles are `01 device_payload`, `02 account_archive`, `03 approved_integration_decrypt`. Wraps are strictly sorted by `(role, key_id)` bytewise and cannot repeat a pair. An outbound envelope contains exactly one `01` wrap for the selected `device_id`, exactly one `02` archive wrap, and at most six `03` wraps from the approved manifest. An inbound envelope contains exactly one `02` archive wrap and zero to six `03` wraps; it has no `01` wrap. The server cannot add a reader or switch devices because the sender signature covers every wrap.

For each wrap, `HPKE info = ASCII("ZTSE/wrap/v1\0") || SHA-256(protected) || role || key_id` and `HPKE aad = ASCII("ZTSE/wrap-aad/v1\0") || protected || role || key_id`. `HPKE Seal` encrypts the same 32-byte CEK once to that public key. A fresh ephemeral key/context is required per wrap. The 65-byte `enc` must be a valid on-curve uncompressed P-256 point; `hpke_ct` is the 48-byte result of one seal. A recipient uses only the wrap whose role and key ID match its pinned, currently authorized private key and rejects all other candidate substitutions.

### Body and signature transcripts

`body_aad = ASCII("ZTSE/body/v1\0") || magic || profile || kind || flags || protected_len || protected`. `body_ct = AES-256-GCM(CEK, body_nonce, body_aad, body_utf8)`, with tag appended. The nonce and ciphertext sit outside `Protected`, but the signature covers both. Changing a metadata byte fails both body authentication and signature verification; changing a wrap or nonce fails the signature.

Let `unsigned` be every byte from `magic` through the final `wrap`, before `signature`. The signature input is `ASCII("ZTSE/sign/v1\0") || u32(len(unsigned)) || unsigned`. `signature` is P-256 ECDSA/SHA-256 over that input (the signing API hashes it once). Signing an already computed SHA-256 digest through a hashing API would hash twice and is forbidden. The sender never signs JSON, reconstructed fields, or a hash of an alternate serialization. A verifier checks the exact received `unsigned` bytes and then checks the sender role/scope in a trusted manifest. Signature validity alone is not authorization.

For idempotency, the server hashes `unsigned`, not randomized ECDSA signature bytes, and binds `(account_id, message_id)` and the HTTP `Idempotency-Key` to that hash. Reuse with different unsigned bytes is a conflict. Reuse with identical bytes cannot produce a second logical send. Replaying an inbound signed envelope uses `(account_id, device_id, event_id)` and a sequence window; it cannot create a second webhook logical event.

## Provisional key manifest bytes

The directory must deliver a complete owner-signed object, not an unverified map of public keys. Candidate `Manifest01` is:

```text
magic[4] = 5a 54 4d 41       # ZTMA
profile:u8 = 01
account_id[16]
vault_generation:u64
keyset_version:u64
issued_ms:u64
expires_ms:u64
previous_manifest_digest[32]  # zero only for genesis
root_public_point[65]
key_count:u8 = 1..64
key[key_count] = role:u8 || key_id[32] || public_point[65] ||
                 subject_device_id[16] || subject_line_id[16] || scope_bitmap:u16 ||
                 valid_from_ms:u64 || valid_until_ms:u64 || state:u8
signature[64]
EOF
```

Records are strictly sorted `(role, key_id)` with no duplicates or unknown roles/states/scopes. Roles distinguish owner authorization, device authentication, device payload, account archive, integration signing and integration decryption. The owner root signs `ASCII("ZTSE/manifest/v1\0") || u32(len(manifest_without_signature)) || manifest_without_signature`. The digest of the complete manifest bytes, including signature, is what the envelope binds. A trusted client pins `(account_id, vault_generation, root fingerprint)`, verifies a monotonic version and previous-digest chain, and persists the highest accepted version before accepting commands. An account login or server directory response alone does **not** authenticate genesis. The owner must provision the initial root fingerprint to the SDK/phone over a separately authenticated comparison or recovery-kit channel.

The candidate manifest role values are `01 device_payload`, `02 account_archive`, `03 integration_decrypt`, `04 device_auth`, `05 integration_sign`, `06 owner_auth`. The first three match the envelope wrap-role bytes. Candidate `state` values are `01 active` and `02 revoked`; other values fail closed. `scope_bitmap` tentatively uses bit `0x0001` for outbound SMS signing and `0x0002` for inbound event signing, with all other bits rejected. The owner root is also in a `06` record matching `root_public_point`. Device roles `01` and `04` require nonzero matching subject device and line IDs; account/archive/integration roles require zero subject IDs unless a later reviewed profile defines narrower integration subjects. Signing roles use key ID algorithm `0x0101`; encryption roles use `0x0010`. A second manifest with the same `(vault_generation, keyset_version)` but a different digest is a fork and must be rejected and surfaced to the owner.

This manifest layout is deliberately incomplete as a release specification: the authoritative scope bitmap, genesis ceremony, signing-root rotation and signed revocation freshness still need the decisions in [ZT-009 review package](zt-009-review.md). Until those are resolved, clients must not implement `Manifest01` as an accepted trust source.

## Processing order and transport boundary

1. Parse the bounded binary envelope exactly; reject unsupported profile/kind and malformed lengths. Compare HTTP/WSS authenticated tenant and selected device with `Protected`; never trust a URL or caller-supplied duplicate routing value over the signed bytes.
2. Obtain the owner-root-pinned manifest and verify signature, account/generation, digest, expiry, prior chain and locally stored high-water mark. Check signer role, scope, validity and revocation, selected line/device and each recipient wrap. A server response without the signed manifest is insufficient.
3. Verify the envelope signature over its original bytes before any decrypt or radio action. Check message/event identity, expiry and replay store. The relay checks authorization and routing; the device repeats origin, manifest, expiry, line, segment and grant checks immediately before the SMS boundary.
4. The phone unwraps only its device role, opens the body, validates strict UTF-8 and actual segment limit, then follows the existing durable intent/grant protocol. A retry after ambiguous radio submission stays `unknown`; cryptographic acceptance never authorizes a second radio attempt.
5. For inbound, the phone first normalizes and deduplicates the complete received text, allocates a stable event identity, encrypts to archive and explicit readers, signs, and durably queues ciphertext. The relay stores only the envelope and visible metadata and sends the same signed ciphertext in webhooks. A customer's local runtime verifies and decrypts; a plain webhook consumer has no decryption ability.

The proposed public route is a new sealed-only endpoint with raw envelope body and `Content-Type: application/vnd.zrotext.sealed.v1`; it never accepts a `body`, plaintext JSON, or downgrade header. The current private `/v1/alpha` route is a synthetic M1 test mechanism and must not be exposed as a customer plaintext shortcut. Transport JSON, where necessary, carries unpadded base64url of the **same** binary envelope; the verifier never signs or trusts the JSON serialization.

## Required vector set before adoption

Publish licensed, nonsecret byte fixtures in `protocol/v1/vectors/`: RFC 9180 P-256 base-mode known answers; deterministic fixture keys/randomness for outbound and inbound envelopes; exact protected/unsigned/signature bytes; TypeScript, Android and Rust cross-open results; manifest chain/rollback cases; and malformed/tamper corpus. Fuzz bounded parsers. Include altered AAD, wrong tenant/device/line/peer, wrong wrap role, invalid point, truncated/extra bytes, oversized count, duplicate wrap, changed expiry, stale manifest, revoked signer, copied ciphertext under a new ID, altered signature, duplicate inbound event and out-of-order sequence. Test concurrent HPKE sender contexts and nonce safety; never reuse a context across concurrent `Seal` operations without the library's proven synchronization.

The test vectors will be generated **after** expert review adjusts this draft. Passing self-generated vectors is not independent protocol validation.
