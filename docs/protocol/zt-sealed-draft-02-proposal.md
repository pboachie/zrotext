# ZT sealed content: byte profile draft 02 proposal

**Test-only proposal, 2026-09-24. No production client may emit or accept profile 02.** Profile 01 and its fixtures remain unchanged. This proposal tests a versioned HPKE single-shot transcript that can be opened through Tink Java's Android Keystore helper. It does not settle the other ZT-009 product and authorization decisions.

## Profile delta from draft 01

The envelope grammar, limits, field meanings, ordered wrap set, 32-byte CEK, AES-256-GCM body, ECDSA P-256 origin signature, and HPKE suite remain as in [draft 01](zt-sealed-draft-01.md). The wire `profile:u8` becomes `02`. Parsers must select exactly one profile, reject unknown profiles, and never try another profile after authentication failure. Existing profile-01 vectors must not be reinterpreted as profile 02.

The HPKE suite is RFC 9180 base mode DHKEM(P-256, HKDF-SHA256) `0x0010` / HKDF-SHA256 `0x0001` / AES-128-GCM `0x0001`, with `NO_PREFIX`. Each wrap uses one fresh sender context, exactly one `Seal`, a 65-byte uncompressed on-curve `enc`, and a 48-byte `ct` for the 32-byte CEK. A recipient uses only the wrap matching a pinned, currently authorized `(role, key_id)`; HPKE base mode itself does not authenticate the sender.

Define `P2` as the **exact received bytes** `magic[4] || profile:u8(02) || kind:u8 || flags:u16 || protected_len:u16 || protected[protected_len]`, before `body_nonce`. It is 10 bytes plus `protected_len`. It includes the account, message/device/line identities, keyset version, manifest digest, signer ID, times, peer and kind-specific identity/intent through `protected`. The candidate key ID remains `SHA-256(ASCII("ZTSE/key/v1\0") || 0x0010 || public_point_65)`; a key's ID therefore does not change solely because the envelope profile changes.

For each wrap, the proposed RFC 9180 inputs are:

```text
info = ASCII("ZTSE/wrap/v2\0") || P2 || role:u8 || key_id[32]
aad  = empty byte string
```

`info` is 213 bytes for a 157-byte `protected` record; the maximum under draft-01 grammar is 241 bytes. Use the full byte string, including the exact length and profile fields, without JSON conversion, normalization, or hashing by the application. The HPKE key schedule hashes `info` into its context; an altered `P2`, role, or key ID must fail CEK opening. The recipient must independently reconstruct `info` from the parsed, bounded **received** bytes and compare identity/authorization to a trusted manifest before using the opened CEK. It must not take an attacker-supplied parallel `info` field. The empty HPKE AAD is intentional and cannot be interpreted as draft 01's nonempty AAD.

The body and signature remain nonempty and domain-separated, with profile-02 labels:

```text
body_aad = ASCII("ZTSE/body/v2\0") || P2
body_ct  = AES-256-GCM-Seal(CEK, body_nonce[12], body_aad, strict_utf8_body), serialized ciphertext || tag[16]
unsigned = exact envelope bytes from magic through the final wrap
signature_input = ASCII("ZTSE/sign/v2\0") || u32(len(unsigned)) || unsigned
signature = ECDSA-P-256-SHA256(signature_input), raw r[32] || s[32]
```

The origin signature covers the body nonce/ciphertext and every wrap role, key ID, `enc`, and `ct`. It is checked against an authorized manifest signer and its permitted role/scope; a valid signature alone is not authorization. Body AAD binds the whole protected context again to body plaintext. Retries replay the same full envelope; they do not create a new HPKE context or body nonce. Q2/Q4/Q6–Q11 and grant/radio release gates remain open.

[RFC 9180 section 8.1](https://www.rfc-editor.org/rfc/rfc9180.html#section-8.1) specifically recommends putting auxiliary authenticated information in Setup `info` for single-shot APIs. Draft 02 uses one `Seal` per wrap, so no varying per-context message AAD is needed. The profile change is explicit because draft-01 `info`/AAD ciphertexts are not interoperable with these inputs.

## Android provider feasibility and limit

Tink Java 1.23.0's `HpkeHelperForAndroidKeystore` takes a caller-produced P-256 ECDH result, recipient public key, `enc`, `ct`, and nonempty `contextInfo` and performs the remaining RFC 9180 KEM/key-schedule/open operations with empty AAD. Its accepted suite includes the IDs above and `NO_PREFIX`. The caller can use API 31+ Android Keystore `KeyAgreement` with a non-exportable `PrivateKey`; only the 32-byte ECDH result enters app memory and must be cleared promptly. Non-exportability does not imply hardware backing; device `KeyInfo.securityLevel` must be recorded separately. [Tink helper source](https://github.com/tink-crypto/tink-java/blob/v1.23.0/src/main/java/com/google/crypto/tink/hybrid/internal/HpkeHelperForAndroidKeystore.java#L22-L110).

This is **not yet a stable production provider approval**: the helper is in Tink's `hybrid.internal` package, and `HpkePublicKey.create` is marked `@RestrictedApi` for partial-key access. A released, public Java method is callable for a test, but its package and annotation do not promise a supported compatibility surface. Keep Tink only on the Android instrumentation-test classpath in this branch. Before production, obtain a supported upstream API or make and review an explicit dependency/support decision, then complete signed-envelope, manifest, replay, API-floor, key-loss, hardware-level, and independent Rust/browser vectors. [Tink public-key source](https://github.com/tink-crypto/tink-java/blob/v1.23.0/src/main/java/com/google/crypto/tink/hybrid/HpkePublicKey.java#L151-L179).

The `M2Draft02TinkKeystoreTest` and `android-tink-draft02-interop.mjs` proof reuse the public draft-01 outbound `protected` fixture under a profile-02 header, with an emulator-only generated Android Keystore recipient and independent `@hpke/core` sender. They test correct CEK opening, changed `info`/protected/profile/role/key-ID rejection, changed ciphertext rejection, invalid `enc` rejection, lost-key denial and alias cleanup. This is a wrap proof, not a complete signed profile-02 envelope. It does not invoke a production sealed route, SMS, or a physical phone.

## Complete outbound envelope candidate evidence

The separate [Android instrumentation receiver](../../android/app/src/androidTest/java/org/zrotext/gateway/Draft02TinkEnvelopeReceiver.kt), [test-only Manifest02 verifier](../../android/app/src/androidTest/java/org/zrotext/gateway/Draft02ManifestVerifier.kt), and [browser harness](../../sdk/typescript/test/android-tink-draft02-envelope.mjs) build and open a complete **outbound** profile-02 envelope. The browser uses Web Crypto for AES-256-GCM body encryption and low-`s` ECDSA P-256 signing, and `@hpke/core` for two independent HPKE wraps (device and archive). It creates exact RootPin02, owner-signed Manifest02, and dual-signed RootTransition02 bytes. Android bounds and verifies the pin fingerprint, manifest signature, semantic digest, roles/scopes/subjects, freshness and reader set before checking the exact `ZTSE/sign/v2\0 || u32(unsigned_len) || unsigned` signature with JCA, opening the device wrap through Tink 1.23.0 and non-exportable Keystore ECDH, and authenticating the body with nonempty profile-02 AAD. The public draft-01 `Protected` fixture supplies synthetic identities; its manifest digest and version are replaced with the generated profile-02 manifest identity. Web Crypto ECDSA signatures and the Keystore public point vary per run, so this is an executable cross-client vector, not a pinned byte-for-byte fixture.

The harness includes focused negatives for an altered or high-`s` envelope signature, profile, truncated/trailing envelope, invalid `enc`, wrong HPKE `info`, wrong signed manifest digest or peer, a forged owner signature, stale manifest, wrong signed signer scope, revoked signer with a separately signed matching envelope, same-version semantic-digest fork, wrong pin fingerprint, wrong selected device, forged new-root transition signature, duplicate message, and a signed conflicting envelope with the same message ID. It also exercises a valid two-root transition and first manifest under the new generation. Two signed mutants isolate body integrity: changed nonce must fail AES-GCM, and a changed message ID with fresh HPKE wraps and valid signature must fail because the original body ciphertext used the old body AAD. A deleted Keystore alias must fail closed. This harness is restricted to an emulator and invokes no phone or radio path.

The root fingerprint and pin arrive together from the same browser test process; that proves exact-byte interoperability, **not** an independently authenticated owner comparison. Android has no durable root/high-water store, trusted clock or live line/grant transaction. The in-memory replay journal only proves sequential duplicate/conflict behavior within one process; it is not durable, atomic across workers, or tied to the M1 grant state. The archive wrap is authorized by its owner-signed record and syntax-checked, but the phone cannot prove archive decryption without the archive private key. Low-`s` enforcement is a profile-02 candidate exercised here, not an accepted Q6 product decision.

| Remaining ZT-009 gate | Gap after this proof |
|---|---|
| Q1–Q4 | Exact pin/manifest/transition bytes and browser→Android verification work in a test. Independent owner comparison, accepted role/scope policy, lost-root ceremony, trusted clock, durable high-water, withheld-update and cross-client fork witness remain open. |
| Q5 | Tink's helper is in `hybrid.internal`; `HpkePublicKey.create` is `@RestrictedApi`. API 31 device behavior, supported-provider contract, reboot/key-loss lifecycle and physical security level for draft 02 remain open. |
| Q6–Q7 | Test-only low-`s` manifest/transition/envelope verification and outbound role/reader checks pass. Policy acceptance, Rust vectors, live binding-generation/grant transaction, inbound transcript and full adversarial corpus remain open. |
| Q8–Q10 | Inbound multipart/event sequencing, durable replay, SMS segment UX, vault and recovery remain open. |
| Q11 | No sealed-only production route, downgrade test, deployed leakage sweep or backup/log canary evidence. |

The released dependency is pinned only on the instrumentation-test classpath. Neither this receiver nor Tink is in the app's production source/runtime classpath. No profile-02 route is enabled.

## Separate authorization candidate

The [Manifest02 authorization candidate](zt-sealed-draft-02-manifest-candidate.md) proposes the exact owner-signed manifest and dual-signed root-transition bytes, semantic **unsigned-byte** manifest digest, role/scope and freshness rules, and strict low-`s` signatures exercised by this test-only Android proof. The TypeScript verifier retains private, defensive snapshots of verified authority and high-water state so mutating a returned `Uint8Array` cannot change its authorization result. Neither language's helper is a production trust store or stable provider contract. Q1–Q4 and Q6–Q11 stay open until the proposed choices are accepted and the remaining release evidence exists.
