# Android Keystore HPKE provider study (draft Q5)

**Test and decision aid, 2026-09-24.** This does not accept draft 01, enable
sealed mode, or add a production decryptor. The required wrap is RFC 9180 base
mode DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, with a raw 65-byte
`enc`, 48-byte ciphertext for one 32-byte CEK, and the draft's distinct,
nonempty `info` and AAD. The Android recipient private key must stay in
Android Keystore on API 31+.

## Evaluated implementation paths

| Path | Exact `info` and AAD | Non-exportable P-256 recipient | Finding |
| --- | --- | --- | --- |
| Tink Java high-level HPKE | `contextInfo` supplies `info`; its decryptor uses empty AAD | Takes raw private-key bytes | Cannot open draft wraps with the required key claim. |
| Tink Java Keystore helper | `contextInfo` supplies `info`; `open` still uses empty AAD | Caller supplies raw ECDH output from Keystore, not a Keystore key handle | Does not meet the AAD requirement. It is also under `hybrid.internal`. |
| Bouncy Castle HPKE | Exposes separate `info` and AAD | P-256 `Decap` consumes `ECPrivateKeyParameters` containing a scalar | Its public HPKE receiver cannot use the Android Keystore key. Its custom KEM constructor cannot be used for an out-of-package adapter because the abstract KEM methods are package-private. |
| Android platform HPKE | Exposes separate inputs | Native API begins at 37; the documented provider currently implements only X25519 | Does not serve the selected API 31+ floor or P-256 draft suite. |

These findings were checked against [Tink Java
`2e9bad7`](https://github.com/tink-crypto/tink-java/blob/2e9bad7ce3d644bf8fdd4d10d4bd7c33564a4862/src/main/java/com/google/crypto/tink/hybrid/internal/HpkeHelperForAndroidKeystore.java),
its [ordinary decryptor](https://github.com/tink-crypto/tink-java/blob/2e9bad7ce3d644bf8fdd4d10d4bd7c33564a4862/src/main/java/com/google/crypto/tink/hybrid/internal/HpkeDecrypt.java),
[Bouncy Castle `94270ff` HPKE](https://github.com/bcgit/bc-java/blob/94270ff1cb4efe4c015178d679af7d28837bd5bc/core/src/main/java/org/bouncycastle/crypto/hpke/HPKE.java),
its [DHKEM](https://github.com/bcgit/bc-java/blob/94270ff1cb4efe4c015178d679af7d28837bd5bc/core/src/main/java/org/bouncycastle/crypto/hpke/DHKEM.java)
and [KEM extension type](https://github.com/bcgit/bc-java/blob/94270ff1cb4efe4c015178d679af7d28837bd5bc/core/src/main/java/org/bouncycastle/crypto/hpke/KEM.java),
and the Android [HPKE](https://developer.android.com/reference/android/crypto/hpke/Hpke)
and [KEM parameter](https://developer.android.com/reference/android/crypto/hpke/KemParameterSpec)
API references. This is a bounded search of those maintained paths, not a
claim that no other library or future provider could work.

## Test-only interoperability evidence

The [Android instrumentation proof](../../android/app/src/androidTest/java/org/zrotext/gateway/M2KeystoreHpkeProofTest.kt)
uses Keystore `PURPOSE_AGREE_KEY` and a test-only RFC 9180 composition. It
opened the official [P-256 known answer](https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.1)
with nonempty AAD, then opened a draft-shaped wrap with a generated
non-exportable recipient key. The separate [TypeScript vector
suite](../../sdk/typescript/README.md) pins `@hpke/core` 1.7.5 and passes seven
RFC/draft tests. Its emulator-only [host
harness](../../sdk/typescript/test/android-keystore-interop.mjs) used
`@hpke/core` to seal to a newly generated API 36 Pixel AVD Keystore public
point; Android independently reconstructed the draft key ID, `info` and AAD,
opened the 32-byte CEK, rejected changed `info`/AAD, and deleted the temporary
alias. The focused Gradle build succeeded and the host harness printed `PASS`.

The separate Samsung SM-S928U API 36 test reported
`KeyInfo.securityLevel=TRUSTED_ENVIRONMENT`, successful Keystore ECDH/open,
and alias deletion (`OK (3 tests)`). This is reported platform evidence for
one temporary key, not independent hardware attestation or key-lifecycle
proof. No SMS or network/power setting was involved in either test.

## Remaining Q5 decision

The platform can perform the cryptographic operation, but none of the
evaluated maintained high-level APIs directly handles both the non-exportable
P-256 recipient and this draft's nonempty AAD on API 31+. The test-only
composition is not a selected production provider. Engineering must select a
supported provider or explicitly own and validate the composition, including
point parsing, key ID and role binding, key loss/reboot, device API and security
levels, independent Rust/browser vectors, fuzz/adversarial cases, and the
complete signed envelope and grant boundary. Keep sealed mode disabled and Q5
open until that choice and the remaining ZT-009 decisions are recorded.
