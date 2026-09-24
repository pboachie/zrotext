# ZT-009 candidate decisions and review gates

**Open decision log, 2026-09-23.** This records proposed wire rules and the decisions needed before the sealed profile can be accepted. No row approves production cryptography. Record the selected choice, alternatives, owner, decision date, and verification evidence in a future revision. A blank acceptance field keeps the gate open.

The companion [draft 01 byte profile](zt-sealed-draft-01.md) is the exact candidate under discussion. [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-7) defines the HPKE P-256 suite identifiers and 65-byte `enc`; [RFC 9180 §7.1.4](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.4) requires validation of P-256 public-key inputs. [Web Crypto ECDSA](https://www.w3.org/TR/webcrypto/#ecdsa) specifies fixed-width `r || s` output and hashes the supplied message. These sources specify primitives, not this application's authorization or recovery policy.

## Candidate wire clarifications made in this revision

| Item | Candidate rule | Remaining gate |
|---|---|---|
| Inbound identity | For kind 02, `message_id` equals `event_id` byte-for-byte; the phone allocates it once and retries replay the same envelope. This is incompatible with the current M1 inbound route, which requires an existing outbound `message_id`, same-device `attempt_id`, and positive sent evidence. A separate sealed inbound contract or revised signed source fields are required. | Q8 and transcript tests (Q7). |
| Envelope bounds | Check exact kind-specific protected size and final offset. With current field/count bounds, maximum 34,213 outbound or 34,082 inbound bytes; the 36,864-byte pre-allocation cap remains. | Parser fuzz corpus and Q7/Q9 review. |
| Manifest bounds | Exactly `215 + 149 * key_count` bytes, count 1..64, maximum 9,751 before allocation. Reject truncation, trailing bytes, wrong ordering/IDs, invalid fixed fields. | Cryptographic validation and role/scope decisions Q2. |
| Manifest identity | Persist complete signed bytes and their digest. Re-signing identical unsigned fields at the same generation/version with a different valid ECDSA signature is a fork, not a harmless refresh. | Genesis, rotation and freshness Q1/Q3/Q4. |

Changing an accepted wire choice requires a new profile byte and regenerated vectors. The structural checks in this revision do not prove signature validity, key authorization, nonce safety or safe implementation.

## Decisions still required

| Gate | Decision owner and required choice | Evidence for closure | Acceptance |
|---|---|---|---|
| Q1 root bootstrap | Product/security: choose an authenticated out-of-band owner-root comparison and recovery ceremony for browser, SDK and phone. | Reproducible enrollment and phishing/key-substitution tests, browser-code limitation stated. | Open |
| Q2 scopes and roles | Product/security: approve a complete per-role scope bitmap, subject binding, validity, registration, expiry and key-loss policy; forbid public-key reuse across roles. | Versioned matrix and cross-account, wrong-role, expired/revoked, extra-reader and cross-role key-alias vectors. | Open |
| Q3 root rotation/reset | Product/security: decide signed root transition and lost-all-keys new-generation ceremony, including owner warnings. | Rotation and recovery bytes, fork tests, lost-all-keys drill. | Open |
| Q4 freshness/revocation | Product/security: set maximum signed-manifest age, offline behavior and stale-key exposure; assess withheld updates and need for a separate witness. | Quantified exposure window; offline, rollback, fork and withholding tests. Local high-water alone is insufficient. | Open |
| Q5 Android HPKE key storage | Product selected sealed mode on API 31+ only; the M1 SMS gateway keeps minSdk 28. Engineering must validate a maintained exact-profile HPKE path with a non-exportable device payload key and distinct nonempty `info` and AAD. | Exact raw `enc`/`ct`, `info` and AAD interoperability on emulator and supported phone, key-storage/security-level evidence, and fail-closed capability gating. | Device floor selected; technical validation open |
| Q6 ECDSA encoding | Engineering/security: choose strict DER/raw conversion and low-`s` normalization or rejection policy. | P-256 signature and malleability vectors on browser, Android and Rust. | Open |
| Q7 transcript binding | Engineering/security: assess every signed/AAD field, role, recipient and replay domain, including inbound identity and M1 integration. | [Transcript matrix](zt-009-transcript-matrix.md), adversarial altered-field and cross-role alias vectors, and documented results. | Open |
| Q8 inbound semantics | Product/Android/security: define multipart normalization boundary, ambiguous line handling, stable event allocation, durable sequence, clock skew and offline replay. | Crash/reboot, duplicate, out-of-order and metadata-only contract tests. | Open |
| Q9 limits and UX | Product/Android: choose SMS encoding, six-segment UX, padding/length disclosure and oversize behavior. | Unicode and segment vectors plus supported-device test; documented metadata leakage. | Open |
| Q10 vault/recovery | Product/security: select separate vault format, recovery-secret KDF, archive retention and key-revocation semantics. | Versioned vault bytes and lost-login, recovery, lost-all and old-ciphertext drills. | Open |
| Q11 downgrade/leakage | Engineering/security: choose sealed-only route and alpha isolation policy; test downgrade paths. | Parser rejection and seeded canary sweep across database, backups, logs, traces, errors and webhook retries. | Open |

ZT-009 closes only after Q1–Q11 have actual decisions, a versioned profile, and reproducible evidence for the stated security properties. ZT-010/011/012 then require interoperable vectors, implementation/recovery evidence, leakage tests and remediation of findings as specified in the [threat model](zt-009-review.md).

## Q5 virtual feasibility observation (2026-09-23)

Two isolated Pixel 8 API 36 emulator tests passed. An Android Keystore P-256 key returned no private encoding and completed provider ECDH. Separately, Tink Java 1.23.0 with a `NO_PREFIX` P-256 HPKE key emitted a 65-byte encapsulated point followed by ciphertext and tag; matching `contextInfo` opened it and changed `contextInfo` failed. These tests did not combine the Keystore key with HPKE decapsulation or test nonempty HPKE AAD.

The ordinary Tink [HPKE decryptor](https://github.com/tink-crypto/tink-java/blob/v1.23.0/src/main/java/com/google/crypto/tink/hybrid/internal/HpkeDecrypt.java) consumes raw private-key bytes. Its [Android Keystore helper](https://github.com/tink-crypto/tink-java/blob/v1.23.0/src/main/java/com/google/crypto/tink/hybrid/internal/HpkeHelperForAndroidKeystore.java) accepts a caller-supplied ECDH result and opens with empty AAD; it does not take a Keystore private key. The draft wrap requires a distinct nonempty AAD, so this library path does not yet satisfy the candidate profile. Q5 stays open pending a maintained compatible path and exact cross-client vectors. No custom ECDH/HPKE bridge was accepted or implemented.

The documented Android Keystore ECDH purpose, [`PURPOSE_AGREE_KEY`](https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_AGREE_KEY), was added in API 31. The current gateway package has `minSdk` 28, so this non-exportable ECDH route cannot be assumed across its stated device range. A software HPKE key encrypted at rest under a [Keystore AEAD key](https://github.com/tink-crypto/tink-java/blob/v1.23.0/src/main/java/com/google/crypto/tink/integration/android/AndroidKeystore.java) would have a different exposure claim because its private bytes enter app memory for decryption. The product decision below excludes API 28–30 from sealed mode; the exact nonempty-AAD HPKE provider and key lifecycle remain open engineering work.

## Q5 product device-floor decision (2026-09-23)

The founder selected **API 31+ for sealed-content mode only**. The existing M1 SMS gateway continues to support API 28+; a phone on API 28–30 must not enroll a sealed payload key, accept a sealed outbound grant, or claim sealed inbound protection. The decision does not authorize a software-key fallback on API 28–30. A future change to that device policy requires a new explicit decision and security review.

For API 31+, the draft's intended device payload private key is non-exportable through Android Keystore. This engineering requirement is not a finding that hardware backing or draft 01 HPKE decapsulation works. Engineering must find a maintained path that opens the exact RFC 9180 P-256 suite with distinct nonempty `info` and AAD while using the Keystore key, or revise the profile and regenerate vectors before any sealed route is enabled. Tests must verify actual provider operations, key security level where claimed, capability denial on API 28–30, and behavior after reboot and key loss. AVD evidence alone does not prove hardware backing; Q5 remains open until compatible implementation and supported-phone evidence exist.
