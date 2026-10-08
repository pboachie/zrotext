# ADR 0010: wolfSSL cryptocb-only Android HPKE receiver bridge

Status: accepted (maintainer selection recorded on issue #1003, 2026-10-06).
This ADR records the selected maintained provider for the sealed profile's
Android receiver and the mechanics of shipping it. It changes no wire format:
the profile stays RFC 9180 base mode DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 /
AES-128-GCM with raw 65-byte `enc`, a 48-byte wrap over a 32-byte CEK, and
distinct nonempty `info` and AAD. Sealed mode stays disabled; nothing in the
gateway service, registration or radio path calls the bridge yet.

## Decision

The Android recipient provider is [wolfSSL](https://github.com/wolfSSL/wolfssl)
pinned to `v5.9.4-stable` (commit `3c5eead4`), built for the NDK with the
crypto-callback-only ECC configuration, with the recipient ECDH executed by
AndroidKeyStore through the wolfSSL crypto-callback boundary (ADR 0009 option
2C). The independent GO-WITH-CONDITIONS review posted on #1003 verified from
the 5.9.4 sources that the P-256 receiver path dispatches the recipient ECDH
through `wc_CryptoCb_Ecdh` before any software math, that the scalar-exporting
copy path is unreachable for device keys, and that `info` and AAD flow to
disjoint uses.

## Binding conditions, as realized

1. **Software ECDH is compiled out.** `android/app/src/main/cpp/user_settings.h`
   defines `WOLF_CRYPTO_CB`, `WOLF_CRYPTO_CB_ONLY_ECC` and
   `WC_NO_DEFAULT_DEVID` — the ECC effect of upstream's
   `--enable-cryptocb=only,no-default-devid`. Any bridge gap fails closed with
   `NO_VALID_DEVID`; there is no software fallback. Upstream's literal
   `cryptocb=only` would additionally strip software SHA-256 and AES, which
   the wolfSSL HPKE receiver itself needs (its AEAD object is created with
   `INVALID_DEVID` and the key schedule runs in software), so those two
   `ONLY` strips are deliberately absent; only the recipient ECDH crosses
   the bridge.
2. **The callback never returns `CRYPTOCB_UNAVAILABLE`.** The registered
   device answers `WC_PK_TYPE_ECDH` through one Keystore `KeyAgreement` per
   open or returns a hard negative error; non-ECDH dispatches to the device
   fail hard.
3. **Wrapper framing.** `HpkeWrapFraming` (Kotlin) and `zt_hpke_open` (native)
   both enforce: `enc` exactly 65 bytes, ciphertext (tag included) at least
   17 bytes, `ctSz` passed to wolfSSL excludes the 16-byte inline tag
   (`C - 16`), plaintext capacity `C - 16`, nonempty and distinct
   `info`/AAD.
4. **API floor unchanged.** Enrollment and opening require API 31+
   `PURPOSE_AGREE_KEY`; API 28-30 is refused at runtime; `minSdk` stays 28.
   Key creation stays enrollment-only via `DevicePayloadKeyStore`; a lost or
   revoked key is refused, never regenerated.
5. **Transients.** The per-message DH secret is materialized once inside the
   Keystore callback and zeroed on both sides of the JNI boundary; wolfSSL
   zeroes the KEM and schedule copies (`hpke.c` `ForceZero`).

## Test architecture

- `android/app/src/main/cpp/tests/zrotext_hpke_kat.c` (host, CI): the RFC
  9180 A.3 known-answer vector opened through the exact vendored wolfSSL
  subset and production wrapper with a software test key, plus negative
  cases (changed info/AAD/tag/key, framing violations, off-curve point) and
  the two fail-closed proofs (unregistered key `NO_VALID_DEVID`; callback
  hard error propagation).
- `WolfHpkeKeystoreBridgeDeviceTest` (API 31+ emulator, `android-device-smoke`
  workflow): the full bridge — enrollment, claims read-back, cross-client
  software-sender seal opened through Keystore, tampering, key loss and
  revocation refusals.
- `HpkeWrapFramingTest` (JVM): the framing rules and API floor.

The host suite is an additional lane, clearly labeled; it is not provider
acceptance and does not replace the Android instrumentation suite. Emulator
results do not establish hardware backing.

## License

wolfSSL 5.9.4 is GPLv3-or-later. ZROtext is AGPL-3.0-only. GPLv3 §13 and
AGPLv3 §13 each grant explicit permission to combine the two into one work
confirmed by the FSF FAQ, so the combination is compliant with ZROtext
unchanged. Obligations recorded here per review condition 6:

- The vendored subset under `android/app/src/main/cpp/wolfssl/` keeps
  upstream's license notices unmodified (see its `LICENSING` and per-file
  headers); `PROVENANCE` pins the exact upstream tag, commit and per-file
  SHA-256 digests.
- Corresponding Source offers for the combined work must include this
  vendored wolfSSL source (it is in the same repository, so ordinary source
  distribution satisfies it).
- ZROtext's own `SPDX-License-Identifier: AGPL-3.0-only` headers are
  unchanged; a future non-GPL distribution of the combined app would require
  the separate wolfSSL commercial license and is out of scope.

## What remains open

The physical API 31+ key-lifecycle gate from #1003 (enrollment, existing-key
operation, hardware-backed claims, reboot, key loss/revocation, no accidental
regeneration on supported hardware) is untouched by this ADR and stays open.
Provider acceptance, virtual feasibility and physical security observations
remain distinct records.
