/* SPDX-License-Identifier: AGPL-3.0-only
 *
 * wolfCrypt build configuration for the ZROtext AndroidKeyStore HPKE bridge.
 *
 * This file realizes the maintainer-selected wolfSSL configuration from the
 * #1003 independent review (GO-WITH-CONDITIONS, condition 1):
 *
 *     --enable-hpke --enable-cryptocb=only,no-default-devid
 *
 * restricted to the single HPKE suite this bridge serves, RFC 9180 base mode
 * DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM. Upstream translates
 * `cryptocb=only` into "-DWOLF_CRYPTO_CB plus -DWOLF_CRYPTO_CB_ONLY_<ALG> for
 * every enabled algorithm" (configure.ac); for this build that is:
 *
 *   - WOLF_CRYPTO_CB_ONLY_ECC: the software ECC ECDH body is compiled out
 *     entirely (ecc.c falls through to `return NO_VALID_DEVID`). Any bridge
 *     gap therefore fails closed with NO_VALID_DEVID; there is no silent
 *     software fallback for the recipient ECDH. This is the binding condition.
 *   - WC_NO_DEFAULT_DEVID: the `,no-default-devid` half. Keys initialized
 *     without an explicit device id never reach a platform default callback.
 *
 * Deliberately NOT defined here, and why: WOLF_CRYPTO_CB_ONLY_SHA256 and
 * WOLF_CRYPTO_CB_ONLY_AES would strip the software SHA-256 and AES-GCM bodies
 * while this build registers an ECDH-only callback. The wolfSSL HPKE receiver
 * itself creates its AEAD object with INVALID_DEVID and runs the HKDF key
 * schedule in software (hpke.c: "the AES-GCM half intentionally stays
 * software"); stripping them would make every open fail with no fallback, not
 * a stronger bridge. Only the recipient ECDH crosses the Keystore boundary.
 *
 * Verified in CI by the host known-answer test, which additionally proves:
 *   - an ECDH on a key without a registered device fails with NO_VALID_DEVID
 *     (software ECDH is absent, not merely bypassed), and
 *   - a registered callback that reports a hard error propagates that error
 *     instead of falling through to software.
 */

#ifndef ZROTEXT_WOLFSSL_USER_SETTINGS_H
#define ZROTEXT_WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* The crypto-callback layer itself; the bridge registers exactly one device
 * whose callback answers WC_PK_TYPE_ECDH and hard-fails everything else. */
#define WOLF_CRYPTO_CB

/* cryptocb=only for ECC: compile the software ECDH/ECDSA bodies out. */
#define WOLF_CRYPTO_CB_ONLY_ECC

/* No platform default device id: only explicitly initialized keys reach the
 * registered callback; everything else fails closed with NO_VALID_DEVID. */
#define WC_NO_DEFAULT_DEVID

/* The one HPKE suite this bridge serves: P-256 ECDH key agreement, HKDF
 * over SHA-256, AES-128-GCM. HAVE_ECC_DHE exposes the ECDH crypto-callback
 * dispatch; HAVE_AESGCM keeps the software AEAD the HPKE receiver uses with
 * an INVALID_DEVID object (only the recipient ECDH crosses the bridge). */
#define HAVE_HPKE
#define HAVE_HKDF
#define HAVE_ECC
#define HAVE_ECC_DHE
#define HAVE_AESGCM
/* WOLFSSL_VALIDATE_ECC_IMPORT is deliberately NOT defined. With
 * cryptocb-only ECC, import-time point validation dispatches
 * WC_PK_TYPE_EC_CHECK_PUB_KEY to the key's device; the ephemeral key has no
 * device (import would fail NO_VALID_DEVID) and point validation is not the
 * ECDH bridge's contract. Curve membership is enforced where the bytes
 * enter: DevicePayloadKeyStore.decodePoint validates the peer point inside
 * the Keystore callback, the enrolled recipient point is validated at
 * enrollment, and any wrong point fails the AEAD authentication. */

/* Math: generic SP integer implementation (pure C, all four Android ABIs). */
#define WOLFSSL_SP_MATH_ALL

/* Match the upstream default-hardening build: constant-time ECC. */
#define ECC_TIMING_RESISTANT

/* Heap over stack for large temporaries; Android worker stacks are small. */
#define WOLFSSL_SMALL_STACK

/* Single-threaded library: the bridge serializes key operations per alias in
 * Kotlin (PayloadKeyLifecycle file lock + device monitor) and the crypto
 * callback registry is written once during JNI_OnLoad and never mutated. */
#define SINGLE_THREADED

/* The bridge is embed-only: no TLS, no sockets, no diagnostics text.
 * WOLFCRYPT_ONLY replaces the TLS-layer certificate authority lookups
 * (ssl.c) that the vendored ASN.1 object references with the in-library
 * dummy forms. The filesystem stays available: the hardened HPKE decap
 * constructs a transient RNG object (never drawn from on the device-key
 * path), which needs the entropy source. */
#define WOLFCRYPT_ONLY
#define NO_WRITEV
#define NO_ERROR_STRINGS
#define NO_MAIN_DRIVER
#define NO_OLD_TLS

/* Unused algorithm families: this build serves P-256 + SHA-256 + AES-128-GCM
 * only. Keys are never generated or exported as private material by wolfSSL;
 * the receiver imports a public point and serializes a public point. */
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_MD5
#define NO_SHA
#define NO_SHA512
#define NO_PSK
#define NO_WOLFSSL_DIR
/* Password-based encryption of encrypted key files: the vendored ASN.1
 * object references the PWDBASED helper, but the bridge never opens an
 * encrypted key file. */
#define NO_PWDBASED
/* The bridge never parses certificate times; ecc.c pulls the ASN.1 object
 * in, so keep its validity-date machinery stubbed. */
#define NO_ASN_TIME

#ifdef __cplusplus
}
#endif

#endif /* ZROTEXT_WOLFSSL_USER_SETTINGS_H */
