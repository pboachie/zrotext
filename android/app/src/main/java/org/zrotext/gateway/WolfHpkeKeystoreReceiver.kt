// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import java.security.PrivateKey
import javax.crypto.KeyAgreement

/** The wire-framing rules of one sealed wrap, enforced before the native
 * bridge is ever reached (binding condition 3 of the #1003 provider
 * selection; the native wrapper re-checks them as defense in depth).
 * JVM-testable on its own: no Android or native dependency. */
internal object HpkeWrapFraming {
    /** Raw 65-byte uncompressed P-256 encapsulation (DHKEM_P256_ENC_LEN). */
    const val ENC_LEN = 65

    /** Ciphertext plus its 16-byte AEAD tag, minimum one plaintext byte. */
    const val MIN_CT_LEN = 17

    fun requireValid(enc: ByteArray, ct: ByteArray, info: ByteArray, aad: ByteArray) {
        require(enc.size == ENC_LEN) { "Invalid encapsulation length" }
        require(ct.size >= MIN_CT_LEN) { "Invalid ciphertext length" }
        require(info.isNotEmpty() && aad.isNotEmpty()) { "info and AAD must be nonempty" }
        require(!info.contentEquals(aad)) { "info and AAD must be distinct" }
    }

    /** Sealed eligibility floor: enrollment and opening require API 31+
     * Keystore `PURPOSE_AGREE_KEY`; API 28-30 is refused at runtime and
     * minSdk stays 28 (binding condition 4). */
    fun requireApiFloor(sdk: Int) {
        require(sdk >= 31) { "Sealed HPKE requires Android API 31+" }
    }
}

/**
 * The selected maintained HPKE receiver for the sealed profile (maintainer
 * decision on #1003, 2026-10-06): wolfSSL 5.9.4, pinned to v5.9.4-stable
 * (commit 3c5eead4), built for the NDK with crypto-callback-only ECC, opening
 * RFC 9180 base-mode DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
 * wraps where the recipient ECDH executes inside AndroidKeyStore as one
 * `KeyAgreement("ECDH")` on an API 31+ PURPOSE_AGREE_KEY alias.
 *
 * Binding conditions from the selection, as implemented:
 *  1. The wolfSSL subset ships with software ECDH compiled out
 *     (`-DWOLF_CRYPTO_CB_ONLY_ECC` in user_settings.h): any bridge gap fails
 *     closed with NO_VALID_DEVID and never falls back to software. The host
 *     known-answer test proves the unregistered-key failure in CI.
 *  2. The registered crypto callback answers every ECDH or returns a hard
 *     error; CRYPTOCB_UNAVAILABLE is never returned.
 *  3. [HpkeWrapFraming] enforces enc == 65 bytes, ciphertext (tag included)
 *     >= 17 bytes, and nonempty, distinct info/AAD; the native wrapper strips
 *     the 16-byte inline tag (ctSz = C - 16) and re-validates.
 *  4. API 28-30 is refused at runtime; minSdk stays 28.
 *
 * Dormant boundary: key creation stays enrollment-only through
 * [DevicePayloadKeyStore]; nothing in the gateway service, registration or
 * radio path calls this class, and sealed mode stays disabled. A lost or
 * revoked key is refused here, never regenerated. The DH shared secret is a
 * per-message transient: the native layer zeroes its copies, wolfSSL zeroes
 * the KEM copy, and the caller must zero the returned plaintext after use.
 */
class WolfHpkeKeystoreReceiver(private val keystore: DevicePayloadKeyStore) {

    companion object {
        init {
            System.loadLibrary("zrotext_hpke_keystore")
        }
    }

    /** Opens one sealed wrap against the enrolled recipient pinned by
     * [pinnedKeyId]. Returns exactly ct.size - 16 plaintext bytes; the caller
     * must zero them after use. Refuses a missing, revoked, changed or
     * non-exportable-incompatible key without replacing it. */
    fun open(
        pinnedKeyId: ByteArray,
        enc: ByteArray,
        ct: ByteArray,
        info: ByteArray,
        aad: ByteArray
    ): ByteArray {
        if (Build.VERSION.SDK_INT < 31) error("Sealed HPKE requires Android API 31+")
        HpkeWrapFraming.requireValid(enc, ct, info, aad)
        return keystore.withRecipientKey(pinnedKeyId) { privateKey, public ->
            nativeOpen(privateKey, public.point, enc, ct, info, aad)
        }
    }

    /** One native RFC 9180 open. The enrolled public point rides along so the
     * native KEM context binds the exact validated recipient identity.
     * Throws GeneralSecurityException on any failure; plaintext failures are
     * indistinguishable by design. */
    private external fun nativeOpen(
        privateKey: PrivateKey,
        recipientPoint: ByteArray,
        enc: ByteArray,
        ct: ByteArray,
        info: ByteArray,
        aad: ByteArray
    ): ByteArray

    /** Called back from native code for the single Keystore ECDH of one
     * open. The peer point arrives re-encoded by wolfSSL as 0x04 || X || Y;
     * the returned 32-byte X coordinate is a per-message transient that the
     * native layer zeroes after copying. */
    private fun agreeFromNative(privateKey: PrivateKey, peerPoint: ByteArray): ByteArray {
        require(peerPoint.size == HpkeWrapFraming.ENC_LEN && peerPoint[0] == 0x04.toByte()) {
            "Invalid peer point"
        }
        val secret = KeyAgreement.getInstance("ECDH").run {
            init(privateKey)
            doPhase(DevicePayloadKeyStore.decodePoint(peerPoint), true)
            generateSecret()
        }
        if (secret.size != 32) {
            secret.fill(0)
            error("Unexpected P-256 secret width")
        }
        return secret
    }
}
