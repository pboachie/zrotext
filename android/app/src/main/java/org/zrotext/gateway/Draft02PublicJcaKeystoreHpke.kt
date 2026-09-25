// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Dormant, API 31+ RFC 9180 base-mode device recipient for proposed profile 02.
 *
 * This uses only Android Keystore ECDH and public JCA HmacSHA256/AES-GCM APIs. It owns
 * the HPKE composition itself. This is an unwrap primitive, not an envelope verifier:
 * the caller must authorize the exact signed envelope, manifest, route, grant and replay
 * state before using its CEK. No production receive route calls it.
 */
internal object Draft02PublicJcaKeystoreHpke {
    private val version = "HPKE-v1".toByteArray(Charsets.US_ASCII)
    private val kemSuite = "KEM".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 0x10)
    private val hpkeSuite = "HPKE".toByteArray(Charsets.US_ASCII) +
        byteArrayOf(0, 0x10, 0, 1, 0, 1)
    private val profileInfoLabel = "ZTSE/wrap/v2\u0000".toByteArray(Charsets.US_ASCII)
    private val zeroSalt = ByteArray(32)

    /** P2 components must be slices of the same bounded, received outbound envelope. */
    fun openDeviceCek(
        keyStore: DevicePayloadKeyStore,
        receivedHeader: ByteArray,
        receivedProtected: ByteArray,
        role: Int,
        pinnedKeyId: ByteArray,
        enc: ByteArray,
        ciphertext: ByteArray
    ): ByteArray {
        DevicePayloadKeyStore.requireSupportedSdk(android.os.Build.VERSION.SDK_INT)
        require(enc.size == 65 && ciphertext.size == 48) {
            "Invalid profile-02 HPKE wrap shape"
        }
        val info = buildDeviceInfo(receivedHeader, receivedProtected, role, pinnedKeyId)
        try {
            val recipient = keyStore.existingPublic()
            require(MessageDigest.isEqual(recipient.keyId, pinnedKeyId)) {
                "Payload recipient identity changed"
            }
            // agreeExisting validates the uncompressed on-curve point and uses the
            // non-exportable Keystore private key. Its ECDH result lives in app memory.
            val dh = keyStore.agreeExisting(enc, pinnedKeyId)
            try {
                val sharedSecret = deriveSharedSecret(dh, enc, recipient.point)
                try {
                    val material = deriveKeyMaterial(sharedSecret, info)
                    try {
                        // Single-shot profile: sequence number zero, so nonce is base_nonce.
                        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(material.key, "AES"),
                            GCMParameterSpec(128, material.nonce))
                        // Draft 02 binds P2 and role in Setup info. Its HPKE AAD is empty.
                        cipher.updateAAD(byteArrayOf())
                        return cipher.doFinal(ciphertext).also { cek ->
                            if (cek.size != 32) {
                                cek.fill(0)
                                error("Invalid profile-02 CEK width")
                            }
                        }
                    } finally { material.clear() }
                } finally { sharedSecret.fill(0) }
            } finally { dh.fill(0) }
        } finally { info.fill(0) }
    }

    internal fun buildDeviceInfo(header: ByteArray, protected: ByteArray,
                                 role: Int, keyId: ByteArray): ByteArray {
        require(header.size == 10 && header.copyOfRange(0, 8).contentEquals(
            byteArrayOf(0x5a, 0x54, 0x53, 0x45, 2, 1, 0, 0)) &&
            protected.size in 157..170 &&
            (((header[8].toInt() and 0xff) shl 8) or (header[9].toInt() and 0xff)) == protected.size &&
            role == 1 && keyId.size == 32) { "Invalid profile-02 device transcript" }
        return profileInfoLabel + header + protected + role.toByte() + keyId
    }

    internal fun deriveSharedSecret(dh: ByteArray, enc: ByteArray,
                                    recipientPoint: ByteArray): ByteArray {
        require(dh.size == 32 && enc.size == 65 && recipientPoint.size == 65)
        val eaePrk = labeledExtract(zeroSalt, kemSuite, "eae_prk", dh)
        return try {
            labeledExpand(eaePrk, kemSuite, "shared_secret", enc + recipientPoint, 32)
        } finally { eaePrk.fill(0) }
    }

    internal class KeyMaterial(val key: ByteArray, val nonce: ByteArray) {
        fun clear() { key.fill(0); nonce.fill(0) }
    }

    internal fun deriveKeyMaterial(sharedSecret: ByteArray, info: ByteArray): KeyMaterial {
        require(sharedSecret.size == 32)
        val pskIdHash = labeledExtract(zeroSalt, hpkeSuite, "psk_id_hash", byteArrayOf())
        val infoHash = labeledExtract(zeroSalt, hpkeSuite, "info_hash", info)
        val context = byteArrayOf(0) + pskIdHash + infoHash // mode_base, no PSK
        pskIdHash.fill(0)
        infoHash.fill(0)
        try {
            val secret = labeledExtract(sharedSecret, hpkeSuite, "secret", byteArrayOf())
            try {
                val key = labeledExpand(secret, hpkeSuite, "key", context, 16)
                try {
                    return KeyMaterial(key, labeledExpand(secret, hpkeSuite, "base_nonce", context, 12))
                } catch (failure: Exception) {
                    key.fill(0)
                    throw failure
                }
            } finally { secret.fill(0) }
        } finally { context.fill(0) }
    }

    private fun labeledExtract(salt: ByteArray, suite: ByteArray, label: String,
                               input: ByteArray): ByteArray {
        val labeledInput = version + suite + label.toByteArray(Charsets.US_ASCII) + input
        return try { hmac(salt, labeledInput) } finally { labeledInput.fill(0) }
    }

    private fun labeledExpand(prk: ByteArray, suite: ByteArray, label: String,
                              context: ByteArray, length: Int): ByteArray {
        require(length in 1..32) { "Only one HKDF-SHA256 block is supported" }
        val labeledInfo = byteArrayOf(0, length.toByte()) + version + suite +
            label.toByteArray(Charsets.US_ASCII) + context + byteArrayOf(1)
        return try {
            val block = hmac(prk, labeledInfo)
            try { block.copyOfRange(0, length) } finally { block.fill(0) }
        } finally { labeledInfo.fill(0) }
    }

    private fun hmac(key: ByteArray, input: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(input)
        }
}
