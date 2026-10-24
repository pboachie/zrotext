// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

/** Public-recipient encryption through the same pinned wolfSSL RFC9180 implementation.
 * A fresh transient sender key is not an enrolled identity, recipient, consent or effect
 * capability. Its private object stays in JCA; neither scalar nor encoded key is read.
 * The maintained callback-only ECC build and existing hardware receiver stay unchanged. */
internal class WolfHpkePublicSender {
    private val admission = ThreadLocal<(() -> Unit)?>()
    /** Returns enc65 || ciphertext48 for exactly one CEK32. Owns/clears its CEK copy;
     * the caller must clear the original. No alternate provider or empty-AAD path exists. */
    fun seal(recipientPoint: ByteArray, cek: ByteArray, info: ByteArray, aad: ByteArray,
        current: () -> Unit): ByteArray {
        HpkeWrapFraming.requireApiFloor(Build.VERSION.SDK_INT)
        require(recipientPoint.size == 65 && cek.size == 32 && info.size in 1..1024 && aad.size in 1..1024)
        val point = recipientPoint.copyOf(); val key = cek.copyOf()
        val context = info.copyOf(); val associated = aad.copyOf()
        var ciphertext: ByteArray? = null
        try {
            require(key.size == 32 && context.size in 1..1024 && associated.size in 1..1024 &&
                !context.contentEquals(associated))
            DevicePayloadKeyStore.decodePoint(point)
            check(admission.get() == null)
            current()
            val ephemeral = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            }.generateKeyPair()
            try {
                current()
                val enc = DevicePayloadKeyStore.encodePoint(ephemeral.public as ECPublicKey)
                admission.set(current)
                try {
                    WolfHpkeOperationGate.operation(current) {
                        nativeSeal(ephemeral.private, enc, point, key, context, associated).also { ciphertext = it }
                    }
                    current()
                    check(checkNotNull(ciphertext).size == 48)
                    return enc + checkNotNull(ciphertext)
                } finally { admission.remove() }
            } finally {
                // Providers may retain internal copies; no private encoding is requested.
                runCatching { ephemeral.private.destroy() }
            }
        } finally { key.fill(0); ciphertext?.fill(0) }
    }
    private external fun nativeSeal(ephemeral: PrivateKey, enc: ByteArray, recipient: ByteArray,
        cek: ByteArray, info: ByteArray, aad: ByteArray): ByteArray

    /** The native callback uses only this operation's ephemeral JCA private object. */
    private fun agreeFromNative(privateKey: PrivateKey, peerPoint: ByteArray): ByteArray {
        checkNotNull(admission.get()).invoke()
        val peer = DevicePayloadKeyStore.decodePoint(peerPoint)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey); checkNotNull(admission.get()).invoke()
        agreement.doPhase(peer, true); checkNotNull(admission.get()).invoke()
        val secret = agreement.generateSecret()
        try {
            check(secret.size == 32); checkNotNull(admission.get()).invoke()
            return secret
        } catch (failure: Throwable) { secret.fill(0); throw failure }
    }
    override fun toString() = "WolfHpkePublicSender(transient-public-encryption-only)"
    companion object { init { System.loadLibrary("zrotext_hpke_keystore") } }
}
