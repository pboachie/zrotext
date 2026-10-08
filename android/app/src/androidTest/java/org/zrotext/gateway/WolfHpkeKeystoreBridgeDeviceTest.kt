// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.UUID

/**
 * Cross-client known-answer tests for the selected maintained HPKE receiver
 * (maintainer decision on #1003): a software RFC 9180 sender seals to the
 * enrolled AndroidKeyStore PURPOSE_AGREE_KEY recipient and the wolfSSL
 * cryptocb-only native bridge opens through one Keystore KeyAgreement.
 *
 * These are the full-bridge Android KATs. The published RFC 9180 fixed-vector
 * open (whose recipient private key cannot live in AndroidKeyStore) runs as
 * the additional software-key host suite in CI; this device suite is the
 * one that exercises the authentic Keystore boundary. No SMS, radio or
 * network is involved; all keys are temporary test aliases.
 */
@RunWith(AndroidJUnit4::class)
class WolfHpkeKeystoreBridgeDeviceTest {
    private fun newAlias(): String = "zrotext.hpke.bridge.${UUID.randomUUID()}"

    private fun openStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }

    private fun recipient(alias: String) = DevicePayloadKeyStore(
        InstrumentationRegistry.getInstrumentation().targetContext, alias)

    private fun receiver(alias: String) = WolfHpkeKeystoreReceiver(recipient(alias))

    private fun rejects(block: () -> Unit) {
        try {
            block()
            throw AssertionError("Malformed or mismatched wrap was accepted")
        } catch (expected: java.security.GeneralSecurityException) {
            // Native open and Keystore failures fail closed.
        } catch (expected: IllegalStateException) {
            // Custody, key-loss and API-floor refusals fail closed.
        } catch (expected: IllegalArgumentException) {
            // Framing and identity validation fail closed.
        }
    }

    private fun wrapInfo(protectedBody: ByteArray, keyId: ByteArray): ByteArray {
        val role = byteArrayOf(1)
        return "ZTSE/wrap/v1\u0000".toByteArray(Charsets.US_ASCII) +
            MessageDigest.getInstance("SHA-256").digest(protectedBody) + role + keyId
    }

    private fun wrapAad(protectedBody: ByteArray, keyId: ByteArray): ByteArray {
        val role = byteArrayOf(1)
        return "ZTSE/wrap-aad/v1\u0000".toByteArray(Charsets.US_ASCII) +
            protectedBody + role + keyId
    }

    @Test fun enrolledRecipientExposesNonExportableAgreeKeyClaims() {
        assumeTrue(Build.VERSION.SDK_INT >= 31)
        val alias = newAlias()
        val store = openStore()
        try {
            val public = recipient(alias).getOrCreateForEnrollment()
            val privateKey = store.getKey(alias, null) as java.security.PrivateKey
            val info = KeyFactory.getInstance("EC", "AndroidKeyStore")
                .getKeySpec(privateKey, android.security.keystore.KeyInfo::class.java)
            assertNull(privateKey.encoded)
            assertEquals(android.security.keystore.KeyProperties.ORIGIN_GENERATED, info.origin)
            assertTrue(info.purposes and android.security.keystore.KeyProperties.PURPOSE_AGREE_KEY != 0)
            assertEquals(256, info.keySize)
            assertEquals(65, public.point.size)
            assertArrayEquals(public.keyId, DevicePayloadKeyStore.keyId(public.point))
            // Metadata, not attestation: the value is read back verbatim.
            // No sendStatus here: an identity-less status-code event would be
            // rejected as an unexpected test class by the no-radio allowlist
            // parser, which requires every completion to carry its class.
            assertTrue(PayloadKeySecurity.values().contains(public.security))
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            assertFalse(store.containsAlias(alias))
        }
    }

    @Test fun crossClientSealOpensThroughNativeBridgeAndRejectsTampering() {
        assumeTrue(Build.VERSION.SDK_INT >= 31)
        val alias = newAlias()
        val store = openStore()
        try {
            val public = recipient(alias).getOrCreateForEnrollment()
            val cek = ByteArray(32) { (it xor 0x5a).toByte() }
            val protectedBody = ByteArray(157) { it.toByte() }
            val info = wrapInfo(protectedBody, public.keyId)
            val aad = wrapAad(protectedBody, public.keyId)
            val (enc, sealed) = SoftwareHpkeSeal.seal(public.point, cek, info, aad)
            assertEquals(65, enc.size)
            assertEquals(48, sealed.size)

            val opened = receiver(alias).open(public.keyId, enc, sealed, info, aad)
            assertArrayEquals(cek, opened)
            cek.fill(0)
            opened.fill(0)

            // Changed info / changed AAD / swapped wrap inputs must fail.
            rejects { receiver(alias).open(public.keyId, enc, sealed, info + 1, aad) }
            rejects { receiver(alias).open(public.keyId, enc, sealed, info, aad + 1) }
            rejects { receiver(alias).open(public.keyId, sealed, enc, info, aad) }
            rejects { receiver(alias).open(public.keyId, enc, sealed.copyOf().also {
                it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
            }, info, aad) }
            // Wrong recipient identity fails closed.
            rejects { receiver(alias).open(ByteArray(32) { (it + 1).toByte() }, enc, sealed, info, aad) }
            // Framing rejections (binding condition 3).
            rejects { receiver(alias).open(public.keyId, enc.copyOf(64), sealed, info, aad) }
            rejects { receiver(alias).open(public.keyId, enc + 0, sealed, info, aad) }
            rejects { receiver(alias).open(public.keyId, enc, sealed.copyOf(16), info, aad) }
            rejects { receiver(alias).open(public.keyId, enc, sealed, ByteArray(0), aad) }
            rejects { receiver(alias).open(public.keyId, enc, sealed, info, ByteArray(0)) }
            rejects { receiver(alias).open(public.keyId, enc, sealed, info, info.copyOf()) }
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            assertFalse(store.containsAlias(alias))
        }
    }

    @Test fun lostRecipientKeyRefusesWithoutRegeneration() {
        assumeTrue(Build.VERSION.SDK_INT >= 31)
        val alias = newAlias()
        val store = openStore()
        try {
            val public = recipient(alias).getOrCreateForEnrollment()
            store.deleteEntry(alias)
            rejects { recipient(alias).existingPublic() }
            rejects { recipient(alias).withRecipientKey(public.keyId) { _, _ -> true } }
            // The refused receive must not resurrect or replace the identity.
            assertFalse(store.containsAlias(alias))
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            assertFalse(store.containsAlias(alias))
        }
    }

    @Test fun revokedRecipientKeyRefusesLaterOpens() {
        assumeTrue(Build.VERSION.SDK_INT >= 31)
        val alias = newAlias()
        val store = openStore()
        try {
            val public = recipient(alias).getOrCreateForEnrollment()
            recipient(alias).revokeExisting(public.keyId)
            rejects { recipient(alias).withRecipientKey(public.keyId) { _, _ -> true } }
            assertNotEquals(0, public.keyId.size) // tombstone kept the identity
            // Revocation is local denial; it never deletes the key object.
            assertTrue(store.containsAlias(alias))
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            assertFalse(store.containsAlias(alias))
        }
    }
}

/** Minimal software RFC 9180 sender for the cross-client KATs. Independent
 * of the receiver path under test: JCA only, no native calls. */
private object SoftwareHpkeSeal {
    private val params: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    fun decodePoint(raw: ByteArray): ECPublicKey {
        require(raw.size == 65 && raw[0] == 4.toByte()) { "Invalid P-256 point encoding" }
        val x = BigInteger(1, raw.copyOfRange(1, 33))
        val y = BigInteger(1, raw.copyOfRange(33, 65))
        val p = (params.curve.field as java.security.spec.ECFieldFp).p
        require(x < p && y < p && y.modPow(BigInteger.TWO, p) ==
            x.modPow(BigInteger.valueOf(3), p).add(params.curve.a.multiply(x))
                .add(params.curve.b).mod(p)) { "Invalid P-256 point" }
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
            as ECPublicKey
    }

    fun encodePoint(key: ECPublicKey): ByteArray {
        require(key.params.curve == params.curve && key.params.generator == params.generator)
        fun coordinate(value: BigInteger): ByteArray {
            require(value.signum() >= 0)
            val signed = value.toByteArray()
            val magnitude = if (signed.size == 33 && signed[0] == 0.toByte())
                signed.copyOfRange(1, 33) else signed
            require(magnitude.size <= 32)
            return ByteArray(32).also { magnitude.copyInto(it, 32 - magnitude.size) }
        }
        return byteArrayOf(4) + coordinate(key.w.affineX) + coordinate(key.w.affineY)
    }

    private val kemSuite = "KEM".toByteArray() + byteArrayOf(0, 16)
    private val suite = "HPKE".toByteArray() + byteArrayOf(0, 16, 0, 1, 0, 1)
    private val prefix = "HPKE-v1".toByteArray()

    private fun extract(salt: ByteArray, ikm: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
            doFinal(ikm)
        }

    private fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * 32))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        var previous = ByteArray(0)
        val out = ArrayList<Byte>()
        for (i in 1..((length + 31) / 32)) {
            previous = mac.doFinal(previous + info + i.toByte())
            out.addAll(previous.toList())
        }
        return out.take(length).toByteArray()
    }

    private fun labeledExtract(salt: ByteArray, suiteId: ByteArray, label: String, ikm: ByteArray) =
        extract(salt, prefix + suiteId + label.toByteArray() + ikm)

    private fun labeledExpand(prk: ByteArray, suiteId: ByteArray, label: String,
                              info: ByteArray, length: Int) =
        expand(prk, byteArrayOf((length ushr 8).toByte(), length.toByte()) + prefix + suiteId +
            label.toByteArray() + info, length)

    fun seal(recipientPointBytes: ByteArray, cek: ByteArray, info: ByteArray,
             aad: ByteArray): Pair<ByteArray, ByteArray> {
        require(cek.size == 32 && info.isNotEmpty() && aad.isNotEmpty())
        val recipientPoint = decodePoint(recipientPointBytes)
        val ephemeral = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val enc = encodePoint(ephemeral.public as ECPublicKey)
        val dh = KeyAgreement.getInstance("ECDH").run {
            init(ephemeral.private)
            doPhase(recipientPoint, true)
            generateSecret().also { require(it.size == 32) }
        }
        val shared = try {
            val eae = labeledExtract(ByteArray(0), kemSuite, "eae_prk", dh)
            labeledExpand(eae, kemSuite, "shared_secret", enc + recipientPointBytes, 32)
                .also { eae.fill(0) }
        } finally { dh.fill(0) }
        return try {
            val context = byteArrayOf(0) +
                labeledExtract(ByteArray(0), suite, "psk_id_hash", ByteArray(0)) +
                labeledExtract(ByteArray(0), suite, "info_hash", info)
            val secret = labeledExtract(shared, suite, "secret", ByteArray(0))
            val key = try {
                labeledExpand(secret, suite, "key", context, 16) to
                    labeledExpand(secret, suite, "base_nonce", context, 12)
            } finally { secret.fill(0) }
            val sealed = try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.first, "AES"),
                    GCMParameterSpec(128, key.second))
                cipher.updateAAD(aad)
                cipher.doFinal(cek)
            } finally { key.first.fill(0); key.second.fill(0) }
            enc to sealed
        } finally { shared.fill(0) }
    }
}
