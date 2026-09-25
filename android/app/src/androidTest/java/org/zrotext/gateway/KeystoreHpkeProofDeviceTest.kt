// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
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
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECParameterSpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Test-only RFC 9180 composition. This is deliberately outside main source: it does not approve
 * a custom HPKE provider, the draft envelope, or production sealed mode. No key is exported from
 * AndroidKeyStore. The RFC test vector uses a separate public, deterministic software test key.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreHpkeProofDeviceTest {
    private val browserInteropAlias = "zrotext.m2.hpke.browser-interop-test"

    @Test fun keystoreDerConvertsToCanonicalRawSignature() {
        val alias = "zrotext.m2.sig-proof.${UUID.randomUUID()}"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        try {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            val pair = KeyPairGenerator.getInstance("EC", "AndroidKeyStore").run {
                initialize(spec); generateKeyPair()
            }
            assertNull(pair.private.encoded)
            val point = DevicePayloadKeyStore.encodePoint(pair.public as ECPublicKey)
            val envelope = ByteArray(557)
            byteArrayOf(0x5a, 0x54, 0x53, 0x45, 1, 1, 0, 0, 0, 157.toByte()).copyInto(envelope)
            MessageDigest.getInstance("SHA-256").digest(
                "ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point
            ).copyInto(envelope, 114)
            val unsigned = envelope.copyOfRange(0, envelope.size - 64)
            val transcript = "ZTSE/sign/v1\u0000".toByteArray(Charsets.US_ASCII) +
                byteArrayOf(0, 0, (unsigned.size ushr 8).toByte(), unsigned.size.toByte()) + unsigned
            val der = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private); update(transcript); sign()
            }
            val raw = Draft01SignaturePrimitive.canonicalRawFromDer(der)
            assertEquals(64, raw.size)
            raw.copyInto(envelope, unsigned.size)
            assertTrue(Draft01SignaturePrimitive.verifyOutboundParsed(
                envelope, point, Draft01SignaturePrimitive.LowSPolicy.REQUIRE_LOW_S))
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("m2_keystore_der_low_s", "PASSED")
            })
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            assertFalse(store.containsAlias(alias))
        }
    }

    // These three methods are called in order by the emulator-only Node harness. Ordinary
    // connectedAndroidTest runs skip them and cannot leave a persistent test alias behind.
    @Test fun prepareBrowserInteropRecipient() {
        assumeBrowserInteropHarness()
        HpkeOneShot.requireSupportedApi(Build.VERSION.SDK_INT)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        if (store.containsAlias(browserInteropAlias)) store.deleteEntry(browserInteropAlias)
        val recipient = DevicePayloadKeyStore(browserInteropAlias).getOrCreateForEnrollment()
        assertNull(store.getKey(browserInteropAlias, null)?.encoded)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("m2_browser_interop_recipient_point_hex", recipient.point.toHex())
        })
    }

    @Test fun openBrowserInteropWrap() {
        assumeBrowserInteropHarness()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        try {
            val args = InstrumentationRegistry.getArguments()
            val enc = hexBytes(requireNotNull(args.getString("m2_enc_hex")))
            val ct = hexBytes(requireNotNull(args.getString("m2_ct_hex")))
            val expectedCek = hexBytes(requireNotNull(args.getString("m2_cek_hex")))
            val keyStore = DevicePayloadKeyStore(browserInteropAlias)
            val recipient = keyStore.existingPublic()
            val protected = ByteArray(157) { it.toByte() }
            val role = byteArrayOf(1)
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val keyId = digest.digest("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) +
                byteArrayOf(0, 16) + recipient.point)
            assertArrayEquals(keyId, recipient.keyId)
            val info = "ZTSE/wrap/v1\u0000".toByteArray(Charsets.US_ASCII) + digest.digest(protected) + role + keyId
            val aad = "ZTSE/wrap-aad/v1\u0000".toByteArray(Charsets.US_ASCII) + protected + role + keyId
            assertArrayEquals(expectedCek, openBrowserWrap(keyStore, recipient, enc, ct, info, aad))
            rejects { openBrowserWrap(keyStore, recipient, enc, ct, info + 1, aad) }
            rejects { openBrowserWrap(keyStore, recipient, enc, ct, info, aad + 1) }
            rejects { keyStore.agreeExisting(enc, ByteArray(32)) }
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("m2_browser_to_keystore_open", "PASSED")
            })
            expectedCek.fill(0)
        } finally {
            if (store.containsAlias(browserInteropAlias)) store.deleteEntry(browserInteropAlias)
            assertFalse(store.containsAlias(browserInteropAlias))
        }
    }

    @Test fun openBrowserInteropEnvelope() {
        assumeBrowserInteropHarness()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        val keyStore = DevicePayloadKeyStore(browserInteropAlias)
        try {
            val envelope = hexBytes(requireNotNull(InstrumentationRegistry.getArguments().getString("m2_envelope_hex")))
            val keyId = keyStore.existingPublic().keyId
            val expected = Draft01KeystoreReceiver.Expected(
                ByteArray(16) { 0xa1.toByte() }, ByteArray(16) { 0xd1.toByte() },
                ByteArray(16) { 0xb1.toByte() }, "+12", ByteArray(32) { 0x4d.toByte() }, keyId,
                hexBytes("0451590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed" +
                    "e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4"))
            assertEquals("Draft outbound ✉", Draft01KeystoreReceiver.openOutbound(envelope, expected, keyStore))
            rejects { Draft01KeystoreReceiver.openOutbound(envelope.copyOf().also {
                it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
            }, expected, keyStore) }
            rejects { Draft01KeystoreReceiver.openOutbound(envelope.copyOf().also {
                it[10 + 157 + 16] = (it[10 + 157 + 16].toInt() xor 1).toByte()
            }, expected, keyStore) }
            val parsed = Draft01KeystoreReceiver.parseOutbound(envelope)
            val info = Draft01KeystoreReceiver.wrapInfo(parsed)
            val aad = Draft01KeystoreReceiver.wrapAad(parsed)
            rejects { Draft01KeystoreReceiver.openDeviceWrap(parsed, keyStore, info + 1, aad) }
            rejects { Draft01KeystoreReceiver.openDeviceWrap(parsed, keyStore, info, aad + 1) }
            rejects { Draft01KeystoreReceiver.openDeviceWrap(parsed.copy(deviceWrap =
                parsed.deviceWrap.copy(enc = ByteArray(65))), keyStore) }
            rejects { Draft01KeystoreReceiver.openDeviceWrap(parsed.copy(deviceWrap =
                parsed.deviceWrap.copy(keyId = ByteArray(32))), keyStore) }
            rejects { Draft01KeystoreReceiver.parseOutbound(envelope.copyOf(envelope.size - 1)) }
            rejects { Draft01KeystoreReceiver.parseOutbound(envelope + 0.toByte()) }
            store.deleteEntry(browserInteropAlias)
            assertThrows(IllegalStateException::class.java) {
                Draft01KeystoreReceiver.openOutbound(envelope, expected, keyStore)
            }
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("m2_browser_envelope_open", "PASSED")
                putString("m2_browser_envelope_lost_key_denied", "PASSED")
            })
        } finally {
            if (store.containsAlias(browserInteropAlias)) store.deleteEntry(browserInteropAlias)
            assertFalse(store.containsAlias(browserInteropAlias))
        }
    }

    @Test fun cleanupBrowserInteropRecipient() {
        assumeBrowserInteropHarness()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        if (store.containsAlias(browserInteropAlias)) store.deleteEntry(browserInteropAlias)
        assertFalse(store.containsAlias(browserInteropAlias))
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("m2_browser_interop_alias_removed", "PASSED")
        })
    }

    private fun assumeBrowserInteropHarness() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("m2_host_driver") == "1")
    }

    private fun openBrowserWrap(keyStore: DevicePayloadKeyStore, recipient: DevicePayloadPublic,
                                enc: ByteArray, ct: ByteArray, info: ByteArray, aad: ByteArray): ByteArray {
        val dh = keyStore.agreeExisting(enc, recipient.keyId)
        try {
            val shared = HpkeOneShot.kemSecret(dh, enc, recipient.point)
            return try { HpkeOneShot.open(shared, ct, info, aad) }
            finally { shared.fill(0) }
        } finally { dh.fill(0) }
    }

    @Test fun proofFloorRejectsApisBelow31() {
        for (api in 28..30) rejects { HpkeOneShot.requireSupportedApi(api) }
        HpkeOneShot.requireSupportedApi(31)
    }

    @Test fun rfc9180P256BaseVectorWithNonemptyInfoAndAad() {
        // RFC 9180 Appendix A.3.1, first encryption. Public test values, not app key material.
        val recipient = KeyFactory.getInstance("EC").generatePrivate(
            ECPrivateKeySpec(hex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"), P256.params)
        )
        val recipientPoint = P256.decode(hexBytes("04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"))
        val enc = hexBytes("04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4")
        val ct = hexBytes("5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434")
        val info = hexBytes("4f6465206f6e2061204772656369616e2055726e")
        val aad = hexBytes("436f756e742d30")
        val dh = P256.dh(recipient, P256.decode(enc), keystore = false)
        val shared = HpkeOneShot.kemSecret(dh, enc, P256.encode(recipientPoint))
        assertArrayEquals(hexBytes("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8"), shared)
        assertArrayEquals(hexBytes("4265617574792069732074727574682c20747275746820626561757479"), HpkeOneShot.open(shared, ct, info, aad))
        rejects { HpkeOneShot.open(shared, ct, info + 1, aad) }
        rejects { HpkeOneShot.open(shared, ct, info, aad + 1) }
        dh.fill(0)
        shared.fill(0)
    }

    @Test fun api31KeystoreRecipientOpensDraftWrapAndRejectsTampering() {
        assumeTrue(Build.VERSION.SDK_INT >= 31) // Actual Keystore operation is ineligible below API 31.
        val alias = "zrotext.m2.hpke.proof.${UUID.randomUUID()}"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        try {
            val pair = KeyPairGenerator.getInstance("EC", "AndroidKeyStore").run {
                initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).build())
                generateKeyPair()
            }
            val privateKey = store.getKey(alias, null) as PrivateKey
            val recipientPoint = pair.public as ECPublicKey
            val infoFromStore = KeyFactory.getInstance("EC", "AndroidKeyStore")
                .getKeySpec(privateKey, KeyInfo::class.java)
            assertNull(privateKey.encoded)
            assertEquals(KeyProperties.ORIGIN_GENERATED, infoFromStore.origin)
            assertTrue(infoFromStore.purposes and KeyProperties.PURPOSE_AGREE_KEY != 0)
            val securityLevel = when (infoFromStore.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TRUSTED_ENVIRONMENT"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "UNKNOWN_SECURE"
                else -> "UNKNOWN"
            }
            assertEquals(65, P256.encode(recipientPoint).size)

            val protected = ByteArray(157) { it.toByte() }
            val role = byteArrayOf(1)
            val keyId = ByteArray(32) { (it + 29).toByte() }
            val info = "ZTSE/wrap/v1\u0000".toByteArray(Charsets.US_ASCII) +
                java.security.MessageDigest.getInstance("SHA-256").digest(protected) + role + keyId
            val aad = "ZTSE/wrap-aad/v1\u0000".toByteArray(Charsets.US_ASCII) + protected + role + keyId
            val cek = ByteArray(32) { (it xor 0x5a).toByte() }
            val wrap = HpkeOneShot.seal(recipientPoint, cek, info, aad)
            assertEquals(65, wrap.first.size)
            assertEquals(48, wrap.second.size)
            assertArrayEquals(cek, HpkeOneShot.openKeystore(privateKey, recipientPoint, wrap.first, wrap.second, info, aad))
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("m2_keystore_security_level", securityLevel)
                putString("m2_keystore_key_origin", "GENERATED")
                putString("m2_keystore_ecdh_and_hpke_open", "PASSED")
            })
            rejects { HpkeOneShot.openKeystore(privateKey, recipientPoint, wrap.first, wrap.second, info + 1, aad) }
            rejects { HpkeOneShot.openKeystore(privateKey, recipientPoint, wrap.first, wrap.second, info, aad + 1) }
            rejects { HpkeOneShot.openKeystore(privateKey, recipientPoint, wrap.first, wrap.second, info, "ZTSE/wrap-aad/v1\u0000".toByteArray() + protected + byteArrayOf(2) + keyId) }
            rejects { HpkeOneShot.openKeystore(privateKey, recipientPoint, ByteArray(65), wrap.second, info, aad) }
            rejects { HpkeOneShot.openKeystore(privateKey, recipientPoint, byteArrayOf(4) + ByteArray(64), wrap.second, info, aad) }
            rejects { HpkeOneShot.openKeystore(privateKey, recipientPoint, wrap.first.copyOf(64), wrap.second, info, aad) }
            rejects { HpkeOneShot.openKeystore(privateKey, recipientPoint, wrap.first, wrap.second.copyOf(47), info, aad) }
            val other = KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair()
            }
            val wrongDh = P256.dh(other.private, P256.decode(wrap.first), false)
            val wrongShared = HpkeOneShot.kemSecret(wrongDh, wrap.first, P256.encode(other.public as ECPublicKey))
            try { rejects { HpkeOneShot.open(wrongShared, wrap.second, info, aad) } }
            finally { wrongDh.fill(0); wrongShared.fill(0) }
            cek.fill(0)
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            assertFalse(store.containsAlias(alias))
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("m2_keystore_temp_alias_removed", "PASSED")
            })
        }
    }

    private fun rejects(block: () -> Unit) {
        try {
            block()
            throw AssertionError("Malformed or mismatched HPKE input was accepted")
        } catch (expected: java.security.GeneralSecurityException) {
            // Fail closed; do not expose decrypted bytes.
        } catch (expected: IllegalArgumentException) {
            // Exact length and point validation also fail closed.
        }
    }

    private fun hex(value: String) = BigInteger(value, 16)
    private fun hexBytes(value: String): ByteArray {
        require(value.length % 2 == 0 && value.matches(Regex("[0-9a-f]*")))
        return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private object P256 {
        val params: ECParameterSpec = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }

        fun decode(raw: ByteArray): ECPublicKey {
            require(raw.size == 65 && raw[0] == 4.toByte()) { "Invalid P-256 point encoding" }
            val x = BigInteger(1, raw.copyOfRange(1, 33))
            val y = BigInteger(1, raw.copyOfRange(33, 65))
            val p = (params.curve.field as ECFieldFp).p
            require(x < p && y < p && y.modPow(BigInteger.TWO, p) ==
                x.modPow(BigInteger.valueOf(3), p).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)) {
                "Invalid P-256 point"
            }
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) as ECPublicKey
        }

        fun encode(key: ECPublicKey): ByteArray {
            require(key.params.curve == params.curve && key.params.generator == params.generator)
            fun coordinate(n: BigInteger): ByteArray = n.toByteArray().let { bytes ->
                val magnitude = if (bytes.size == 33 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, 33) else bytes
                require(n.signum() >= 0 && magnitude.size <= 32)
                ByteArray(32).also { out -> magnitude.copyInto(out, 32 - magnitude.size) }
            }
            return byteArrayOf(4) + coordinate(key.w.affineX) + coordinate(key.w.affineY)
        }

        fun dh(privateKey: PrivateKey, peer: ECPublicKey, keystore: Boolean): ByteArray =
            (if (keystore) KeyAgreement.getInstance("ECDH", "AndroidKeyStore") else KeyAgreement.getInstance("ECDH")).run {
                init(privateKey)
                doPhase(peer, true)
                generateSecret().also { require(it.size == 32) }
            }
    }

    internal object HpkeOneShot {
        private val kemSuite = "KEM".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 16)
        private val suite = "HPKE".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 16, 0, 1, 0, 1)
        private val prefix = "HPKE-v1".toByteArray(Charsets.US_ASCII)
        private val empty = byteArrayOf()

        fun requireSupportedApi(sdk: Int) {
            require(sdk >= 31) { "Sealed-mode proof requires Android API 31+" }
        }

        private fun extract(salt: ByteArray, ikm: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
            doFinal(ikm)
        }

        private fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
            require(length in 1..(255 * 32))
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            var previous = empty
            val out = ArrayList<Byte>()
            for (i in 1..((length + 31) / 32)) {
                previous = mac.doFinal(previous + info + i.toByte())
                out.addAll(previous.toList())
            }
            return out.take(length).toByteArray()
        }

        private fun labeledExtract(salt: ByteArray, suiteId: ByteArray, label: String, ikm: ByteArray) =
            extract(salt, prefix + suiteId + label.toByteArray(Charsets.US_ASCII) + ikm)

        private fun labeledExpand(prk: ByteArray, suiteId: ByteArray, label: String, info: ByteArray, length: Int) =
            expand(prk, byteArrayOf((length ushr 8).toByte(), length.toByte()) + prefix + suiteId +
                label.toByteArray(Charsets.US_ASCII) + info, length)

        fun kemSecret(dh: ByteArray, enc: ByteArray, recipientPoint: ByteArray): ByteArray {
            val eae = labeledExtract(empty, kemSuite, "eae_prk", dh)
            return labeledExpand(eae, kemSuite, "shared_secret", enc + recipientPoint, 32).also { eae.fill(0) }
        }

        private fun keyAndNonce(shared: ByteArray, info: ByteArray): Pair<ByteArray, ByteArray> {
            require(info.isNotEmpty())
            val context = byteArrayOf(0) + labeledExtract(empty, suite, "psk_id_hash", empty) +
                labeledExtract(empty, suite, "info_hash", info)
            val secret = labeledExtract(shared, suite, "secret", empty)
            return try {
                labeledExpand(secret, suite, "key", context, 16) to
                    labeledExpand(secret, suite, "base_nonce", context, 12)
            } finally { secret.fill(0) }
        }

        fun seal(recipient: ECPublicKey, cek: ByteArray, info: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
            require(cek.size == 32 && aad.isNotEmpty())
            val ephemeral = KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair()
            }
            val enc = P256.encode(ephemeral.public as ECPublicKey)
            val dh = P256.dh(ephemeral.private, recipient, keystore = false)
            val shared = kemSecret(dh, enc, P256.encode(recipient))
            dh.fill(0)
            try {
                val (key, nonce) = keyAndNonce(shared, info)
                return try {
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                    cipher.updateAAD(aad)
                    enc to cipher.doFinal(cek)
                } finally { key.fill(0); nonce.fill(0) }
            } finally { shared.fill(0) }
        }

        fun openKeystore(privateKey: PrivateKey, recipient: ECPublicKey, enc: ByteArray, ct: ByteArray,
                         info: ByteArray, aad: ByteArray): ByteArray {
            requireSupportedApi(Build.VERSION.SDK_INT)
            require(privateKey.encoded == null)
            require(ct.size == 48 && info.isNotEmpty() && aad.isNotEmpty())
            val dh = P256.dh(privateKey, P256.decode(enc), keystore = true)
            val shared = kemSecret(dh, enc, P256.encode(recipient))
            dh.fill(0)
            return try { open(shared, ct, info, aad) } finally { shared.fill(0) }
        }

        fun open(shared: ByteArray, ct: ByteArray, info: ByteArray, aad: ByteArray): ByteArray {
            require(ct.size >= 16 && info.isNotEmpty() && aad.isNotEmpty())
            val (key, nonce) = keyAndNonce(shared, info)
            return try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(ct)
            } finally { key.fill(0); nonce.fill(0) }
        }
    }
}
