// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyStore
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class DeviceSigningKeyStoreTest {
    @Test fun keyRemainsInAndroidKeystoreAndSignsBothServerChallenges() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val alias = "zrotext.test.signing.${UUID.randomUUID()}"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        try {
            val signer = DeviceSigningKeyStore(context, alias)
            val first = signer.getOrCreate()
            val second = DeviceSigningKeyStore(context, alias).getOrCreate()
            assertArrayEquals(first.spkiDer, second.spkiDer)
            assertArrayEquals(first.fingerprint, second.fingerprint)
            assertNull(second.strongBoxFallbackOnCreation)
            assertTrue(first.spkiDer.size in 80..160)
            assertTrue(first.fingerprintHex.matches(Regex("[0-9A-F]{64}")))
            assertNotNull(keyStore.getKey(alias, null))
            assertNull(keyStore.getKey(alias, null)?.encoded)

            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(first.spkiDer))
            val account = UUID.randomUUID()
            val pairing = UUID.randomUUID()
            val nonce = ByteArray(32) { it.toByte() }
            val enrollmentSignature = signer.signEnrollmentChallenge(account, pairing, nonce)
            val enrollmentBytes = EnrollmentProof.enrollmentBytes(account, pairing, first.fingerprint, nonce)
            assertTrue(verify(publicKey, enrollmentBytes, enrollmentSignature))
            assertFalse(verify(publicKey, enrollmentBytes + 0x01.toByte(), enrollmentSignature))

            val device = UUID.randomUUID()
            val challenge = UUID.randomUUID()
            val authSignature = signer.signDeviceChallenge(account, device, challenge, nonce)
            val authBytes = EnrollmentProof.deviceAuthBytes(account, device, challenge, nonce)
            assertTrue(verify(publicKey, authBytes, authSignature))
            assertFalse(verify(publicKey, authBytes + 0x01.toByte(), authSignature))
        } finally {
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
    }

    private fun verify(publicKey: java.security.PublicKey, bytes: ByteArray, signature: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(bytes)
            verify(signature)
        }
}
