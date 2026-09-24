// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.KeyAgreement

@RunWith(AndroidJUnit4::class)
class DevicePayloadKeyStoreDeviceTest {
    @Test fun nonExportableRecipientIsStableAndMissingKeyFailsClosed() {
        assumeTrue(Build.VERSION.SDK_INT >= 31)
        val alias = "zrotext.test.payload.${UUID.randomUUID()}"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
        try {
            val recipient = DevicePayloadKeyStore(alias)
            val first = recipient.getOrCreateForEnrollment()
            val second = DevicePayloadKeyStore(alias).getOrCreateForEnrollment()
            assertArrayEquals(first.point, second.point)
            assertArrayEquals(first.keyId, second.keyId)
            assertEquals(65, first.point.size)
            assertEquals(32, first.keyId.size)

            val privateKey = store.getKey(alias, null)
            assertNull(privateKey.encoded)
            val info = KeyFactory.getInstance("EC", "AndroidKeyStore")
                .getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
            assertEquals(KeyProperties.ORIGIN_GENERATED, info.origin)
            assertEquals(KeyProperties.PURPOSE_AGREE_KEY, info.purposes)
            assertEquals(256, info.keySize)

            val sender = KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair()
            }
            val enc = DevicePayloadKeyStore.encodePoint(sender.public as java.security.interfaces.ECPublicKey)
            val expected = KeyAgreement.getInstance("ECDH").run {
                init(sender.private)
                doPhase(DevicePayloadKeyStore.decodePoint(first.point), true)
                generateSecret()
            }
            val actual = recipient.agreeExisting(enc, first.keyId)
            assertArrayEquals(expected, actual)
            actual.fill(0)
            expected.fill(0)
            assertThrows(IllegalArgumentException::class.java) {
                recipient.agreeExisting(enc, ByteArray(32))
            }
            assertThrows(IllegalArgumentException::class.java) {
                recipient.agreeExisting(ByteArray(65), first.keyId)
            }

            store.deleteEntry(alias)
            assertFalse(store.containsAlias(alias))
            assertThrows(IllegalStateException::class.java) { recipient.agreeExisting(enc, first.keyId) }
            assertFalse(store.containsAlias(alias))
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
        }
    }
}
