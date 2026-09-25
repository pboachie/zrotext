// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.crypto.tink.hybrid.HpkeParameters
import com.google.crypto.tink.hybrid.HpkePublicKey
import com.google.crypto.tink.hybrid.internal.HpkeHelperForAndroidKeystore
import com.google.crypto.tink.util.Bytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.GeneralSecurityException
import java.security.KeyStore

/**
 * Emulator-only draft-02 provider probe. It uses Tink's published Keystore helper with RFC 9180
 * info and empty HPKE AAD. It does not parse a production envelope or enable sealed-mode routes.
 */
@RunWith(AndroidJUnit4::class)
class Draft02TinkKeystoreDeviceTest {
    private val alias = "zrotext.m2.draft02.tink-interop-test"

    @Test fun prepareRecipient() {
        requireHarness()
        DevicePayloadKeyStore.requireSupportedSdk(Build.VERSION.SDK_INT)
        val store = openStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
        val recipient = DevicePayloadKeyStore(alias).getOrCreateForEnrollment()
        assertEquals(65, recipient.point.size)
        assertNull(store.getKey(alias, null)?.encoded)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("m2_draft02_recipient_point_hex", recipient.point.toHex())
            putString("m2_draft02_security_level", recipient.security.name)
        })
    }

    @Test fun openBrowserWrapWithTinkHelper() {
        requireHarness()
        val store = openStore()
        try {
            val args = InstrumentationRegistry.getArguments()
            val enc = decodeHex(requireNotNull(args.getString("m2_draft02_enc_hex")))
            val ct = decodeHex(requireNotNull(args.getString("m2_draft02_ct_hex")))
            val expectedCek = decodeHex(requireNotNull(args.getString("m2_draft02_cek_hex")))
            val keyStore = DevicePayloadKeyStore(alias)
            val recipient = keyStore.existingPublic()
            // Public draft-01 outbound Protected fixture, carried under a profile-02 header.
            val protected = decodeHex(
                "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a131313131313131313131313131313131" +
                    "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1" +
                    "00000000000000034d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d" +
                    "4d4d4d4d4d4d4d4d225778922ad1f5921f1561095dff1dd8f3d316dcb59736f4" +
                    "8631697880c723ae0000018bcfe568000000018bcfe6eea001032b3132"
            )
            val info = wrapInfo(protected, 1, recipient.keyId)

            assertTrue(info.isNotEmpty())
            assertEquals(65, enc.size)
            assertEquals(48, ct.size)
            assertArrayEquals(expectedCek, open(keyStore, recipient, enc, ct, info))
            assertThrows(GeneralSecurityException::class.java) {
                open(keyStore, recipient, enc, ct, info.copyOf().also { it[23] = (it[23].toInt() xor 1).toByte() })
            }
            assertThrows(GeneralSecurityException::class.java) {
                open(keyStore, recipient, enc, ct, wrapInfo(protected, 2, recipient.keyId))
            }
            assertThrows(GeneralSecurityException::class.java) {
                open(keyStore, recipient, enc, ct, wrapInfo(protected, 1,
                    recipient.keyId.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }))
            }
            assertThrows(GeneralSecurityException::class.java) {
                open(keyStore, recipient, enc, ct, info.copyOf().also { it[17] = 1 })
            }
            assertThrows(GeneralSecurityException::class.java) {
                open(keyStore, recipient, enc, ct.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }, info)
            }
            assertThrows(IllegalArgumentException::class.java) {
                open(keyStore, recipient, ByteArray(65), ct, info)
            }
            store.deleteEntry(alias)
            assertThrows(IllegalStateException::class.java) { keyStore.existingPublic() }
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("m2_draft02_tink_open", "PASSED")
                putString("m2_draft02_changed_info_denied", "PASSED")
                putString("m2_draft02_lost_key_denied", "PASSED")
            })
            expectedCek.fill(0)
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias)
            assertFalse(store.containsAlias(alias))
        }
    }

    @Test fun cleanupRecipient() {
        requireHarness()
        val store = openStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
        assertFalse(store.containsAlias(alias))
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("m2_draft02_alias_removed", "PASSED")
        })
    }

    @Test fun draft02FloorExcludesApi28To30() {
        for (sdk in 28..30) {
            assertThrows(IllegalArgumentException::class.java) {
                DevicePayloadKeyStore.requireSupportedSdk(sdk)
            }
        }
        DevicePayloadKeyStore.requireSupportedSdk(31)
    }

    private fun open(
        keyStore: DevicePayloadKeyStore, recipient: DevicePayloadPublic,
        enc: ByteArray, ct: ByteArray, info: ByteArray
    ): ByteArray {
        require(enc.size == 65 && ct.size == 48) { "Invalid draft-02 wrap length" }
        val dh = keyStore.agreeExisting(enc, recipient.keyId)
        try {
            val params = HpkeParameters.builder()
                .setKemId(HpkeParameters.KemId.DHKEM_P256_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_128_GCM)
                .setVariant(HpkeParameters.Variant.NO_PREFIX)
                .build()
            val publicKey = HpkePublicKey.create(params, Bytes.copyFrom(recipient.point), null)
            return HpkeHelperForAndroidKeystore.create(publicKey)
                .decryptUnauthenticatedWithEncapsulatedKeyAndP256SharedSecret(enc, dh, ct, 0, info)
        } finally {
            dh.fill(0)
        }
    }

    private fun wrapInfo(protected: ByteArray, role: Int, keyId: ByteArray): ByteArray {
        require(protected.size == 157 && role in 1..3 && keyId.size == 32)
        val header = byteArrayOf(0x5a, 0x54, 0x53, 0x45, 2, 1, 0, 0, 0, protected.size.toByte())
        return "ZTSE/wrap/v2\u0000".toByteArray(Charsets.US_ASCII) +
            header + protected + role.toByte() + keyId
    }

    private fun requireHarness() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("m2_draft02_host_driver") == "1")
    }

    private fun openStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }

    private fun decodeHex(text: String): ByteArray {
        require(text.length % 2 == 0 && text.matches(Regex("[0-9a-f]*")))
        return ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
