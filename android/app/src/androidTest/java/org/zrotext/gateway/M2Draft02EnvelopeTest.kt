// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.GeneralSecurityException
import java.security.KeyStore

/** Browser-sent complete profile-02 envelope; all authority inputs here are public test fixtures. */
@RunWith(AndroidJUnit4::class)
class M2Draft02EnvelopeTest {
    private val alias = "zrotext.m2.draft02.envelope-test"

    @Test fun prepareRecipient() {
        requireHarness()
        DevicePayloadKeyStore.requireSupportedSdk(Build.VERSION.SDK_INT)
        val store = openStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
        val recipient = DevicePayloadKeyStore(alias).getOrCreateForEnrollment()
        assertEquals(65, recipient.point.size)
        assertNull(store.getKey(alias, null)?.encoded)
        InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
            putString("m2_draft02_envelope_recipient_point_hex", recipient.point.toHex())
            putString("m2_draft02_envelope_security_level", recipient.security.name)
        })
    }

    @Test fun openBrowserEnvelopeAndDenyMutations() {
        requireHarness()
        val store = openStore()
        val keyStore = DevicePayloadKeyStore(alias)
        try {
            val args = InstrumentationRegistry.getArguments()
            val envelope = decodeHex(requireNotNull(args.getString("m2_draft02_envelope_hex")))
            val nonceMutant = decodeHex(requireNotNull(args.getString("m2_draft02_nonce_mutant_hex")))
            val manifestMutant = decodeHex(requireNotNull(args.getString("m2_draft02_manifest_mutant_hex")))
            val bodyAadMutant = decodeHex(requireNotNull(args.getString("m2_draft02_body_aad_mutant_hex")))
            val recipient = keyStore.existingPublic()
            val trusted = Draft02TinkEnvelopeReceiver.TrustedView(
                ByteArray(16) { 0xa1.toByte() }, ByteArray(16) { 0xd1.toByte() },
                ByteArray(16) { 0xb1.toByte() }, "+12", ByteArray(32) { 0x4d.toByte() }, 3,
                decodeHex("0451590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed" +
                    "e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4"),
                recipient.keyId,
                decodeHex("077d873e1ff06750695653ea83dd16e2058de174a06092e6d23576946f578164")
            )
            val replay = Draft02TinkEnvelopeReceiver.ReplayJournal()
            assertEquals("Draft02 outbound ✓", Draft02TinkEnvelopeReceiver.openOutbound(
                envelope, trusted, keyStore, replay))
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted, keyStore, replay)
            }
            assertThrows(IllegalStateException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(nonceMutant, trusted, keyStore, replay)
            }

            val fresh = { Draft02TinkEnvelopeReceiver.ReplayJournal() }
            assertThrows(GeneralSecurityException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(nonceMutant, trusted, keyStore, fresh())
            }
            val bodyAadParsed = Draft02TinkEnvelopeReceiver.parseOutbound(bodyAadMutant)
            val rewrappedCek = Draft02TinkEnvelopeReceiver.openDeviceWrap(bodyAadParsed, keyStore)
            try { assertArrayEquals(ByteArray(32) { 0xc2.toByte() }, rewrappedCek) }
            finally { rewrappedCek.fill(0) }
            assertThrows(GeneralSecurityException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(bodyAadMutant, trusted, keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(manifestMutant, trusted, keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(ownerSignatureAccepted = false), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(signerAuthorizedForOutbound = false), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(deviceCurrentlyAuthorized = false), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(archiveKeyId = ByteArray(32)), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(keysetVersion = 4), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(peer = "+13"), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope.copyOf().also {
                    it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
                }, trusted, keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.parseOutbound(envelope.copyOf(envelope.size - 1))
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.parseOutbound(envelope + 0.toByte())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.parseOutbound(envelope.copyOf().also { it[4] = 1 })
            }
            assertThrows(IllegalArgumentException::class.java) {
                val badEnc = envelope.copyOf()
                val encAt = envelope.size - 64 - 2 * 146 + 33
                badEnc.fill(0, encAt, encAt + 65)
                Draft02TinkEnvelopeReceiver.parseOutbound(badEnc)
            }

            val parsed = Draft02TinkEnvelopeReceiver.parseOutbound(envelope)
            assertThrows(GeneralSecurityException::class.java) {
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed, keyStore,
                    Draft02TinkEnvelopeReceiver.wrapInfo(parsed).copyOf().also {
                        it[23] = (it[23].toInt() xor 1).toByte()
                    })
            }
            assertThrows(GeneralSecurityException::class.java) {
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed, keyStore,
                    Draft02TinkEnvelopeReceiver.wrapInfo(parsed).copyOf().also { it[180] = 2 })
            }
            assertThrows(GeneralSecurityException::class.java) {
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed, keyStore,
                    Draft02TinkEnvelopeReceiver.wrapInfo(parsed).copyOf().also {
                        it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
                    })
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed.copy(deviceWrap =
                    parsed.deviceWrap.copy(keyId = ByteArray(32))), keyStore)
            }
            store.deleteEntry(alias)
            assertThrows(IllegalStateException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted, keyStore, fresh())
            }
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("m2_draft02_full_envelope_open", "PASSED")
                putString("m2_draft02_signed_body_manifest_replay_denials", "PASSED")
                putString("m2_draft02_envelope_alias_removed", "PASSED")
            })
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
            putString("m2_draft02_envelope_alias_removed", "PASSED")
        })
    }

    private fun requireHarness() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("m2_draft02_envelope_host_driver") == "1")
    }
    private fun openStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null, null) }
    private fun decodeHex(text: String): ByteArray {
        require(text.length % 2 == 0 && text.matches(Regex("[0-9a-f]*")))
        return ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
