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
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.GeneralSecurityException
import java.security.KeyStore

/** Browser-sent complete profile-02 envelope; all authority inputs here are public test fixtures. */
@RunWith(AndroidJUnit4::class)
class Draft02EnvelopeDeviceTest {
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
            val rootPin = decodeHex(requireNotNull(args.getString("m2_draft02_root_pin_hex")))
            val rootFingerprint = decodeHex(requireNotNull(args.getString("m2_draft02_root_fingerprint_hex")))
            val manifestBytes = decodeHex(requireNotNull(args.getString("m2_draft02_manifest_hex")))
            val staleManifest = decodeHex(requireNotNull(args.getString("m2_draft02_stale_manifest_hex")))
            val forgedManifest = decodeHex(requireNotNull(args.getString("m2_draft02_forged_manifest_hex")))
            val forkManifest = decodeHex(requireNotNull(args.getString("m2_draft02_fork_manifest_hex")))
            val revokedManifest = decodeHex(requireNotNull(args.getString("m2_draft02_revoked_manifest_hex")))
            val wrongScopeManifest = decodeHex(requireNotNull(args.getString("m2_draft02_wrong_scope_manifest_hex")))
            val wrongLineManifest = decodeHex(requireNotNull(args.getString("m2_draft02_wrong_line_manifest_hex")))
            val zeroLineManifest = decodeHex(requireNotNull(args.getString("m2_draft02_zero_line_manifest_hex")))
            val transition = decodeHex(requireNotNull(args.getString("m2_draft02_transition_hex")))
            val forgedTransition = decodeHex(requireNotNull(args.getString("m2_draft02_forged_transition_hex")))
            val rotatedRoot = decodeHex(requireNotNull(args.getString("m2_draft02_rotated_root_hex")))
            val rotatedManifest = decodeHex(requireNotNull(args.getString("m2_draft02_rotated_manifest_hex")))
            val revokedEnvelope = decodeHex(requireNotNull(args.getString("m2_draft02_revoked_envelope_hex")))
            val wrongLineEnvelope = decodeHex(requireNotNull(args.getString("m2_draft02_wrong_line_envelope_hex")))
            val highSEnvelope = decodeHex(requireNotNull(args.getString("m2_draft02_high_s_envelope_hex")))
            val now = System.currentTimeMillis()
            val trusted = Draft02TinkEnvelopeReceiver.TrustedView(
                rootPin, rootFingerprint, manifestBytes,
                ByteArray(16) { 0xd1.toByte() }, ByteArray(16) { 0xb1.toByte() }, "+12"
            )
            val pin = Draft02ManifestVerifier.enroll(rootPin, rootFingerprint)
            val verifiedManifest = Draft02ManifestVerifier.verify(manifestBytes, pin, now)
            val rotatedTrust = Draft02ManifestVerifier.verifyTransition(
                transition, verifiedManifest.nextTrust, rotatedRoot, now)
            assertEquals(2L, Draft02ManifestVerifier.verify(rotatedManifest, rotatedTrust, now).generation)
            assertThrows(IllegalArgumentException::class.java) {
                Draft02ManifestVerifier.verifyTransition(
                    forgedTransition, verifiedManifest.nextTrust, rotatedRoot, now)
            }
            val replay = Draft02TinkEnvelopeReceiver.ReplayJournal()
            val parsedNormal = Draft02TinkEnvelopeReceiver.parseOutbound(envelope)
            val jcaCek = Draft02TinkEnvelopeReceiver.openDeviceWrap(parsedNormal, keyStore)
            val tinkCek = Draft02TinkEnvelopeReceiver.openDeviceWrapTink(parsedNormal, keyStore)
            try {
                assertArrayEquals(ByteArray(32) { 0xc2.toByte() }, jcaCek)
                assertArrayEquals(tinkCek, jcaCek)
            } finally {
                jcaCek.fill(0)
                tinkCek.fill(0)
            }
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
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(manifest = staleManifest), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(manifest = forgedManifest), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(manifest = wrongScopeManifest), keyStore, fresh())
            }
            assertEquals(1L, Draft02ManifestVerifier.verify(wrongLineManifest, pin, now).version)
            val wrongLineDenial = assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(wrongLineEnvelope,
                    trusted.copy(manifest = wrongLineManifest), keyStore, fresh())
            }
            assertTrue(wrongLineDenial.message.orEmpty().contains("Manifest signer authority"))
            assertThrows(IllegalArgumentException::class.java) {
                Draft02ManifestVerifier.verify(zeroLineManifest, pin, now)
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(revokedEnvelope,
                    trusted.copy(manifest = revokedManifest), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02ManifestVerifier.verify(forkManifest, verifiedManifest.nextTrust, now)
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(peer = "+13"), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(deviceId = ByteArray(16)), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted.copy(rootFingerprint = ByteArray(32)), keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope.copyOf().also {
                    it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
                }, trusted, keyStore, fresh())
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(highSEnvelope, trusted, keyStore, fresh())
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
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed.copy(protected =
                    parsed.protected.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }), keyStore)
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed.copy(deviceWrap =
                    parsed.deviceWrap.copy(role = 2)), keyStore)
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed.copy(header =
                    parsed.header.copyOf().also { it[4] = 1 }), keyStore)
            }
            assertThrows(IllegalArgumentException::class.java) {
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed.copy(deviceWrap =
                    parsed.deviceWrap.copy(keyId = ByteArray(32))), keyStore)
            }
            assertThrows(GeneralSecurityException::class.java) {
                Draft02TinkEnvelopeReceiver.openDeviceWrap(parsed.copy(deviceWrap =
                    parsed.deviceWrap.copy(ct = parsed.deviceWrap.ct.copyOf().also {
                        it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
                    })), keyStore)
            }
            store.deleteEntry(alias)
            assertThrows(IllegalStateException::class.java) {
                Draft02TinkEnvelopeReceiver.openOutbound(envelope, trusted, keyStore, fresh())
            }
            InstrumentationRegistry.getInstrumentation().sendStatus(0, Bundle().apply {
                putString("m2_draft02_full_envelope_open", "PASSED")
                putString("m2_draft02_public_jca_tink_equivalence", "PASSED")
                putString("m2_draft02_signed_manifest_denials", "PASSED")
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
