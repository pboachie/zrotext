// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Room
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.spec.SecretKeySpec

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [30])
class LineOptOutUploadTest {
    private val account = UUID.fromString("11111111-1111-4111-8111-111111111111")
    private val device = UUID.fromString("22222222-2222-4222-8222-222222222222")
    private val line = "33333333-3333-4333-8333-333333333333"
    private val eventId = "44444444-4444-4444-8444-444444444444"
    private val recipient = "+15551234567"
    private val dedupe = "a".repeat(64)
    private val senderToken = "b".repeat(64)

    private fun row() = LocalInboundWithdrawal(dedupe, senderToken,
        InboundClassification.OPT_OUT, 7, line, 7, 1700000000000L,
        eventId, 42, ByteArray(30), ByteArray(12))

    @Test fun exactTranscriptAndFrameContainOnlyLineBoundOptOutMetadata() {
        val bytes = LineOptOutUploadFrame.signedBytes(account, device, row(), recipient)
        assertEquals(126, bytes.size)
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }
        assertEquals("bd2e9c463936887cfa804c2a35ecf2be37004b9c6f2104f1f3e758a38fd5459a",
            digest)
        assertFalse(bytes.contentEquals(LineOptOutUploadFrame.signedBytes(account, device,
            row().copy(classification = InboundClassification.OPT_OUT_REVIEW), recipient)))
        assertFalse(bytes.contentEquals(LineOptOutUploadFrame.signedBytes(account, device,
            row().copy(bindingGeneration = 8), recipient)))
        assertFalse(bytes.contentEquals(LineOptOutUploadFrame.signedBytes(account, device,
            row(), "+15551234568")))
        assertThrows(IllegalArgumentException::class.java) {
            LineOptOutUploadFrame.signedBytes(account, device, row(), "15551234567")
        }

        val frame = LineOptOutUploadFrame.encode(9, row().copy(signatureDer = ByteArray(70)),
            recipient)
        val json = JSONObject(frame)
        assertEquals(setOf("v", "type", "connection_epoch", "event_id", "sequence",
            "line_id", "binding_generation", "action", "recipient_e164", "observed_at_ms",
            "signature_der"), json.keys().asSequence().toSet())
        assertEquals("line_opt_out", json.getString("type"))
        assertEquals(recipient, json.getString("recipient_e164"))
        assertFalse(frame.contains("body") || frame.contains("attempt_id") ||
            frame.contains("message_id") || frame.contains("ciphertext") ||
            frame.contains("senderToken"))
        val ack = JSONObject().put("v", 1).put("type", "line_opt_out_ack")
            .put("event_id", eventId).put("created", false)
        assertEquals(eventId, LineOptOutUploadFrame.ackEventId(ack))
        assertThrows(IllegalArgumentException::class.java) {
            LineOptOutUploadFrame.ackEventId(JSONObject(ack.toString())
                .put("suppression_cleared", true))
        }
        val missingCreated = JSONObject(ack.toString()).apply { remove("created") }
        assertThrows(IllegalArgumentException::class.java) {
            LineOptOutUploadFrame.ackEventId(missingCreated)
        }
    }

    @Test fun uploadGateRejectsMissingChangedOrAmbiguousLineAndOldEvidence() {
        val binding = LocalLineBinding(accountId = account.toString(),
            deviceId = device.toString(), lineId = line, generation = 7,
            subscriptionId = 7, installedAtMs = 1699999999000L, cardId = 42)
        val now = 1700000001000L
        assertTrue(LineOptOutUploadGate.allows(row(), binding, account, device, 7,
            listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), null, account, device, 7,
            listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), binding, account, device, 7,
            listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), binding, account, device, 8,
            listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row().copy(observedSubscriptionId = null),
            binding, account, device, 7, listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row().copy(bindingGeneration = 6),
            binding, account, device, 7, listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row().copy(encryptedSender = null),
            binding, account, device, 7, listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), binding.copy(accountId =
            "55555555-5555-4555-8555-555555555555"), account, device, 7,
            listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), binding.copy(installedAtMs = now),
            account, device, 7, listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), binding, account, device, 7,
            listOf(ActiveSimCard(7, 42)), now + 7L * 24 * 60 * 60 * 1000))
        assertFalse(LineOptOutUploadGate.allows(row(), binding, account, device, 7,
            listOf(ActiveSimCard(7, 43)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), binding.copy(cardId = null),
            account, device, 7, listOf(ActiveSimCard(7, 42)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), binding, account, device, 7,
            listOf(ActiveSimCard(7, -2)), now))
        assertFalse(LineOptOutUploadGate.allows(row(), binding, account, device, 7,
            null, now))
    }

    @Test fun senderRecoveryFailsClosedOnMissingCiphertextAndWrongToken() {
        val key = SecretKeySpec(ByteArray(32) { (it + 1).toByte() }, "AES")
        val sealed = InboundVault.sealSenderWithKey(key, recipient, dedupe)
        val stored = row().copy(encryptedSender = sealed.ciphertext,
            senderNonce = sealed.nonce)
        val opener = { value: InboundVault.Sealed, token: String ->
            InboundVault.openSenderWithKey(key, value, token)
        }
        assertEquals(recipient, LineOptOutSender.recover(stored, opener) {
            if (it == recipient) senderToken else "c".repeat(64)
        })
        assertNull(LineOptOutSender.recover(stored, opener) { "c".repeat(64) })
        assertNull(LineOptOutSender.recover(stored.copy(encryptedSender = null), opener) {
            senderToken
        })
        assertNull(LineOptOutSender.recover(stored.copy(senderNonce = ByteArray(12) { 1 }),
            opener) { senderToken })
        assertNull(LineOptOutSender.recover(stored, { _, _ ->
            throw IllegalStateException("keystore unavailable")
        }) { senderToken })
    }

    @Test fun earlierLocalOnlyWithdrawalsDoNotStarveLaterBoundStop() {
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        try {
            val dao = db.attempts()
            val first = "c".repeat(64)
            val unsealed = "d".repeat(64)
            val bound = "e".repeat(64)
            assertTrue(dao.recordLocalWithdrawal(first, senderToken,
                InboundClassification.OPT_OUT, null, emptyList(), 1000))
            assertTrue(dao.installVerifiedLineBinding(LocalLineBinding(accountId =
                account.toString(), deviceId = device.toString(), lineId = line,
                generation = 7, subscriptionId = 7, installedAtMs = 1500), listOf(7)))
            assertTrue(dao.recordLocalWithdrawal(unsealed, senderToken,
                InboundClassification.OPT_OUT_REVIEW, 7, listOf(7), 2000))
            val key = SecretKeySpec(ByteArray(32) { (it + 1).toByte() }, "AES")
            val sealed = InboundVault.sealSenderWithKey(key, recipient, bound)
            assertTrue(dao.recordLocalWithdrawal(bound, senderToken,
                InboundClassification.OPT_OUT, 7, listOf(7), 3000,
                sealed.ciphertext, sealed.nonce))
            assertNull(dao.localWithdrawal(first)?.lineId)
            assertNull(dao.localWithdrawal(unsealed)?.encryptedSender)
            assertEquals(3L, dao.nextLineOptOut(0)?.deviceSequence)
            assertEquals(dao.localWithdrawal(bound)?.eventId, dao.nextLineOptOut(0)?.eventId)
            assertTrue(dao.isRecipientSuppressed(senderToken))
            val eventId = checkNotNull(dao.localWithdrawal(bound)?.eventId)
            assertEquals(1, dao.signLineOptOut(eventId, line, 7, ByteArray(70)))
            assertEquals(1, dao.acknowledgeLineOptOut(eventId, 4000))
            assertNull(dao.nextLineOptOut(0))
            assertNull(dao.localWithdrawal(first)?.acknowledgedAtMs)
            assertNull(dao.localWithdrawal(unsealed)?.acknowledgedAtMs)
            assertTrue(dao.isRecipientSuppressed(senderToken))
        } finally { db.close() }
    }

    @Test fun signatureAndIdentitySurviveRestartAndExactReplayAckKeepsStop() {
        val context: Context = RuntimeEnvironment.getApplication()
        val name = "line-opt-out-replay.db"
        context.deleteDatabase(name)
        val key = SecretKeySpec(ByteArray(32) { (it + 1).toByte() }, "AES")
        val sealed = InboundVault.sealSenderWithKey(key, recipient, dedupe)
        val signer = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val first = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        val original: LocalInboundWithdrawal
        val signature: ByteArray
        try {
            val dao = first.attempts()
            assertTrue(dao.installVerifiedLineBinding(LocalLineBinding(accountId =
                account.toString(), deviceId = device.toString(), lineId = line,
                generation = 7, subscriptionId = 7, installedAtMs = 1000, cardId = 42),
                listOf(ActiveSimCard(7, 42))))
            assertTrue(dao.recordLocalWithdrawal(dedupe, senderToken,
                InboundClassification.OPT_OUT, 7, listOf(ActiveSimCard(7, 42)), 2000,
                sealed.ciphertext, sealed.nonce))
            original = dao.nextLineOptOut(0)!!
            val bytes = LineOptOutUploadFrame.signedBytes(account, device, original, recipient)
            signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(signer.private)
                update(bytes)
                sign()
            }
            assertEquals(1, dao.signLineOptOut(original.eventId!!, line, 7, signature))
            assertEquals(0, dao.signLineOptOut(original.eventId!!, line, 7, signature))
            assertTrue(dao.isRecipientSuppressed(senderToken))
        } finally { first.close() }
        val reopened = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        try {
            val dao = reopened.attempts()
            val pending = dao.nextLineOptOut(0)!!
            assertEquals(42, dao.currentLineBinding()?.cardId)
            assertTrue(LineOptOutUploadGate.allows(pending, dao.currentLineBinding(),
                account, device, 7, listOf(ActiveSimCard(7, 42)), 3000))
            assertFalse(LineOptOutUploadGate.allows(pending, dao.currentLineBinding(),
                account, device, 7, listOf(ActiveSimCard(7, 43)), 3000))
            assertEquals(original.eventId, pending.eventId)
            assertEquals(original.deviceSequence, pending.deviceSequence)
            assertEquals(original.receivedAtMs, pending.receivedAtMs)
            assertArrayEquals(signature, pending.signatureDer)
            assertEquals(recipient, InboundVault.openSenderWithKey(key,
                InboundVault.Sealed(pending.encryptedSender!!, pending.senderNonce!!), dedupe))
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(signer.public)
                update(LineOptOutUploadFrame.signedBytes(account, device, pending, recipient))
                assertTrue(verify(pending.signatureDer))
            }
            val firstFrame = LineOptOutUploadFrame.encode(1, pending, recipient)
            val replayFrame = LineOptOutUploadFrame.encode(2, pending, recipient)
            assertEquals(JSONObject(firstFrame).getString("signature_der"),
                JSONObject(replayFrame).getString("signature_der"))
            assertEquals(1, dao.acknowledgeLineOptOut(original.eventId!!, 3000))
            assertEquals(0, dao.acknowledgeLineOptOut(original.eventId!!, 3001))
            assertNull(dao.nextLineOptOut(0))
            assertNotNull(dao.lineOptOutByEventId(original.eventId!!))
            assertTrue(dao.isRecipientSuppressed(senderToken))
        } finally {
            reopened.close()
            context.deleteDatabase(name)
        }
    }
}
