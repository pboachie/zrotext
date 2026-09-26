// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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
import java.util.Base64
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [30])
class SmsLineActivationFramesTest {
    private val account = UUID.fromString("00000000-0000-4000-8000-000000000001")
    private val line = UUID.fromString("00000000-0000-4000-8000-000000000002")
    private val device = UUID.fromString("00000000-0000-4000-8000-000000000003")
    private val challengeId = UUID.fromString("00000000-0000-4000-8000-000000000004")
    private val nonce = ByteArray(32) { it.toByte() }
    private val b64 = Base64.getUrlEncoder().withoutPadding()

    private val signingKey = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private fun signer(challenge: SmsLineChallenge, api: Int, selected: Int): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(signingKey.private)
            update(SmsLineActivationTranscript.deviceStatement(challenge, api, selected))
            sign()
        }

    private fun challengeFrame(): JSONObject = JSONObject().put("v", 1)
        .put("type", "sms_line_challenge").put("challenge_id", challengeId.toString())
        .put("account_id", account.toString()).put("line_id", line.toString())
        .put("device_id", device.toString()).put("generation", 1)
        .put("nonce", b64.encodeToString(nonce)).put("expires_at_ms", 300_000L)

    private fun rejects(block: () -> Unit): Boolean = runCatching(block).isFailure

    @Test fun challengeFrameIsParsedExactlyAndRejectsAnyDeviation() {
        val parsed = SmsLineActivationFrames.challenge(challengeFrame())
        assertEquals(challengeId, parsed.challengeId)
        assertEquals(line, parsed.lineId)
        assertEquals(1L, parsed.generation)
        assertEquals(300_000L, parsed.expiresAtMs)
        assertArrayEquals(nonce, parsed.nonce)

        assertTrue(rejects { SmsLineActivationFrames.challenge(challengeFrame().put("body", "x")) })
        assertTrue(rejects {
            SmsLineActivationFrames.challenge(challengeFrame().apply { remove("line_id") })
        })
        assertTrue(rejects { SmsLineActivationFrames.challenge(challengeFrame().put("v", 2)) })
        assertTrue(rejects {
            SmsLineActivationFrames.challenge(challengeFrame().put("type", "challenge"))
        })
        assertTrue(rejects {
            SmsLineActivationFrames.challenge(challengeFrame().put("line_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"))
        })
        assertTrue(rejects {
            SmsLineActivationFrames.challenge(challengeFrame().put("line_id", UUID(0, 0).toString()))
        })
        assertTrue(rejects {
            SmsLineActivationFrames.challenge(challengeFrame().put("nonce", b64.encodeToString(ByteArray(31))))
        })
        assertTrue(rejects {
            SmsLineActivationFrames.challenge(challengeFrame().put("nonce",
                Base64.getUrlEncoder().encodeToString(nonce)))
        })
        assertTrue(rejects { SmsLineActivationFrames.challenge(challengeFrame().put("generation", 0)) })
        assertTrue(rejects { SmsLineActivationFrames.challenge(challengeFrame().put("generation", "1")) })
        assertTrue(rejects { SmsLineActivationFrames.challenge(challengeFrame().put("generation", 1.5)) })
    }

    @Test fun proofFrameCarriesOnlyTheSignedDeclaration() {
        val producer = SmsLineActivationDevice({ 30 }, { 7 },
            { listOf(ActiveSimCard(7, 42)) }, ::signer, { 1_000L })
        val proof = producer.prepare(SmsLineActivationFrames.challenge(challengeFrame()),
            account, device)!!
        val frame = JSONObject(SmsLineActivationFrames.proof(9, proof))
        assertEquals(setOf("v", "type", "connection_epoch", "challenge_id", "android_api_level",
            "active_subscription_count", "selected_subscription_id", "signature_der"),
            frame.keys().asSequence().toSet())
        assertEquals("sms_line_proof", frame.getString("type"))
        assertEquals(9L, frame.getLong("connection_epoch"))
        assertEquals(challengeId.toString(), frame.getString("challenge_id"))
        assertEquals(30, frame.getInt("android_api_level"))
        assertEquals(1, frame.getInt("active_subscription_count"))
        assertEquals(7, frame.getInt("selected_subscription_id"))
        assertArrayEquals(proof.deviceSignatureDer(),
            Base64.getUrlDecoder().decode(frame.getString("signature_der")))
        assertTrue(rejects { SmsLineActivationFrames.proof(0, proof) })
    }

    @Test fun proofAckRequiresExactBooleanFields() {
        val ack = JSONObject().put("v", 1).put("type", "sms_line_proof_ack")
            .put("challenge_id", challengeId.toString()).put("accepted", false)
        assertEquals(SmsLineActivationFrames.ProofAck(challengeId, false),
            SmsLineActivationFrames.proofAck(ack))
        assertTrue(rejects { SmsLineActivationFrames.proofAck(JSONObject(ack.toString()).put("accepted", "true")) })
        assertTrue(rejects { SmsLineActivationFrames.proofAck(JSONObject(ack.toString()).put("extra", 1)) })
    }

    @Test fun activatedFrameInstallsOnlyTheExactProofThisPhoneSent() {
        var now = 1_000L
        val active = listOf(ActiveSimCard(7, 42))
        val producer = SmsLineActivationDevice({ 30 }, { 7 }, { active }, ::signer, { now })
        val proof = producer.prepare(SmsLineActivationFrames.challenge(challengeFrame()),
            account, device)!!
        fun activated(signatureDigest: ByteArray = sha256(proof.deviceSignatureDer()),
                      generation: Long = 1): JSONObject = JSONObject().put("v", 1)
            .put("type", "sms_line_activated").put("challenge_id", challengeId.toString())
            .put("account_id", account.toString()).put("line_id", line.toString())
            .put("device_id", device.toString()).put("generation", generation)
            .put("device_statement_sha256", b64.encodeToString(sha256(proof.deviceStatement())))
            .put("device_signature_sha256", b64.encodeToString(signatureDigest))

        assertFalse(SmsLineActivationFrames.activated(activated(ByteArray(32))).matches(proof))
        assertFalse(SmsLineActivationFrames.activated(activated(generation = 2)).matches(proof))
        assertTrue(rejects {
            SmsLineActivationFrames.activated(activated().put("device_signature_sha256", "AQ"))
        })
        assertTrue(rejects { SmsLineActivationFrames.activated(activated().put("accepted", true)) })
        val ack = SmsLineActivationFrames.activated(activated())
        assertTrue(ack.matches(proof))

        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        try {
            val dao = db.attempts()
            // The ack is bound to the authenticated account and device of this stream.
            assertFalse(producer.installAfterAuthenticatedAck(dao, proof, ack,
                UUID.randomUUID(), device))
            assertNull(dao.currentLineBinding())
            now = 2_000L
            assertTrue(producer.installAfterAuthenticatedAck(dao, proof, ack, account, device))
            assertEquals(line.toString(), dao.currentLineBinding()?.lineId)
            assertEquals(42, dao.currentLineBinding()?.cardId)
        } finally { db.close() }
    }

    @Test fun resentAcknowledgementInstallsAfterExpiryOnlyWithinTheHubResendWindow() {
        var now = 1_000L
        val producer = SmsLineActivationDevice({ 30 }, { 7 },
            { listOf(ActiveSimCard(7, 42)) }, ::signer, { now })
        val proof = producer.prepare(SmsLineActivationFrames.challenge(challengeFrame()),
            account, device)!!
        val ack = SmsLineActivationFrames.activated(JSONObject().put("v", 1)
            .put("type", "sms_line_activated").put("challenge_id", challengeId.toString())
            .put("account_id", account.toString()).put("line_id", line.toString())
            .put("device_id", device.toString()).put("generation", 1)
            .put("device_statement_sha256", b64.encodeToString(sha256(proof.deviceStatement())))
            .put("device_signature_sha256", b64.encodeToString(sha256(proof.deviceSignatureDer()))))
        val expiry = proof.challenge.expiresAtMs
        for ((at, installs) in listOf(expiry + SmsLineActivationDevice.ACK_GRACE_MS to false,
                                      expiry + 60_000L to true)) {
            val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
                SmsJournalDatabase::class.java).allowMainThreadQueries().build()
            try {
                now = at
                assertEquals(installs, producer.installAfterAuthenticatedAck(db.attempts(), proof,
                    ack, account, device))
            } finally { db.close() }
        }
    }

    @Test fun acknowledgementRecognisesAnInstalledOrConflictingBinding() {
        val ack = AuthenticatedSmsLineActivationAck.fromActivatedFrame(challengeId, account, line,
            device, 3, ByteArray(32), ByteArray(32))
        fun binding(lineId: UUID = line, generation: Long = 3, accountId: UUID = account) =
            LocalLineBinding(accountId = accountId.toString(), deviceId = device.toString(),
                lineId = lineId.toString(), generation = generation, subscriptionId = 7,
                installedAtMs = 1, cardId = 42)
        assertTrue(ack.isInstalledAs(binding()))
        assertFalse(ack.isInstalledAs(null))
        assertFalse(ack.isInstalledAs(binding(generation = 2)))
        assertFalse(ack.isInstalledAs(binding(accountId = UUID.randomUUID())))
        assertFalse(ack.conflictsWith(null))
        assertFalse(ack.conflictsWith(binding()))
        assertFalse(ack.conflictsWith(binding(generation = 2)))
        assertTrue(ack.conflictsWith(binding(generation = 4)))
        assertTrue(ack.conflictsWith(binding(lineId = UUID.randomUUID(), generation = 1)))
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)
}
