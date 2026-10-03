// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.io.IOException
import java.util.UUID
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Ordinary sealed metadata + actual Room/guarded-holder/CAS consumer. Synthetic fixture custody
 * and fake Android APIs only: no conversation scope, hardware claim or platform SMS operation. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class JournaledPreparedRadioSubmissionTest {
    private class Harness(private val enabled: Boolean = true) : AutoCloseable {
        private val fixture = PreparationFixture()
        private val candidate = fixture.grant()
        private val binding = fixture.binding()
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        var now = fixture.now
        var current = true
        var permit = true
        var lostAck = false
        var ambiguous = false
        var metadataCalls = 0
        var factories = 0
        var fakeCalls = 0
        var selections = 0
        var ackHook: () -> Unit = {}
        var selectedHook: () -> Unit = {}
        var event: AlphaRadioEvent? = null
        private val session = SealedDispatchExecutor.Session(UUID.fromString(candidate.accountId),
            UUID.fromString(candidate.deviceId), candidate.connectionEpoch, candidate.deploymentEpoch,
            UUID.fromString(candidate.sessionId), candidate.originHash)
        private val fields = SealedExecutionGrantValidator.Fields(
            accountId = session.accountId, deviceId = session.deviceId,
            lineId = UUID.fromString(candidate.lineId), messageId = UUID.fromString(candidate.messageId),
            attemptId = UUID.fromString(candidate.attemptId), connectionEpoch = candidate.connectionEpoch,
            deploymentEpoch = candidate.deploymentEpoch, bindingGeneration = candidate.bindingGeneration,
            attemptGeneration = candidate.attemptGeneration, readerRole = 1,
            readerKeyId = PreparationFixture.hex(fixture.json.getString("deviceKeyId")),
            envelopeDigest = PreparationFixture.sha(fixture.envelope()),
            unsignedDigest = PreparationFixture.hex(candidate.unsignedDigest),
            expiresAtMs = candidate.expiresAtMs, segmentCount = 1)
        val context = object : JournaledRadioContext {
            override val message = candidate.messageId
            override val attempt = candidate.attemptId
            override val accountId = candidate.accountId
            override val deviceId = candidate.deviceId
            override val peer = fixture.request().peer().toString(Charsets.US_ASCII)
            override val originalDeadlineMs = candidate.expiresAtMs
            override val deadlineMs = candidate.expiresAtMs
            override val grant get() = SealedEnvelopeFetch.snapshot(fields)
            override val session = this@Harness.session
            override val local = SealedDispatchExecutor.Local(binding, fields.readerKeyId,
                candidate.manifestGeneration, candidate.manifestVersion, candidate.manifestDigest,
                candidate.recipientDigest)
        }
        private val record = SealedPreparationRecord(candidate.accountId, candidate.messageId,
            candidate.attemptId, candidate.unsignedDigest, candidate.identity())
        val body: CharArray
        private val holder: Draft02OutboundPreparation.Prepared
        private fun fresh(): Long {
            check(current && now > 0 && now < context.deadlineMs)
            check(db.attempts().currentLineBinding() == binding)
            return now
        }
        init {
            assertTrue(db.attempts().installVerifiedLineBinding(binding, listOf(ActiveSimCard(3, 7))))
            db.sealedPreparations().reserve(record) { assertEquals(binding, it) }
            val proof = fixture.proof()
            body = Draft02Body.open(proof, fixture.softwareCek(proof))
            // Existing private post-decrypt handoff; never substitute software for shipping custody.
            val finish = Draft02OutboundPreparation.javaClass.declaredMethods.single { it.name == "finish" }
                .apply { isAccessible = true }
            val line: (LocalLineBinding?) -> Unit = { assertEquals(binding, it) }
            val guard: () -> Unit = { fresh(); Unit }
            holder = finish.invoke(Draft02OutboundPreparation, db, record, body, 1, line, guard)
                as Draft02OutboundPreparation.Prepared
        }
        private val driver = object : ConversationRadioDriver {
            override fun requireSelected() { selections++; selectedHook() }
            override fun divide(body: String): ArrayList<String> {
                assertEquals("Candidate sealed text ✓", body)
                return arrayListOf(body)
            }
            override fun prepare(attempt: String, parts: ArrayList<String>) {
                assertEquals(candidate.attemptId, attempt); assertEquals(1, parts.size)
            }
            override fun close() = Unit
            override fun send(peer: String, attempt: String, parts: ArrayList<String>) {
                assertEquals(context.peer, peer)
                assertEquals(AttemptState.RADIO_STARTED, db.attempts().getAttempt(attempt)?.state)
                fakeCalls++
                if (ambiguous) throw IOException("Synthetic uncertain radio result")
            }
        }
        private val wire = object : ConversationRadioIntentWire {
            override fun submitIntent(session: ConversationPhoneSession, value: AlphaRadioEvent): Boolean {
                assertEquals(ConversationPhoneSession.from(this@Harness.session), session)
                assertTrue(ConversationRadioIntentOwnership.owns(value))
                metadataCalls++; event = value; ackHook()
                if (lostAck) throw IOException("Synthetic lost ACK")
                return permit
            }
        }
        fun submit(): ConversationSubmission {
            val relay = Draft02OutboundPreparation.relayPrepared(holder.segmentCount) { consumer ->
                fresh(); holder.consume(consumer)
            }
            return try {
                JournaledPreparedRadioSubmission(db.attempts(), wire, {
                    assertEquals(binding, it); factories++
                    ConversationRadioPlatform(it, driver, ConversationExistingSuppressionTokens {
                        SecretKeySpec(ByteArray(32) { 9 }, "HmacSHA256")
                    }, true)
                }, enabled).submit(context, relay, ::fresh)
            } finally { relay.close(); holder.close() } // Lane retains and closes the executor holder.
        }
        fun attempt() = db.attempts().getAttempt(candidate.attemptId)
        fun assertZeroized() { assertTrue(body.all { it == '\u0000' }) }
        fun assertPermanentReplayFence() {
            assertThrows(Exception::class.java) { db.sealedPreparations().reserve(record) {} }
            assertEquals(ConversationSubmission.UNKNOWN, submit())
        }
        override fun close() { holder.close(); db.close() }
    }
    @Test fun disabledOrdinaryConsumerCannotReserveIntentOrConsumeBody() = Harness(false).use { h ->
        assertEquals(ConversationSubmission.UNKNOWN, h.submit())
        assertNull(h.attempt()); assertEquals(0, h.metadataCalls); assertEquals(0, h.fakeCalls)
        h.assertZeroized(); h.assertPermanentReplayFence()
    }
    @Test fun deniedAckRecordsNoRadioAndNeverEntersPlatform() = Harness().use { h ->
        h.permit = false
        assertEquals(ConversationSubmission.UNKNOWN, h.submit())
        assertEquals(AttemptState.NOT_SUBMITTED, h.attempt()?.state)
        assertNotNull(h.db.attempts().getAlphaEvent(h.event!!.eventId)?.acknowledgedAtMs)
        assertEquals(0, h.factories); assertEquals(0, h.fakeCalls)
        h.assertZeroized(); h.assertPermanentReplayFence()
    }
    @Test fun lostAckRemainsUnknownAndPermanentSealedIdentityExcludesColdReplay() = Harness().use { h ->
        h.lostAck = true
        assertEquals(ConversationSubmission.UNKNOWN, h.submit())
        assertEquals(AttemptState.UNKNOWN, h.attempt()?.state)
        assertNull(h.db.attempts().getAlphaEvent(h.event!!.eventId)?.acknowledgedAtMs)
        assertFalse(ConversationRadioIntentOwnership.owns(h.event!!))
        // No process-local exclusion is supplied: the actual sealed journal identity fences restart.
        assertNull(h.db.attempts().nextAlphaEvent(h.context.accountId, h.context.deviceId,
            h.context.session.originHash))
        assertEquals(0, h.factories); h.assertZeroized(); h.assertPermanentReplayFence()
    }
    @Test fun ordinaryAckPermitsExactlyOneDurableCasBeforeOneFakeCall() = Harness().use { h ->
        assertEquals(ConversationSubmission.SUBMITTED, h.submit())
        assertEquals(1, h.metadataCalls); assertEquals(1, h.fakeCalls)
        assertEquals(AttemptState.RADIO_STARTED, h.attempt()?.state)
        assertEquals(0, h.db.attempts().consumeRadioStart(h.context.attempt, h.context.message, 3, 1, h.now))
        h.assertZeroized(); h.assertPermanentReplayFence(); assertEquals(1, h.fakeCalls)
    }
    @Test fun expiryOrOwnerWithdrawalWhileAckWaitsCannotEnterPlatform() {
        listOf(false, true).forEach { revoke -> Harness().use { h ->
            h.ackHook = { if (revoke) h.current = false else h.now = h.context.deadlineMs }
            assertEquals(ConversationSubmission.UNKNOWN, h.submit())
            assertEquals(0, h.factories); assertEquals(0, h.fakeCalls)
            assertNull(h.db.attempts().getAlphaEvent(h.event!!.eventId)?.acknowledgedAtMs)
            h.assertZeroized()
        } }
    }
    @Test fun expiryAfterSelectedProviderBeforeOrAfterCasCannotReachFakeRadio() {
        listOf(3, 4).forEach { target -> Harness().use { h ->
            h.selectedHook = { if (h.selections == target) h.now = h.context.deadlineMs }
            assertEquals(ConversationSubmission.UNKNOWN, h.submit())
            assertEquals(0, h.fakeCalls); assertNotEquals(AttemptState.RADIO_STARTED, h.attempt()?.state)
            h.assertZeroized(); h.assertPermanentReplayFence()
        } }
    }
    @Test fun throwingFakeRadioStaysAmbiguousAndCannotBeInvokedTwice() = Harness().use { h ->
        h.ambiguous = true
        assertEquals(ConversationSubmission.UNKNOWN, h.submit())
        assertEquals(AttemptState.UNKNOWN, h.attempt()?.state)
        assertEquals(1, h.fakeCalls); h.assertZeroized(); h.assertPermanentReplayFence()
        assertEquals(1, h.fakeCalls)
    }
}
