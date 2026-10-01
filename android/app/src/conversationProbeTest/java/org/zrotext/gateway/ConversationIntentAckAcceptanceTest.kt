// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Metadata/Room probes only; the socket never leaves this process and no radio API is called. */
@RunWith(AndroidJUnit4::class)
class ConversationIntentAckAcceptanceTest {
    private val account = UUID.randomUUID()
    private val device = UUID.randomUUID()
    private val identity = EvidenceIdentity(account.toString(), device.toString(), "11".repeat(32))
    private val session = ConversationPhoneSession(account, device, UUID.randomUUID(), 7, 3, identity.originHash)
    private fun id() = UUID.randomUUID().toString()
    private fun database(name: String): SmsJournalDatabase = Room.databaseBuilder(
        InstrumentationRegistry.getInstrumentation().targetContext, SmsJournalDatabase::class.java, name)
        .allowMainThreadQueries().build()
    private fun withDatabase(body: (String, SmsJournalDatabase) -> Unit) {
        val name = "conversation-acceptance-${id()}.db"
        val db = database(name)
        try { body(name, db) } finally {
            db.close(); InstrumentationRegistry.getInstrumentation().targetContext.deleteDatabase(name)
        }
    }
    private fun reopened(name: String, body: (SmsJournalDatabase) -> Unit) {
        val db = database(name)
        try { body(db) } finally { db.close() }
    }
    @Test fun durableIntentAndAcknowledgmentRemainExactAfterDatabaseReopen() = withDatabase { name, db ->
        val attempt = id(); val message = id(); val event = id()
        db.attempts().reserveAlpha(attempt, message, 3, 1, event, 100, identity = identity)
        assertEquals(0, db.attempts().consumeRadioStart(attempt, message, 3, 1, 101))
        db.close()
        reopened(name) { reopened ->
            val row = checkNotNull(reopened.attempts().getAlphaEvent(event))
            assertEquals(message, row.messageId); assertEquals(attempt, row.attemptId)
            assertEquals(identity.accountId, row.accountId); assertEquals(identity.deviceId, row.deviceId)
            assertEquals(identity.originHash, row.originHash); assertNull(row.acknowledgedAtMs)
            assertTrue(reopened.attempts().acknowledgeAlphaIntent(event, true, 102))
        }
        reopened(name) { reopened ->
            assertEquals(102L, reopened.attempts().getAlphaEvent(event)!!.acknowledgedAtMs)
            assertFalse(reopened.attempts().acknowledgeAlphaIntent(event, true, 103))
            assertEquals(AttemptState.SUBMITTING, reopened.attempts().getAttempt(attempt)!!.state)
            assertEquals(1, reopened.attempts().consumeRadioStart(attempt, message, 3, 1, 104))
            assertEquals(0, reopened.attempts().consumeRadioStart(attempt, message, 3, 1, 105))
        }
    }
    @Test fun deniedAckCannotBecomePermittedOnReplayOrCrossAttemptCas() = withDatabase { _, db ->
        val attempt = id(); val message = id(); val event = id()
        val other = id(); val otherMessage = id(); val otherEvent = id()
        db.attempts().reserveAlpha(attempt, message, 3, 1, event, 100, identity = identity)
        db.attempts().reserveAlpha(other, otherMessage, 4, 2, otherEvent, 100, identity = identity)
        assertFalse(db.attempts().acknowledgeAlphaIntent(event, false, 101))
        assertFalse(db.attempts().acknowledgeAlphaIntent(event, true, 102))
        assertEquals(AttemptState.NOT_SUBMITTED, db.attempts().getAttempt(attempt)!!.state)
        assertEquals(0, db.attempts().consumeRadioStart(attempt, message, 3, 1, 103))
        assertTrue(db.attempts().acknowledgeAlphaIntent(otherEvent, true, 101))
        assertEquals(0, db.attempts().consumeRadioStart(other, message, 4, 2, 103))
        assertEquals(0, db.attempts().consumeRadioStart(other, otherMessage, 3, 2, 103))
        assertEquals(0, db.attempts().consumeRadioStart(other, otherMessage, 4, 1, 103))
        assertEquals(1, db.attempts().consumeRadioStart(other, otherMessage, 4, 2, 104))
    }
    @Test fun unknownAttemptCannotBeAuthorizedAgainByLateAck() = withDatabase { _, db ->
        val attempt = id(); val message = id(); val event = id()
        db.attempts().reserveAlpha(attempt, message, 3, 1, event, 100, identity = identity)
        db.attempts().setState(attempt, AttemptState.UNKNOWN, 101)
        assertFalse(db.attempts().acknowledgeAlphaIntent(event, true, 102))
        assertEquals(AttemptState.UNKNOWN, db.attempts().getAttempt(attempt)!!.state)
        assertEquals(0, db.attempts().consumeRadioStart(attempt, message, 3, 1, 103))
    }
    private fun event() = AlphaRadioEvent(id(), id(), id(), "durable_submit_intent", 100,
        accountId = identity.accountId, deviceId = identity.deviceId, originHash = identity.originHash)
    /** Reflection permits compilation against the reviewed pre-adapter baseline. Missing methods
     * fail acceptance explicitly; there is no skip or fake routing implementation.
     */
    private fun route(wire: ConversationSocketWire, owner: ConversationPhoneSession, event: String,
                      state: String = "submitting", permitted: Boolean = true): String =
        checkNotNull(wire.javaClass.getDeclaredMethod("acceptRadioAck", ConversationPhoneSession::class.java,
            String::class.java, String::class.java, java.lang.Boolean.TYPE)
            .invoke(wire, owner, event, state, permitted)).toString()
    private fun submit(wire: ConversationSocketWire, owner: ConversationPhoneSession, event: AlphaRadioEvent): Boolean =
        wire.javaClass.getDeclaredMethod("submitIntent", ConversationPhoneSession::class.java, AlphaRadioEvent::class.java)
            .invoke(wire, owner, event) as Boolean
    private fun queuedIntent(dao: SmsAttemptDao, excluded: List<String>): AlphaRadioEvent? =
        dao.javaClass.getMethod("nextAlphaEvent", String::class.java, String::class.java,
            String::class.java, List::class.java)
            .invoke(dao, identity.accountId, identity.deviceId, identity.originHash, excluded) as AlphaRadioEvent?
    @Test fun liveSealedIntentDoesNotStarveOrdinaryPumpOrOwnCallbackEvidence() = withDatabase { _, db ->
        val owned = event(); val ordinary = event()
        val type = Class.forName("org.zrotext.gateway.ConversationRadioIntentOwnership")
        val registry = type.getField("INSTANCE").get(null)
        val lease = type.getDeclaredMethod("register", ConversationPhoneSession::class.java,
            String::class.java, String::class.java, String::class.java)
            .invoke(registry, session, owned.eventId, owned.messageId, owned.attemptId) as AutoCloseable
        try {
            db.sealedPreparations().reserve(SealedPreparationRecord(identity.accountId, owned.messageId,
                owned.attemptId, "01".repeat(32), "02".repeat(32))) {}
            for (intent in listOf(owned, ordinary)) db.attempts().reserveAlpha(intent.attemptId,
                intent.messageId, 3, 1, intent.eventId, 100, identity = identity)
            assertEquals(ordinary.eventId, queuedIntent(db.attempts(), listOf(owned.eventId))?.eventId)
            db.attempts().acknowledgeAlphaEvent(ordinary.eventId, 101)
            val callback = owned.copy(eventId = id(), evidence = "sent_ok")
            db.attempts().insertAlphaEvent(callback)
            assertEquals(callback.eventId, queuedIntent(db.attempts(), listOf(owned.eventId))?.eventId)
            assertEquals(false, type.getDeclaredMethod("owns", AlphaRadioEvent::class.java).invoke(registry, callback))
        } finally { lease.close() }
    }
    @Test fun durableSealedIntentCannotReenterPumpAfterDatabaseReopenAndRecovery() = withDatabase { name, db ->
        val intent = event()
        db.sealedPreparations().reserve(SealedPreparationRecord(identity.accountId, intent.messageId,
            intent.attemptId, "01".repeat(32), "02".repeat(32))) {}
        db.attempts().reserveAlpha(intent.attemptId, intent.messageId, 3, 1, intent.eventId, 100, identity = identity)
        db.close()
        reopened(name) { reopened ->
            val dao = reopened.attempts()
            assertNull(queuedIntent(dao, emptyList()))
            recoverJournalState(dao, 101)
            assertEquals(AttemptState.NOT_SUBMITTED, dao.getAttempt(intent.attemptId)!!.state)
            assertNotNull(dao.getAlphaEvent(intent.eventId)!!.acknowledgedAtMs)
            assertEquals("proven_no_submit", queuedIntent(dao, emptyList())?.evidence)
            assertFalse(dao.acknowledgeAlphaIntent(intent.eventId, true, 102))
            assertEquals(0, dao.consumeRadioStart(intent.attemptId, intent.messageId, 3, 1, 103))
            assertNotNull(reopened.sealedPreparations().find(identity.accountId, intent.messageId))
        }
    }
    @Test fun processOwnershipExcludesOnlyExactLiveIntentAndOldCloseCannotReleaseSuccessor() {
        val type = Class.forName("org.zrotext.gateway.ConversationRadioIntentOwnership")
        val registry = type.getField("INSTANCE").get(null)
        val register = type.getDeclaredMethod("register", ConversationPhoneSession::class.java,
            String::class.java, String::class.java, String::class.java)
        val owns = type.getDeclaredMethod("owns", AlphaRadioEvent::class.java)
        val excluded = type.getDeclaredMethod("excluded", EvidenceIdentity::class.java)
        val event = event()
        val first = register.invoke(registry, session, event.eventId, event.messageId, event.attemptId) as AutoCloseable
        try {
            assertEquals(true, owns.invoke(registry, event))
            assertEquals(false, owns.invoke(registry, event.copy(accountId = id())))
            assertEquals(false, owns.invoke(registry, event.copy(deviceId = id())))
            assertEquals(false, owns.invoke(registry, event.copy(originHash = "22".repeat(32))))
            assertEquals(false, owns.invoke(registry, event.copy(attemptId = id())))
            assertEquals(false, owns.invoke(registry, event.copy(evidence = "proven_no_submit")))
            assertEquals(listOf(event.eventId), excluded.invoke(registry, identity))
            assertEquals(emptyList<String>(), excluded.invoke(registry, identity.copy(accountId = id())))
            first.close(); assertEquals(false, owns.invoke(registry, event))
            val successor = register.invoke(registry, session, event.eventId, event.messageId, event.attemptId) as AutoCloseable
            try { first.close(); assertEquals(true, owns.invoke(registry, event)) }
            finally { successor.close() }
            assertEquals(false, owns.invoke(registry, event))
        } finally { first.close() }
    }
    private fun wireCase(body: (ConversationSocketWire, AlphaRadioEvent, AtomicReference<ConversationPhoneSession?>,
                                CountDownLatch, AtomicReference<JSONObject?>) -> Unit) {
        val current = AtomicReference<ConversationPhoneSession?>(session)
        val sent = CountDownLatch(1); val frame = AtomicReference<JSONObject?>()
        val socket = object : okhttp3.WebSocket {
            override fun request() = okhttp3.Request.Builder().url("https://example.org").build()
            override fun queueSize() = 0L
            override fun send(text: String): Boolean { frame.set(JSONObject(text)); sent.countDown(); return true }
            override fun send(bytes: okio.ByteString): Boolean = error("Unexpected content request")
            override fun close(code: Int, reason: String?) = true
            override fun cancel() = Unit
        }
        val wire = ConversationSocketWire(socket, current::get, 1000)
        try { body(wire, event(), current, sent, frame) } finally { wire.invalidate() }
    }
    @Test fun onlyExactLiveAckIsConsumedAndDuplicatesCannotReachOtherDispatcher() = wireCase { wire, event, _, sent, frame ->
        val worker = Executors.newSingleThreadExecutor()
        try {
            val result = worker.submit<Boolean> { submit(wire, session, event) }
            assertTrue(sent.await(2, TimeUnit.SECONDS))
            assertEquals(setOf("v", "type", "connection_epoch", "event_id", "message_id", "attempt_id", "evidence", "observed_at_ms"),
                checkNotNull(frame.get()).keys().asSequence().toSet())
            assertEquals("NOT_OURS", route(wire, session, id()))
            assertEquals("KNOWN_STALE", route(wire, session.copy(session = UUID.randomUUID()), event.eventId))
            assertEquals("KNOWN_STALE", route(wire, session, event.eventId, "unknown"))
            assertFalse(result.isDone)
            assertEquals("CONSUMED", route(wire, session, event.eventId))
            assertTrue(result.get(2, TimeUnit.SECONDS))
            assertEquals("KNOWN_STALE", route(wire, session, event.eventId))
        } finally { wire.invalidate(); worker.shutdownNow() }
    }
    @Test fun sessionRotationReleasesWaitWithoutAuthorityAndAbsorbsLateAck() = wireCase { wire, event, current, sent, _ ->
        val worker = Executors.newSingleThreadExecutor()
        try {
            val result = worker.submit<Boolean> { submit(wire, session, event) }
            assertTrue(sent.await(2, TimeUnit.SECONDS))
            current.set(session.copy(connectionEpoch = 8)); wire.invalidate()
            assertThrows(java.util.concurrent.ExecutionException::class.java) { result.get(2, TimeUnit.SECONDS) }
            assertEquals("KNOWN_STALE", route(wire, session, event.eventId))
        } finally { wire.invalidate(); worker.shutdownNow() }
    }
}
