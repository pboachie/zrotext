// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import androidx.room.Room
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Phone-side retention: only settled evidence older than the window leaves the device. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class JournalRetentionRoomTest {
    private lateinit var db: SmsJournalDatabase
    private lateinit var dao: SmsAttemptDao
    private val retention = GatewayApplication.EVIDENCE_RETENTION_MS
    private val now = System.currentTimeMillis()
    private val old = now - retention - 60_000
    private val recent = now - retention + 60_000
    private val ciphertext = ByteArray(24) { (it + 5).toByte() }
    private val nonce = ByteArray(12) { it.toByte() }
    private val stopToken = "c".repeat(64)

    @Before fun setUp() {
        db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        dao = db.attempts()
    }

    @After fun tearDown() = db.close()

    private fun uuid(seed: Int) = "00000000-0000-4000-8000-" +
        seed.toString().padStart(12, '0')

    private fun settleAlphaEvents(at: Long) {
        while (true) {
            val event = dao.nextAlphaEvent() ?: return
            if (event.evidence == "durable_submit_intent") {
                dao.acknowledgeAlphaIntent(event.eventId, false, at)
            } else {
                assertTrue(dao.acknowledgeAlphaEvent(event.eventId, at) == 1)
            }
        }
    }

    private fun seedSettledAlphaAttempt(attemptSeed: Int, at: Long) {
        val attempt = uuid(attemptSeed)
        dao.reserveAlpha(attempt, uuid(attemptSeed + 100), 7, 1, uuid(attemptSeed + 200), at)
        dao.acknowledgeAlphaIntent(uuid(attemptSeed + 200), false, at + 1)
        settleAlphaEvents(at + 2)
    }

    private fun seedCapturedInbound(attemptSeed: Int, at: Long, senderToken: String): String {
        val attempt = uuid(attemptSeed)
        val messageId = uuid(attemptSeed + 100)
        val intent = uuid(attemptSeed + 200)
        dao.reserveAlpha(attempt, messageId, 7, 1, intent, at, senderToken)
        dao.acknowledgeAlphaIntent(intent, true, at + 1)
        dao.consumeRadioStart(attempt, messageId, 7, 1, at + 2)
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, at + 3)
        val window = dao.activeInboundWindows(senderToken, at + 4).single()
        val event = dao.recordInbound(window, uuid(attemptSeed + 300), 7, 1, at + 4,
            ciphertext, nonce)!!
        assertEquals(InboundClassification.CAPTURED_LOCAL, event.classification)
        assertNotNull(event.encryptedBody)
        dao.signInboundUpload(event.eventId, testEvidenceIdentity.accountId,
            testEvidenceIdentity.deviceId, ByteArray(70) { it.toByte() })
        return event.eventId
    }

    @Test fun acknowledgedAndQuarantinedEvidenceOlderThanRetentionLeavesThePhone() {
        // Quarantined old evidence leaves even though it was never acknowledged.
        dao.reserveAlpha(uuid(3), uuid(103), 7, 1, uuid(203), old)
        dao.acknowledgeAlphaIntent(uuid(203), false, old + 1)
        val quarantinedEvent = dao.nextAlphaEvent()!!
        assertEquals(1, dao.quarantineAlphaEvent(quarantinedEvent.eventId, "identity_changed", old))
        seedSettledAlphaAttempt(1, old)
        seedSettledAlphaAttempt(2, recent)
        dao.reserveAlpha(uuid(8), uuid(108), 7, 1, uuid(208), old) // never settled
        val inboundOld = seedCapturedInbound(4, old, "a".repeat(64))
        val inboundUnacked = seedCapturedInbound(5, old, "b".repeat(64))
        // Acknowledge exactly the first inbound upload; its ciphertext must clear at ack time.
        assertEquals(1, dao.acknowledgeInboundAck(inboundOld, old + 10, false))
        assertNull(dao.inboundByEventId(inboundOld)?.encryptedBody)
        assertNull(dao.inboundByEventId(inboundOld)?.nonce)

        assertTrue(dao.pruneAcknowledgedEvidence(now, retention))

        // Settled and quarantined old rows are gone with their children.
        assertNull(dao.getAttempt(uuid(1)))
        assertNull(dao.getAlphaEvent(uuid(201)))
        assertNull(dao.getAlphaEvent(quarantinedEvent.eventId))
        assertNull(dao.inboundByEventId(inboundOld))
        assertNull(dao.inboundUpload(inboundOld))
        // Recent settled work, unacknowledged evidence and pending uploads survive.
        assertNotNull(dao.getAttempt(uuid(2)))
        assertNotNull(dao.getAttempt(uuid(8)))
        assertNotNull(dao.getAlphaEvent(uuid(208)))
        assertNotNull(dao.inboundByEventId(inboundUnacked))
        assertNotNull(dao.inboundUpload(inboundUnacked))
    }

    @Test fun settledStopUploadLeavesButTheSuppressionBlockStays() {
        val eventId = uuid(60)
        db.openHelper.writableDatabase.execSQL(
            "INSERT INTO local_inbound_withdrawals(dedupeToken, senderToken, classification, " +
                "observedSubscriptionId, receivedAtMs, eventId, deviceSequence, acknowledgedAtMs) " +
                "VALUES(?, ?, 'opt_out', 7, ?, ?, 5, ?)",
            arrayOf(uuid(61), stopToken, old.toString(), eventId, old.toString()))
        val pending = uuid(62)
        db.openHelper.writableDatabase.execSQL(
            "INSERT INTO local_inbound_withdrawals(dedupeToken, senderToken, classification, " +
                "observedSubscriptionId, receivedAtMs, eventId, deviceSequence, acknowledgedAtMs) " +
                "VALUES(?, ?, 'opt_out', 7, ?, ?, 6, NULL)",
            arrayOf(uuid(63), "d".repeat(64), old.toString(), pending))
        db.openHelper.writableDatabase.execSQL(
            "INSERT INTO local_recipient_suppressions(senderToken, observedAtMs) VALUES(?, ?)",
            arrayOf(stopToken, old.toString()))

        assertTrue(dao.pruneAcknowledgedEvidence(now, retention))

        assertNull(dao.lineOptOutByEventId(eventId))
        assertEquals(true, dao.isRecipientSuppressed(stopToken))
        assertNotNull(dao.lineOptOutByEventId(pending))
    }

    @Test fun periodicPruneNeverRewritesLiveAttemptStates() {
        // A reserved attempt and an authorized submitting send must survive the
        // daily task untouched; only startup crash recovery may reclassify them.
        dao.reserveAlpha(uuid(20), uuid(120), 7, 1, uuid(220), old)
        assertEquals(true, dao.acknowledgeAlphaIntent(uuid(220), true, old + 1))
        dao.consumeRadioStart(uuid(20), uuid(120), 7, 1, old + 2)
        assertEquals("radio_started", dao.getAttempt(uuid(20))?.state)
        dao.reserveAlpha(uuid(22), uuid(122), 7, 1, uuid(222), old)
        assertEquals("reserved", dao.getAttempt(uuid(22))?.state)

        pruneJournalEvidence(dao, now)

        assertEquals("radio_started", dao.getAttempt(uuid(20))?.state)
        assertEquals("reserved", dao.getAttempt(uuid(22))?.state)
        assertNotNull(dao.getAlphaEvent(uuid(222)))

        // The startup path is the one that reclassifies a dead process's states.
        recoverJournalState(dao, now)
        assertEquals("not_submitted", dao.getAttempt(uuid(22))?.state)
        assertEquals("unknown", dao.getAttempt(uuid(20))?.state)
    }

    @Test fun terminalAttemptWithUnacknowledgedInboundUploadSurvivesThePrune() {
        val eventId = seedCapturedInbound(10, old, "e".repeat(64))
        // Settle every alpha event too, so only the pending inbound upload
        // keeps this terminal attempt alive.
        settleAlphaEvents(old + 5)

        assertTrue(dao.pruneAcknowledgedEvidence(now, retention))

        assertNotNull(dao.getAttempt(uuid(10)))
        assertNotNull(dao.inboundByEventId(eventId))
        assertNotNull(dao.inboundUpload(eventId))
    }

    @Test fun nothingIsPrunedInsideTheRetentionWindow() {
        seedSettledAlphaAttempt(7, recent)
        assertEquals(false, dao.pruneAcknowledgedEvidence(now, retention))
        assertNotNull(dao.getAttempt(uuid(7)))
    }

    @Test fun terminalAttemptWithUnacknowledgedRadioEvidenceSurvivesThePrune() {
        dao.reserveAlpha(uuid(9), uuid(109), 7, 1, uuid(209), old)
        dao.acknowledgeAlphaIntent(uuid(209), true, old + 1)
        dao.consumeRadioStart(uuid(9), uuid(109), 7, 1, old + 2)
        dao.recordCallback(uuid(9), 0, false, Activity.RESULT_OK, null, old + 3)
        val unackedCallback = dao.nextAlphaEvent()!!
        assertEquals(uuid(9), unackedCallback.attemptId)

        assertTrue(dao.pruneAcknowledgedEvidence(now, retention))

        assertNotNull(dao.getAttempt(uuid(9)))
        assertNotNull(dao.getAlphaEvent(unackedCallback.eventId))
    }
}
