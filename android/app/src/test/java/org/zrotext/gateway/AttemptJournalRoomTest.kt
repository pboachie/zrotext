// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import android.content.Context
import androidx.room.Room
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class AttemptJournalRoomTest {
    private lateinit var db: SmsJournalDatabase
    private lateinit var dao: SmsAttemptDao

    @Before fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java
        ).allowMainThreadQueries().build()
        dao = db.attempts()
    }

    @After fun tearDown() {
        db.close()
    }

    @Test fun committedIntentCannotBeReservedAgainAndRestartLeavesItUnknown() {
        val id = "c84ab19f-e2a7-42cc-9897-475091a61d31"
        dao.reserve(id, 3, 2, 10)
        assertEquals(AttemptState.SUBMITTING, dao.getAttempt(id)?.state)
        assertEquals(2, dao.getSegments(id).size)
        assertThrows(RuntimeException::class.java) { dao.reserve(id, 3, 2, 11) }
        assertEquals(2, dao.getSegments(id).size)
        dao.markInterrupted(20)
        assertEquals(AttemptState.UNKNOWN, dao.getAttempt(id)?.state)
        dao.recordCallback(id, 0, false, Activity.RESULT_OK, null, 30)
        assertEquals(AttemptState.UNKNOWN, dao.getAttempt(id)?.state)
        dao.recordCallback(id, 1, false, Activity.RESULT_OK, null, 40)
        assertEquals(AttemptState.SUBMITTED, dao.getAttempt(id)?.state)
        dao.recordCallback(id, 0, false, Activity.RESULT_OK, null, 50)
        assertEquals(AttemptState.SUBMITTED, dao.getAttempt(id)?.state)
        dao.recordCallback(id, 0, false, 1, null, 60)
        assertEquals(AttemptState.UNKNOWN, dao.getAttempt(id)?.state)
        assertTrue(dao.getAttempt(id)!!.evidenceConflict)
        dao.recordCallback(id, 0, true, Activity.RESULT_OK, DeliveryStatus.RECEIVED, 70)
        assertEquals(AttemptState.UNKNOWN, dao.getAttempt(id)?.state)
    }

    @Test fun lateDeliveryReportResolvesUnverifiedReceiptWithoutBlindRetry() {
        val id = "a11cd605-2578-4da2-81aa-ff2a4cc86cf1"
        dao.reserve(id, 3, 1, 10)
        dao.recordCallback(id, 0, false, Activity.RESULT_OK, null, 20)
        dao.markTimedOutDeliveries(100, 200)
        assertEquals(AttemptState.DELIVERY_UNKNOWN, dao.getAttempt(id)?.state)
        dao.recordCallback(id, 0, true, Activity.RESULT_OK, DeliveryStatus.UNVERIFIED, 300)
        assertEquals(AttemptState.DELIVERY_UNKNOWN, dao.getAttempt(id)?.state)
        dao.recordCallback(id, 0, true, Activity.RESULT_OK, DeliveryStatus.RECEIVED, 400)
        assertEquals(AttemptState.DELIVERED, dao.getAttempt(id)?.state)
    }

    @Test fun missingSegmentCallbackBecomesUnknownAndLateEvidenceCanResolveIt() {
        val id = "0864b607-3342-43bb-b023-7c7b8ddebd43"
        dao.reserve(id, 3, 2, 10)
        dao.recordCallback(id, 0, false, Activity.RESULT_OK, null, 20)
        assertEquals(AttemptState.SUBMITTING, dao.getAttempt(id)?.state)
        dao.markStalledSubmission(id, 30)
        assertEquals(AttemptState.UNKNOWN, dao.getAttempt(id)?.state)
        dao.recordCallback(id, 1, false, Activity.RESULT_OK, null, 40)
        assertEquals(AttemptState.SUBMITTED, dao.getAttempt(id)?.state)
        dao.markStalledSubmission(id, 50)
        assertEquals(AttemptState.SUBMITTED, dao.getAttempt(id)?.state)
    }

    @Test fun impossibleCallbackAfterRecordedNoSendForcesUnknown() {
        val id = "9a5ac24d-e6ca-4533-84ab-58e68fecb39a"
        dao.reserve(id, 3, 1, 10)
        dao.setState(id, AttemptState.NOT_SUBMITTED, 20)
        dao.markInterrupted(30)
        assertEquals(AttemptState.NOT_SUBMITTED, dao.getAttempt(id)?.state)
        dao.recordCallback(id, 0, false, Activity.RESULT_OK, null, 40)
        assertEquals(Activity.RESULT_OK, dao.getSegment(id, 0)?.sentResultCode)
        assertEquals(AttemptState.UNKNOWN, dao.getAttempt(id)?.state)
        assertTrue(dao.getAttempt(id)!!.evidenceConflict)
    }

    @Test fun alphaIntentAndCallbackAreDurableAndAcknowledgedOnce() {
        val attempt = "c1b2f661-6813-43c2-8c6a-f91423c0f944"
        val message = "16680f7e-27ea-4b65-b33e-9f17d1875b60"
        val intent = "5e53ad82-3dba-4674-bac3-1a08301e7f2e"
        dao.reserveAlpha(attempt, message, 3, 1, intent, 10)
        assertEquals(AttemptState.RESERVED, dao.getAttempt(attempt)?.state)
        assertEquals(intent, dao.nextAlphaEvent()?.eventId)
        assertThrows(RuntimeException::class.java) { dao.reserveAlpha(attempt, message, 3, 1, intent, 11) }
        assertTrue(dao.acknowledgeAlphaIntent(intent, true, 20))
        assertEquals(AttemptState.SUBMITTING, dao.getAttempt(attempt)?.state)
        assertEquals(1, dao.consumeRadioStart(attempt, message, 3, 1, 21))
        assertEquals(AttemptState.RADIO_STARTED, dao.getAttempt(attempt)?.state)
        assertEquals(0, dao.consumeRadioStart(attempt, message, 3, 1, 22))
        assertEquals(0, dao.markAcknowledgedNoRadio(attempt, 23))
        assertEquals(null, dao.nextAlphaEvent())
        assertEquals(false, dao.acknowledgeAlphaIntent(intent, true, 21))
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 30)
        dao.recordCallback(attempt, 0, true, Activity.RESULT_OK, DeliveryStatus.RECEIVED, 30)
        val callback = dao.nextAlphaEvent()!!
        assertEquals(message, callback.messageId)
        assertEquals("sent_callback_ok", callback.evidence)
        assertEquals(0, callback.segmentIndex)
        assertEquals(1, callback.segmentCount)
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 31)
        assertEquals(callback.eventId, dao.nextAlphaEvent()?.eventId)
        dao.acknowledgeAlphaEvent(callback.eventId, 40)
        val delivery = dao.nextAlphaEvent()!!
        assertEquals("delivery_callback_ok", delivery.evidence)
        assertEquals(null, delivery.segmentIndex)
        dao.recordCallback(attempt, 0, true, Activity.RESULT_OK, DeliveryStatus.RECEIVED, 51)
        assertEquals(delivery.eventId, dao.nextAlphaEvent()?.eventId)
    }

    @Test fun restartAndDeniedAckCannotAuthorizeRadio() {
        val attempt = "aae2e1c8-3833-4755-88c7-3f30e1588b08"
        val message = "f5368533-8bc8-43e7-925d-f64d9b11ce69"
        val intent = "35ee372e-2e1d-474f-b979-21075baed095"
        dao.reserveAlpha(attempt, message, 3, 1, intent, 10)
        dao.markUnsentReservations(20)
        assertEquals(AttemptState.NOT_SUBMITTED, dao.getAttempt(attempt)?.state)
        assertEquals(false, dao.acknowledgeAlphaIntent(intent, true, 30))
        assertEquals(null, dao.nextAlphaEvent())
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 40)
        assertEquals(AttemptState.UNKNOWN, dao.getAttempt(attempt)?.state)
        assertEquals(null, dao.nextAlphaEvent())

        val secondAttempt = "35019d46-ad54-4acd-a82e-06179feeb08a"
        val secondIntent = "94d2431f-e8d2-43f6-b953-d5b40d4e7883"
        dao.reserveAlpha(secondAttempt, message, 3, 1, secondIntent, 50)
        assertEquals(false, dao.acknowledgeAlphaIntent(secondIntent, false, 60))
        assertEquals(AttemptState.NOT_SUBMITTED, dao.getAttempt(secondAttempt)?.state)
        assertEquals(0, dao.markAcknowledgedNoRadio(secondAttempt, 61))
    }

    @Test fun versionOneJournalMigratesWithoutDiscardingAttempt() {
        val context = RuntimeEnvironment.getApplication()
        val name = "journal-migration-test.db"
        context.deleteDatabase(name)
        val old = context.openOrCreateDatabase(name, Context.MODE_PRIVATE, null)
        old.execSQL("CREATE TABLE sms_attempts (attemptId TEXT NOT NULL PRIMARY KEY, subscriptionId INTEGER NOT NULL, segmentCount INTEGER NOT NULL, state TEXT NOT NULL, createdAtMs INTEGER NOT NULL, updatedAtMs INTEGER NOT NULL)")
        old.execSQL("CREATE TABLE sms_segments (attemptId TEXT NOT NULL, segmentIndex INTEGER NOT NULL, sentResultCode INTEGER, deliveryResultCode INTEGER, deliveryStatus INTEGER, PRIMARY KEY(attemptId, segmentIndex), FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)")
        old.execSQL("CREATE INDEX index_sms_segments_attemptId ON sms_segments(attemptId)")
        old.execSQL("INSERT INTO sms_attempts VALUES ('legacy-attempt', 3, 1, 'submitting', 10, 10)")
        old.execSQL("INSERT INTO sms_segments(attemptId, segmentIndex) VALUES ('legacy-attempt', 0)")
        old.version = 1
        old.close()

        val migrated = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().addMigrations(
                SmsJournalDatabase.MIGRATION_1_2, SmsJournalDatabase.MIGRATION_2_3).build()
        try {
            assertNotNull(migrated.attempts().getAttempt("legacy-attempt"))
            assertEquals(false, migrated.attempts().getAttempt("legacy-attempt")!!.evidenceConflict)
            assertEquals(null, migrated.attempts().getAttempt("legacy-attempt")!!.messageId)
            migrated.attempts().markInterrupted(20)
            assertEquals(AttemptState.UNKNOWN, migrated.attempts().getAttempt("legacy-attempt")?.state)
        } finally {
            migrated.close()
            context.deleteDatabase(name)
        }
    }
}
