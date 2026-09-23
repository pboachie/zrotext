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
            .allowMainThreadQueries().addMigrations(SmsJournalDatabase.MIGRATION_1_2).build()
        try {
            assertNotNull(migrated.attempts().getAttempt("legacy-attempt"))
            assertEquals(false, migrated.attempts().getAttempt("legacy-attempt")!!.evidenceConflict)
            migrated.attempts().markInterrupted(20)
            assertEquals(AttemptState.UNKNOWN, migrated.attempts().getAttempt("legacy-attempt")?.state)
        } finally {
            migrated.close()
            context.deleteDatabase(name)
        }
    }
}
