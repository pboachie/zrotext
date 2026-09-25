// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import androidx.room.Room
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class InboundJournalTest {
    private lateinit var db: SmsJournalDatabase
    private lateinit var dao: SmsAttemptDao
    private val attempt = "f00537b4-a965-4ea0-ae13-98e5a157a244"
    private val message = "3dbfbba7-3d0a-48b6-8ca2-c683a8a3f718"
    private val intent = "ab86c772-e80d-40f4-8e6c-84e1c639a207"
    private val senderToken = "a".repeat(64)
    private val dedupeToken = "b".repeat(64)
    private val ciphertext = ByteArray(24) { (it + 5).toByte() }
    private val nonce = ByteArray(12) { it.toByte() }

    @Before fun setUp() {
        db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        dao = db.attempts()
        dao.reserveAlpha(attempt, message, 7, 1, intent, 1000, senderToken)
    }

    @After fun tearDown() = db.close()

    @Test fun exactSenderSimWindowAndPositiveSentEvidenceCaptureOnce() {
        val window = dao.activeInboundWindows(senderToken, 2000).single()
        assertEquals(0, dao.activeInboundWindows("c".repeat(64), 2000).size)
        assertEquals(0, dao.activeInboundWindows(senderToken, 1000 + 24L * 60 * 60 * 1000).size)
        assertNull(dao.recordInbound(window, dedupeToken, 8, 2, 2000, ciphertext, nonce))
        assertNull(dao.recordInbound(window, dedupeToken, 7, 2, window.closesAtMs,
            ciphertext, nonce))
        assertEquals(false, dao.acknowledgeAlphaIntent(intent, false, 1001))
        val preSend = dao.recordInbound(window, dedupeToken, 7, 2, 2000, ciphertext, nonce)!!
        assertEquals(InboundClassification.SEND_UNVERIFIED, preSend.classification)
        assertNull(preSend.encryptedBody)
        assertEquals(preSend.eventId, dao.recordInbound(window, dedupeToken, 7, 2, 2001,
            ciphertext, nonce)?.eventId)
        assertEquals(1, dao.inboundForAttempt(attempt).size)
    }

    @Test fun successfulSentEvidenceAllowsOnlyEncryptedLocalBody() {
        val window = dao.activeInboundWindows(senderToken, 2000).single()
        assertEquals(true, dao.acknowledgeAlphaIntent(intent, true, 1001))
        dao.consumeRadioStart(attempt, message, 7, 1, 1002)
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 1003)
        val event = dao.recordInbound(window, dedupeToken, 7, 2, 2000, ciphertext, nonce)!!
        assertEquals(InboundClassification.CAPTURED_LOCAL, event.classification)
        assertArrayEquals(ciphertext, event.encryptedBody)
        assertArrayEquals(nonce, event.nonce)
        assertEquals(event.eventId, dao.recordInbound(window, dedupeToken, 7, 2, 2001,
            byteArrayOf(99), byteArrayOf(99))?.eventId)
        assertEquals(1, dao.inboundForAttempt(attempt).size)
    }

    @Test fun missingSimAndAmbiguousSendRemainUnverifiedWithoutBody() {
        val window = dao.activeInboundWindows(senderToken, 2000).single()
        dao.acknowledgeAlphaIntent(intent, true, 1001)
        dao.consumeRadioStart(attempt, message, 7, 1, 1002)
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 1003)
        val missingSim = dao.recordInbound(window, dedupeToken, null, 1, 2000,
            ciphertext, nonce)!!
        assertEquals(InboundClassification.SIM_UNVERIFIED, missingSim.classification)
        assertNull(missingSim.encryptedBody)
        dao.recordCallback(attempt, 0, false, 1, null, 1004) // conflicting evidence
        val conflict = dao.recordInbound(window, "c".repeat(64), 7, 1, 2000,
            ciphertext, nonce)!!
        assertEquals(InboundClassification.SEND_UNVERIFIED, conflict.classification)
        assertNull(conflict.encryptedBody)
        assertNotNull(dao.inboundByDedupe(dedupeToken))
    }

    @Test fun encryptionFailurePersistsOnlyUnverifiedMetadata() {
        val window = dao.activeInboundWindows(senderToken, 2000).single()
        dao.acknowledgeAlphaIntent(intent, true, 1001)
        dao.consumeRadioStart(attempt, message, 7, 1, 1002)
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 1003)
        val event = dao.recordInbound(window, dedupeToken, 7, 1, 2000, null, null)!!
        assertEquals(InboundClassification.ENCRYPTION_UNVERIFIED, event.classification)
        assertNull(event.encryptedBody)
        assertNull(event.nonce)
    }

    @Test fun overlappingApprovalCannotAttributeAnIncomingMessage() {
        val first = dao.activeInboundWindows(senderToken, 2000).single()
        dao.reserveAlpha("4ea920ff-e60f-4fdf-8021-54053272ea19",
            "494da67f-c780-48c8-b1b1-51248711c496", 7, 1,
            "5b81e04b-c440-4b1c-8598-2ef9290d8833", 1500, senderToken)
        assertEquals(2, dao.activeInboundWindows(senderToken, 2000).size)
        assertNull(dao.recordInbound(first, dedupeToken, 7, 1, 2000, ciphertext, nonce))
    }

    @Test fun inboundEvidencePersistsWhenDatabaseReopens() {
        val context = RuntimeEnvironment.getApplication()
        val name = "inbound-restart-test.db"
        context.deleteDatabase(name)
        val first = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().addMigrations(SmsJournalDatabase.MIGRATION_1_2,
                SmsJournalDatabase.MIGRATION_2_3, SmsJournalDatabase.MIGRATION_3_4,
                SmsJournalDatabase.MIGRATION_4_5, SmsJournalDatabase.MIGRATION_5_6,
                SmsJournalDatabase.MIGRATION_6_7,
                SmsJournalDatabase.MIGRATION_7_8,
                SmsJournalDatabase.MIGRATION_8_9, SmsJournalDatabase.MIGRATION_9_10).build()
        try {
            val a = first.attempts()
            val id = "e6f78854-8cdc-4788-b56c-350d5902a673"
            val msg = "525b70f9-23d7-46c9-92c3-f3e6b251687d"
            val intentId = "b7a2ba13-97eb-4984-8fcf-c7c5aeea4db5"
            a.reserveAlpha(id, msg, 7, 1, intentId, 1000, senderToken)
            a.acknowledgeAlphaIntent(intentId, true, 1001)
            a.consumeRadioStart(id, msg, 7, 1, 1002)
            a.recordCallback(id, 0, false, Activity.RESULT_OK, null, 1003)
            a.recordInbound(a.activeInboundWindows(senderToken, 2000).single(),
                "d".repeat(64), 7, 1, 2000, ciphertext, nonce)
        } finally { first.close() }
        val reopened = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().addMigrations(SmsJournalDatabase.MIGRATION_1_2,
                SmsJournalDatabase.MIGRATION_2_3, SmsJournalDatabase.MIGRATION_3_4,
                SmsJournalDatabase.MIGRATION_4_5, SmsJournalDatabase.MIGRATION_5_6,
                SmsJournalDatabase.MIGRATION_6_7,
                SmsJournalDatabase.MIGRATION_7_8,
                SmsJournalDatabase.MIGRATION_8_9, SmsJournalDatabase.MIGRATION_9_10).build()
        try {
            val persisted = reopened.attempts().inboundByDedupe("d".repeat(64))!!
            assertEquals(InboundClassification.CAPTURED_LOCAL, persisted.classification)
            assertArrayEquals(ciphertext, persisted.encryptedBody)
            assertArrayEquals(nonce, persisted.nonce)
        } finally {
            reopened.close()
            context.deleteDatabase(name)
        }
    }

    @Test fun strictMultipartNormalizationPreservesContentAndRejectsAmbiguity() {
        val a = InboundNormalizer.Part("+1 (202) 555-0199", "Hello ", 5000)
        val b = InboundNormalizer.Part("+12025550199", "world", 5001)
        assertEquals(InboundNormalizer.Message("+12025550199", "Hello world", 2),
            InboundNormalizer.normalize(listOf(a, b)))
        assertNull(InboundNormalizer.normalize(listOf(a, b.copy(sender = "2025550199"))))
        assertNull(InboundNormalizer.normalize(listOf(a, b.copy(sender = "+12025550198"))))
        assertNull(InboundNormalizer.normalize(listOf(a, b.copy(body = null))))
        assertNull(InboundNormalizer.normalize(listOf(a, b.copy(timestampMs = 5000 + 300_001))))
        assertNull(InboundNormalizer.normalize(List(7) { a }))
        assertNull(InboundNormalizer.e164("+1-800-FLOWERS"))
    }
}
