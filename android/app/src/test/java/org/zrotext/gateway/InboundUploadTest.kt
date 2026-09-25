// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import android.content.Context
import androidx.room.Room
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.security.MessageDigest
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class InboundUploadTest {
    private lateinit var db: SmsJournalDatabase
    private lateinit var dao: SmsAttemptDao
    private val attempt = "55555555-5555-4555-8555-555555555555"
    private val message = "44444444-4444-4444-8444-444444444444"
    private val senderToken = "a".repeat(64)

    @Before fun setUp() {
        db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
            SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        dao = db.attempts()
        dao.reserveAlpha(attempt, message, 7, 1,
            "77777777-7777-4777-8777-777777777777", 1000, senderToken)
    }

    @After fun tearDown() = db.close()

    private fun capture(token: String): InboundEvent {
        dao.acknowledgeAlphaIntent("77777777-7777-4777-8777-777777777777", true, 1001)
        dao.consumeRadioStart(attempt, message, 7, 1, 1002)
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 1003)
        return dao.recordInbound(dao.activeInboundWindows(senderToken, 2000).single(),
            token, 7, 2, 2000, ByteArray(24) { 0x5a }, ByteArray(12) { 0x33 })!!
    }

    @Test fun onlyCapturedRowsEnterDurableOutboxAndAckClearsOne() {
        val unverified = dao.recordInbound(dao.activeInboundWindows(senderToken, 2000).single(),
            "b".repeat(64), null, 1, 2000, null, null)!!
        assertEquals(InboundClassification.SIM_UNVERIFIED, unverified.classification)
        assertNull(dao.nextInboundUpload(0))
        val first = capture("c".repeat(64))
        val pending = dao.nextInboundUpload(0)!!
        assertEquals(first.eventId, pending.eventId)
        assertEquals(1L, pending.sequence)
        assertEquals(first.eventId, capture("c".repeat(64)).eventId)
        assertEquals(1L, dao.nextInboundUpload(0)!!.sequence)
        val signature = ByteArray(70) { it.toByte() }
        assertEquals(1, dao.signInboundUpload(first.eventId,
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222", signature))
        assertEquals(0, dao.signInboundUpload(first.eventId, "other", "other", signature))
        assertArrayEquals(signature, dao.inboundUpload(first.eventId)!!.signatureDer)
        assertEquals(1, dao.acknowledgeInboundUpload(first.eventId, 2500))
        assertEquals(0, dao.acknowledgeInboundUpload(first.eventId, 2501))
        assertNull(dao.nextInboundUpload(0))
        val second = capture("d".repeat(64))
        assertEquals(second.eventId, dao.nextInboundUpload(0)!!.eventId)
        assertEquals(2L, dao.nextInboundUpload(0)!!.sequence)
        assertNull(dao.nextInboundUpload(2001))
    }

    @Test fun stopAndReviewRepliesUseSignedMetadataAndLocalBlockSurvivesReplay() {
        dao.acknowledgeAlphaIntent("77777777-7777-4777-8777-777777777777", true, 1001)
        dao.consumeRadioStart(attempt, message, 7, 1, 1002)
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 1003)
        val window = dao.activeInboundWindows(senderToken, 2000).single()
        dao.suppressRecipient(LocalRecipientSuppression(senderToken, 2000))
        val stop = dao.recordInbound(window, "s".repeat(64), 7, 1, 2000,
            null, null, OptOutParser.OPT_OUT)!!
        assertEquals(InboundClassification.OPT_OUT, stop.classification)
        assertNull(stop.encryptedBody)
        assertEquals(stop.eventId, dao.nextInboundUpload(0)!!.eventId)
        dao.suppressRecipient(LocalRecipientSuppression(senderToken, 2100))
        dao.suppressRecipient(LocalRecipientSuppression(senderToken, 1900))
        assertTrue(dao.isRecipientSuppressed(senderToken))
        val start = dao.recordInbound(window, "t".repeat(64), 7, 1, 2200,
            null, null, OptOutParser.OPT_IN)!!
        assertEquals(InboundClassification.OPT_IN, start.classification)
        assertEquals(1, dao.signInboundUpload(start.eventId, testEvidenceIdentity.accountId,
            testEvidenceIdentity.deviceId, testEvidenceIdentity.originHash, ByteArray(70)))
        assertEquals(1, dao.acknowledgeInboundAck(start.eventId, 2300, true))
        // A server START acknowledgement cannot prove the local STOP's line/generation.
        assertTrue(dao.isRecipientSuppressed(senderToken))
    }

    @Test fun exactResumeAndReasonableFreeTextAreClassifiedConservatively() {
        for (word in listOf("STOP", "STOPALL", "UNSUBSCRIBE", "CANCEL", "END", "QUIT",
                "REVOKE", "OPTOUT"))
            assertEquals(OptOutParser.OPT_OUT, OptOutParser.classify("  ${word.lowercase()}  "))
        assertEquals(OptOutParser.OPT_IN, OptOutParser.classify("  sTaRt  "))
        assertEquals(OptOutParser.OPT_IN, OptOutParser.classify("UnStOp"))
        assertNull(OptOutParser.classify("Please START sending marketing messages"))
        assertEquals(OptOutParser.OPT_OUT_REVIEW,
            OptOutParser.classify("Please do not text me again"))
        assertEquals(OptOutParser.OPT_OUT_REVIEW,
            OptOutParser.classify("Remove me from your list"))
    }

    @Test fun signatureBytesMatchIndependentServerVectorAndFrameHasNoContent() {
        val event = InboundEvent("33333333-3333-4333-8333-333333333333", attempt, message,
            "f".repeat(64), 7, 1700000000000L, 2,
            InboundClassification.CAPTURED_LOCAL,
            ByteArray(24) { 0x5a }, ByteArray(12) { 0x33 })
        val upload = InboundUpload(7, event.eventId,
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222", ByteArray(70) { it.toByte() })
        val bytes = InboundUploadFrame.signedBytes(UUID.fromString(checkNotNull(upload.accountId)),
            UUID.fromString(checkNotNull(upload.deviceId)), upload, event)
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }
        assertEquals("a5c16315ba6fdd194c57fcf9104f05ec7da26830c5cf784a962c4363b87dd199", digest)
        val wire = InboundUploadFrame.encode(3, upload, event)
        val json = JSONObject(wire)
        assertEquals(setOf("v", "type", "connection_epoch", "event_id", "sequence",
            "message_id", "attempt_id", "classification", "observed_at_ms",
            "part_count", "signature_der"), json.keys().asSequence().toSet())
        assertFalse(wire.contains("encryptedBody") || wire.contains("ciphertext") ||
            wire.contains("sender") || wire.contains("nonce") || wire.contains("body"))
        assertTrue(wire.toByteArray(Charsets.UTF_8).size < 4096)
    }

    @Test fun versionFourMigrationBackfillsOnlyCapturedEvents() {
        val context: Context = RuntimeEnvironment.getApplication()
        val name = "inbound-upload-migration.db"
        context.deleteDatabase(name)
        val old = context.openOrCreateDatabase(name, Context.MODE_PRIVATE, null)
        old.execSQL("CREATE TABLE sms_attempts (attemptId TEXT NOT NULL PRIMARY KEY, subscriptionId INTEGER NOT NULL, segmentCount INTEGER NOT NULL, state TEXT NOT NULL, createdAtMs INTEGER NOT NULL, updatedAtMs INTEGER NOT NULL, evidenceConflict INTEGER NOT NULL DEFAULT 0, messageId TEXT DEFAULT NULL)")
        old.execSQL("CREATE TABLE sms_segments (attemptId TEXT NOT NULL, segmentIndex INTEGER NOT NULL, sentResultCode INTEGER, deliveryResultCode INTEGER, deliveryStatus INTEGER, PRIMARY KEY(attemptId,segmentIndex), FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)")
        old.execSQL("CREATE INDEX index_sms_segments_attemptId ON sms_segments(attemptId)")
        old.execSQL("CREATE TABLE alpha_radio_events (eventId TEXT NOT NULL PRIMARY KEY, messageId TEXT NOT NULL, attemptId TEXT NOT NULL, evidence TEXT NOT NULL, observedAtMs INTEGER NOT NULL, segmentIndex INTEGER, segmentCount INTEGER, acknowledgedAtMs INTEGER, FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)")
        old.execSQL("CREATE INDEX index_alpha_radio_events_attemptId ON alpha_radio_events(attemptId)")
        old.execSQL("CREATE INDEX index_alpha_radio_events_acknowledgedAtMs_observedAtMs ON alpha_radio_events(acknowledgedAtMs,observedAtMs)")
        old.execSQL("CREATE TABLE inbound_windows (attemptId TEXT NOT NULL PRIMARY KEY, messageId TEXT NOT NULL, senderToken TEXT NOT NULL, subscriptionId INTEGER NOT NULL, opensAtMs INTEGER NOT NULL, closesAtMs INTEGER NOT NULL, FOREIGN KEY(attemptId) REFERENCES sms_attempts(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)")
        old.execSQL("CREATE INDEX index_inbound_windows_senderToken ON inbound_windows(senderToken)")
        old.execSQL("CREATE TABLE inbound_events (eventId TEXT NOT NULL PRIMARY KEY, attemptId TEXT NOT NULL, messageId TEXT NOT NULL, dedupeToken TEXT NOT NULL, observedSubscriptionId INTEGER, receivedAtMs INTEGER NOT NULL, partCount INTEGER NOT NULL, classification TEXT NOT NULL, encryptedBody BLOB, nonce BLOB, FOREIGN KEY(attemptId) REFERENCES inbound_windows(attemptId) ON UPDATE NO ACTION ON DELETE CASCADE)")
        old.execSQL("CREATE INDEX index_inbound_events_attemptId ON inbound_events(attemptId)")
        old.execSQL("CREATE UNIQUE INDEX index_inbound_events_dedupeToken ON inbound_events(dedupeToken)")
        old.execSQL("INSERT INTO sms_attempts(attemptId,subscriptionId,segmentCount,state,createdAtMs,updatedAtMs,messageId) VALUES (?,?,?,?,?,?,?)",
            arrayOf<Any>(attempt, 7, 1, "submitted", 1000, 1000, message))
        val oldRadioId = "77777777-7777-4777-8777-777777777777"
        old.execSQL("INSERT INTO alpha_radio_events(eventId,messageId,attemptId,evidence,observedAtMs) VALUES (?,?,?,?,?)",
            arrayOf<Any>(oldRadioId, message, attempt, "sent_callback_ok", 1003))
        old.execSQL("INSERT INTO inbound_windows VALUES (?,?,?,?,?,?)",
            arrayOf<Any>(attempt, message, senderToken, 7, 1000, 5000))
        old.execSQL("INSERT INTO inbound_events(eventId,attemptId,messageId,dedupeToken,receivedAtMs,partCount,classification) VALUES (?,?,?,?,?,?,?)",
            arrayOf<Any>("33333333-3333-4333-8333-333333333333", attempt, message,
                "f".repeat(64), 2000, 1, InboundClassification.SIM_UNVERIFIED))
        old.execSQL("INSERT INTO inbound_events(eventId,attemptId,messageId,dedupeToken,receivedAtMs,partCount,classification,encryptedBody,nonce) VALUES (?,?,?,?,?,?,?,?,?)",
            arrayOf("66666666-6666-4666-8666-666666666666", attempt, message,
                "e".repeat(64), 2000, 1, InboundClassification.CAPTURED_LOCAL,
                ByteArray(24), ByteArray(12)))
        old.version = 4
        old.close()
        val migrated = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().addMigrations(SmsJournalDatabase.MIGRATION_4_5,
                SmsJournalDatabase.MIGRATION_5_6, SmsJournalDatabase.MIGRATION_6_7,
                SmsJournalDatabase.MIGRATION_7_8,
                SmsJournalDatabase.MIGRATION_8_9).build()
        try {
            val legacyEvent = migrated.attempts().inboundByDedupe("e".repeat(64))!!
            val legacyUpload = migrated.attempts().inboundUpload(legacyEvent.eventId)!!
            assertEquals(1L, legacyUpload.sequence)
            assertNull(legacyUpload.originHash)
            assertNull(migrated.attempts().nextInboundUpload(0))
            assertEquals(1, migrated.attempts().quarantineForeignInbound(
                testEvidenceIdentity.accountId, testEvidenceIdentity.deviceId,
                testEvidenceIdentity.originHash, 3000))
            assertEquals("identity_changed",
                migrated.attempts().inboundUpload(legacyEvent.eventId)?.quarantineReason)
            assertNull(migrated.attempts().getAlphaEvent(oldRadioId)?.accountId)
            assertEquals(1, migrated.attempts().quarantineForeignAlpha(
                testEvidenceIdentity.accountId, testEvidenceIdentity.deviceId,
                testEvidenceIdentity.originHash, 3000))
            assertEquals("identity_changed",
                migrated.attempts().getAlphaEvent(oldRadioId)?.quarantineReason)
            assertNull(migrated.attempts().inboundUpload(migrated.attempts()
                .inboundByDedupe("f".repeat(64))!!.eventId))
            assertEquals(9, migrated.openHelper.readableDatabase.version)
        } finally {
            migrated.close()
            context.deleteDatabase(name)
        }
    }

    @Test fun signedUploadReplaysWithSameIdentityAndSignatureAfterReopen() {
        val context: Context = RuntimeEnvironment.getApplication()
        val name = "inbound-upload-replay.db"
        context.deleteDatabase(name)
        val first = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        val signature = ByteArray(70) { (it + 1).toByte() }
        val eventId: String
        try {
            val local = first.attempts()
            local.reserveAlpha(attempt, message, 7, 1,
                "77777777-7777-4777-8777-777777777777", 1000, senderToken)
            local.acknowledgeAlphaIntent("77777777-7777-4777-8777-777777777777", true, 1001)
            local.consumeRadioStart(attempt, message, 7, 1, 1002)
            local.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 1003)
            eventId = local.recordInbound(local.activeInboundWindows(senderToken, 2000).single(),
                "e".repeat(64), 7, 1, 2000, ByteArray(24), ByteArray(12))!!.eventId
            assertEquals(1, local.signInboundUpload(eventId,
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222", signature))
        } finally { first.close() }
        val reopened = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        try {
            val upload = reopened.attempts().nextInboundUpload(0)!!
            assertEquals(eventId, upload.eventId)
            assertEquals(1L, upload.sequence)
            assertArrayEquals(signature, upload.signatureDer)
            assertEquals("11111111-1111-4111-8111-111111111111", upload.accountId)
            assertEquals("22222222-2222-4222-8222-222222222222", upload.deviceId)
            assertEquals(1, reopened.attempts().acknowledgeInboundUpload(eventId, 3000))
            assertNull(reopened.attempts().nextInboundUpload(0))
        } finally {
            reopened.close()
            context.deleteDatabase(name)
        }
    }

    @Test fun signedOldDeviceUploadCannotStopNewDevicePilot() {
        val old = capture("c".repeat(64))
        val signature = ByteArray(70) { it.toByte() }
        assertEquals(1, dao.signInboundUpload(old.eventId,
            testEvidenceIdentity.accountId, testEvidenceIdentity.deviceId,
            testEvidenceIdentity.originHash, signature))
        val next = EvidenceIdentity("33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444", "b".repeat(64))
        assertNull(dao.nextInboundUpload(0, next.accountId, next.deviceId, next.originHash))
        assertEquals(1, dao.quarantineForeignInbound(next.accountId, next.deviceId,
            next.originHash, 2500))
        assertArrayEquals(signature, dao.inboundUpload(old.eventId)?.signatureDer)
        assertEquals("identity_changed", dao.inboundUpload(old.eventId)?.quarantineReason)

        val newAttempt = "badb7c43-86b4-4d5f-9d6c-2d027344979a"
        val newMessage = "d22d7f5e-4377-434c-a01d-f9726e026b5e"
        val newIntent = "aa1e933b-8ec5-4431-94ad-b68fd16f4760"
        val newSender = "b".repeat(64)
        dao.reserveAlpha(newAttempt, newMessage, 7, 1, newIntent, 1000, newSender, next)
        assertTrue(dao.acknowledgeAlphaIntent(newIntent, true, 1001))
        assertEquals(1, dao.consumeRadioStart(newAttempt, newMessage, 7, 1, 1002))
        dao.recordCallback(newAttempt, 0, false, Activity.RESULT_OK, null, 1003)
        val event = dao.recordInbound(dao.activeInboundWindows(newSender, 2000).single(),
            "d".repeat(64), 7, 1, 2000, ByteArray(24), ByteArray(12))!!
        assertEquals(event.eventId,
            dao.nextInboundUpload(0, next.accountId, next.deviceId, next.originHash)?.eventId)
        assertEquals(0, dao.signInboundUpload(event.eventId,
            testEvidenceIdentity.accountId, testEvidenceIdentity.deviceId,
            next.originHash, signature))
    }
}
