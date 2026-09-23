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
import org.junit.Assert.assertNotNull
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
        val initial = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().build()
        try {
            val local = initial.attempts()
            local.reserveAlpha(attempt, message, 7, 1,
                "77777777-7777-4777-8777-777777777777", 1000, senderToken)
            local.recordInbound(local.activeInboundWindows(senderToken, 2000).single(),
                "f".repeat(64), null, 1, 2000, null, null)
            local.acknowledgeAlphaIntent("77777777-7777-4777-8777-777777777777", true, 1001)
            local.consumeRadioStart(attempt, message, 7, 1, 1002)
            local.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 1003)
            local.recordInbound(local.activeInboundWindows(senderToken, 2000).single(),
                "e".repeat(64), 7, 1, 2000, ByteArray(24), ByteArray(12))
        } finally { initial.close() }
        val old = context.openOrCreateDatabase(name, Context.MODE_PRIVATE, null)
        old.execSQL("DROP TABLE inbound_uploads")
        old.version = 4
        old.close()
        val migrated = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
            .allowMainThreadQueries().addMigrations(SmsJournalDatabase.MIGRATION_4_5).build()
        try {
            assertNotNull(migrated.attempts().nextInboundUpload(0))
            assertEquals(1L, migrated.attempts().nextInboundUpload(0)!!.sequence)
            assertNull(migrated.attempts().inboundUpload(migrated.attempts()
                .inboundByDedupe("f".repeat(64))!!.eventId))
            assertEquals(5, migrated.openHelper.readableDatabase.version)
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
}
