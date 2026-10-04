// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.database.sqlite.SQLiteDatabase
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationJournalStoresTest {
    private val context get() = RuntimeEnvironment.getApplication()
    private val captureFile get() = context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE)
    private val sendFile get() = context.getDatabasePath(ConversationJournalStores.SEND_FILE)
    private val stores = mutableListOf<ConversationJournalStores>()
    private fun newStores() = ConversationJournalStores(context).also(stores::add)
    private fun <T> worker(action: () -> T): T {
        val executor = Executors.newSingleThreadExecutor()
        return try { executor.submit<T> { action() }.get(15, TimeUnit.SECONDS) }
        finally { executor.shutdownNow() }
    }
    @After fun cleanup() {
        stores.forEach { it.close() }
        context.deleteDatabase(ConversationJournalStores.CAPTURE_FILE)
        context.deleteDatabase(ConversationJournalStores.SEND_FILE)
    }
    private fun failure(reason: ConversationJournalStores.Reason, action: () -> Unit) {
        try { action(); fail("Expected journal refusal") }
        catch (error: ConversationJournalStores.Failure) { assertEquals(reason, error.reason) }
    }

    @Test fun constructionAndUnopenedCloseCreateNoJournals() {
        val stores = newStores()
        assertFalse(captureFile.exists())
        assertFalse(sendFile.exists())
        stores.close(); stores.close()
        failure(ConversationJournalStores.Reason.CLOSED) { stores.openForUserAction() }
        assertFalse(captureFile.exists())
        assertFalse(sendFile.exists())
    }

    @Test fun explicitOpenAndCloseRetainFencesWithoutInstallingOrCapturing() = worker {
        val stores = newStores()
        val handles = stores.openForUserAction()
        assertSame(handles, stores.openForUserAction())
        assertNull(handles.capture.installation())
        assertEquals(0, handles.capture.contentCount())
        assertEquals(0, handles.sends.count())
        assertTrue(handles.capture.reserveReceipt("synthetic-receipt", 1))
        val message = UUID.randomUUID().toString()
        val interval = UUID.randomUUID().toString()
        handles.sends.receive(ConversationSendReceipt(message, interval, "11".repeat(32),
            1000, byteArrayOf(1, 2), ByteArray(12)))
        stores.close(); stores.close()
        failure(ConversationJournalStores.Reason.CLOSED) { handles.requireOpen() }
        failure(ConversationJournalStores.Reason.CLOSED) { handles.capture }
        failure(ConversationJournalStores.Reason.CLOSED) { handles.sends }
        val restored = newStores().openForUserAction()
        assertNotNull(restored.capture.receipt("synthetic-receipt"))
        assertEquals(0, restored.capture.contentCount())
        assertNull(restored.capture.installation())
        assertArrayEquals(byteArrayOf(1, 2), restored.sends.receipt(message)!!.protectedPayload)
    }

    private fun legacyCapture() {
        check(captureFile.parentFile!!.isDirectory || captureFile.parentFile!!.mkdirs())
        SQLiteDatabase.openOrCreateDatabase(captureFile, null).use { db ->
            db.execSQL("CREATE TABLE conversation_installation (slot INTEGER NOT NULL PRIMARY KEY, intervalId TEXT NOT NULL, receiptId TEXT NOT NULL, transcriptDigest TEXT NOT NULL, protectedScope BLOB NOT NULL, nonce BLOB NOT NULL, state TEXT NOT NULL)")
            db.execSQL("CREATE TABLE conversation_receipts (token TEXT NOT NULL PRIMARY KEY, firstObservedAtMs INTEGER NOT NULL, captureId TEXT, intervalId TEXT, protectedCapture BLOB, nonce BLOB)")
            db.execSQL("CREATE TABLE conversation_closed_intervals (intervalId TEXT NOT NULL PRIMARY KEY)")
            db.execSQL("INSERT INTO conversation_receipts(token,firstObservedAtMs) VALUES('synthetic-legacy-receipt',1)")
            db.execSQL("INSERT INTO conversation_closed_intervals(intervalId) VALUES('synthetic-closed-interval')")
            db.version = 1
        }
    }

    @Test fun captureVersionOneMigratesWithoutErasingReceiptOrClosureFences() = worker {
        legacyCapture()
        val handles = newStores().openForUserAction()
        assertNotNull(handles.capture.receipt("synthetic-legacy-receipt"))
        assertEquals(1, handles.capture.isClosed("synthetic-closed-interval"))
        assertNull(handles.capture.wireCapture("synthetic-legacy-receipt"))
        assertEquals(0, handles.capture.contentCount())
        assertEquals(0, handles.sends.count())
    }

    @Test fun productionOpenMigratesVersionTwoPendingBytesWithoutInferringUploadAck() = worker {
        legacyCapture()
        val body=byteArrayOf(1,2,3);val envelope=byteArrayOf(4,5,6);val nonce=ByteArray(12){7}
        SQLiteDatabase.openOrCreateDatabase(captureFile,null).use { db ->
            db.execSQL("CREATE TABLE conversation_wire_captures (sequence INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, token TEXT NOT NULL, captureId TEXT NOT NULL, intervalId TEXT NOT NULL, protectedEnvelope BLOB, nonce BLOB)")
            db.execSQL("CREATE UNIQUE INDEX index_conversation_wire_captures_token ON conversation_wire_captures(token)")
            db.execSQL("UPDATE conversation_receipts SET captureId='synthetic-event',intervalId='synthetic-closed-interval',protectedCapture=?,nonce=?",arrayOf(body,nonce))
            db.execSQL("INSERT INTO conversation_wire_captures VALUES(7,'synthetic-legacy-receipt','synthetic-event','synthetic-closed-interval',?,?)",arrayOf(envelope,nonce))
            db.version=2
        }
        val stores=newStores();val handles=stores.openForUserAction()
        assertArrayEquals(body,handles.capture.receipt("synthetic-legacy-receipt")!!.protectedCapture)
        val pending=handles.capture.wireCapture("synthetic-legacy-receipt")!!
        assertEquals(7L,pending.sequence);assertArrayEquals(envelope,pending.protectedEnvelope)
        assertArrayEquals(nonce,pending.nonce);assertNull(pending.acknowledgedDigest)
        assertEquals(1,handles.capture.contentCount());assertEquals(1,handles.capture.isClosed("synthetic-closed-interval"))
        stores.close()
        val reopened=newStores().openForUserAction()
        assertArrayEquals(envelope,reopened.capture.wireCapture("synthetic-legacy-receipt")!!.protectedEnvelope)
        assertNull(reopened.capture.wireCapture("synthetic-legacy-receipt")!!.acknowledgedDigest)
    }

    @Test fun unsupportedSecondSchemaPublishesNoHandlesAndNeverDestructivelyResetsEitherFile() = worker {
        legacyCapture()
        SQLiteDatabase.openOrCreateDatabase(sendFile, null).use { db ->
            db.execSQL("CREATE TABLE synthetic_fence(token TEXT NOT NULL PRIMARY KEY)")
            db.execSQL("INSERT INTO synthetic_fence VALUES('retained')")
            db.version = 99
        }
        val stores = newStores()
        repeat(2) { failure(ConversationJournalStores.Reason.STORAGE_UNAVAILABLE) { stores.openForUserAction() } }
        SQLiteDatabase.openDatabase(sendFile.path, null, SQLiteDatabase.OPEN_READONLY).use { db ->
            assertEquals(99, db.version)
            db.rawQuery("SELECT token FROM synthetic_fence", null).use { rows ->
                assertTrue(rows.moveToFirst()); assertEquals("retained", rows.getString(0))
            }
        }
        SQLiteDatabase.openDatabase(captureFile.path, null, SQLiteDatabase.OPEN_READONLY).use { db ->
            assertEquals(3, db.version)
            db.rawQuery("SELECT token FROM conversation_receipts", null).use { rows ->
                assertTrue(rows.moveToFirst()); assertEquals("synthetic-legacy-receipt", rows.getString(0))
            }
        }
        stores.close()
        failure(ConversationJournalStores.Reason.CLOSED) { stores.openForUserAction() }
    }
}
