// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import androidx.room.Room
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Real Room/component phase tests; synthetic ACK bytes are deliberately NOT a permission
 * projection. There is no SmsManager/current verifier/positive radio factory in this slice. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedSubmit03JournalTest {
    private val app get() = RuntimeEnvironment.getApplication()
    private val fixture = javaClass.classLoader!!.getResourceAsStream("conversation-effects03-v1.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private fun bytes(value: String) = Base64.getUrlDecoder().decode(value)
    private fun hex(value: ByteArray) = TypedSubmit03Record.hex(value)
    private fun id(number: Long) = UUID(0, number).toString()
    private fun command(index: Int = 0) = TypedSubmit03Command.decode(bytes(fixture.getJSONArray("cases").getJSONObject(index).getString("submit")))
    private fun candidate(index: Int = 0) = TypedSubmit03Record.candidate(command(index), bytes(fixture.getString("enrolled_point")))
    private fun memory() = Room.inMemoryDatabaseBuilder(app, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }
    private fun reserve(db: SmsJournalDatabase) = db.typedSubmits03().reserve(candidate()) {}
    private fun ack(db: SmsJournalDatabase, row: TypedSubmit03Record): TypedSubmit03Record {
        assertTrue(db.typedSubmits03().retainFirstAck(row, byteArrayOf(1, 2, 3)) {})
        return db.typedSubmits03().get(row.attemptId)!!
    }
    private fun legacy(db: SmsJournalDatabase, row: TypedSubmit03Record, now: Long = 10) {
        // Defensive corrupt/foreign-writer fixture, never a production migration/backfill.
        val command = row.command()
        db.attempts().insertAttempt(SmsAttempt(command.attemptId, 3, command.segmentCount, AttemptState.SUBMITTING,
            now, now, messageId = command.messageId, accountId = command.accountId,
            deviceId = command.deviceId, originHash = "synthetic-origin"))
        db.attempts().insertSegments((0 until command.segmentCount).map { SmsSegment(command.attemptId, it) })
        db.attempts().insertAlphaEvent(AlphaRadioEvent(id(900), command.messageId, command.attemptId,
            "durable_submit_intent", now, accountId = command.accountId, deviceId = command.deviceId, originHash = "synthetic-origin"))
    }

    @Test fun exactSharedCommandAndNegativeRecordCommitmentsRetainOwnedBytes() {
        for (index in 0..1) {
            val source = fixture.getJSONArray("cases").getJSONObject(index)
            val raw = bytes(source.getString("submit")); val command = TypedSubmit03Command.decode(raw)
            val original = command.bytes(); raw.fill(0)
            assertArrayEquals(original, command.bytes())
            assertArrayEquals(bytes(source.getString("submit_commitment")), command.commitment())
            val closure = TypedNoSubmit03Record.decode(bytes(source.getString("closure_record")))
            closure.requireCommand(command)
            assertArrayEquals(bytes(source.getString("closure_commitment")), closure.commitment())
            assertArrayEquals(closure.bytes(), TypedNoSubmit03Record.create(command, closure.closureId,
                closure.closedFrom, closure.closedMs).bytes())
        }
    }

    @Test fun malformedOrReboundPublicBytesNeverBecomeTheOriginalCommand() {
        val original = command()
        for (size in listOf(0, 152, 154)) assertThrows(IllegalArgumentException::class.java) { TypedSubmit03Command.decode(ByteArray(size)) }
        for (at in listOf(0, 16, 32, 48, 64, 80, 112)) {
            val raw = original.bytes(); raw.fill(0, at, at + if (at < 80) 16 else 32)
            assertThrows(IllegalArgumentException::class.java) { TypedSubmit03Command.decode(raw) }
        }
        for (count in listOf(0, 7, 255)) assertThrows(IllegalArgumentException::class.java) {
            TypedSubmit03Command.decode(original.bytes().also { it[144] = count.toByte() }) }
        val other = TypedSubmit03Command.create(original.accountId, original.deviceId, id(800), original.messageId,
            original.attemptId, original.fetchSha256, original.originalSessionSha256, original.segmentCount, original.observedMs)
        val closure = TypedNoSubmit03Record.create(original, id(801), 0, original.observedMs + 1)
        assertThrows(IllegalArgumentException::class.java) { closure.requireCommand(other) }
    }

    @Test fun negativeClosureCannotPredateTheExactOriginalSubmitObservation() {
        val command = command()
        val original = TypedNoSubmit03Record.create(command, id(813), 0, command.observedMs)
        assertEquals(command.observedMs, original.closedMs)
        val malformed = original.bytes().also { java.nio.ByteBuffer.wrap(it, 202, 8).putLong(command.observedMs - 1) }
        assertThrows(IllegalArgumentException::class.java) { TypedNoSubmit03Record.decode(malformed) }
        assertThrows(IllegalArgumentException::class.java) { TypedNoSubmit03Record.create(command, id(813), 0, command.observedMs - 1) }
    }

    @Test fun invalidClosureTimeLeavesTheRealRoomOriginalUnchanged(): Unit = memory().use { db ->
        val row = ack(db, reserve(db)); val dao = db.typedSubmits03()
        assertThrows(IllegalArgumentException::class.java) { dao.closeBeforeEntry(row, id(814), row.command().observedMs - 1) }
        assertEquals(row, dao.get(row.attemptId)); assertNull(dao.get(row.attemptId)!!.closureB64url)
        assertTrue(dao.callbacks(row.attemptId).isEmpty())
        val closed = dao.closeBeforeEntry(row, id(814), row.command().observedMs)!!
        assertEquals("closed_no_submit", closed.phase)
        assertEquals(row.command().observedMs, TypedNoSubmit03Record.decode(bytes(closed.closureB64url!!)).closedMs)
        assertFalse(dao.retainPlatformEntry(closed, row.command().observedMs + 1) {})
    }

    @Test fun classificationCommitsBeforeTransportAndCannotAdoptLegacyAttempt(): Unit = memory().use { db ->
        val row = reserve(db); assertEquals("reserved", row.phase)
        assertTrue(db.typedSubmits03().callbacks(row.attemptId).isEmpty()); assertNull(row.ackSha256)
        assertNull(db.attempts().getAttempt(row.attemptId)); assertTrue(db.attempts().controlledTestEvents(row.attemptId).isEmpty())
        assertThrows(IllegalStateException::class.java) { db.attempts().reserve(row.attemptId, 3, 1, 10) }
        val other = candidate(1); legacy(db, other)
        assertThrows(IllegalStateException::class.java) { db.typedSubmits03().reserve(other) {} }
    }

    @Test fun withdrawnWriterTransactionLeavesNoClassificationOrAcknowledgement(): Unit = memory().use { db ->
        var checks = 0
        assertThrows(IllegalStateException::class.java) { db.typedSubmits03().reserve(candidate()) { check(++checks < 2) } }
        assertNull(db.typedSubmits03().get(candidate().attemptId))
        val row = reserve(db); checks = 0
        assertThrows(IllegalStateException::class.java) { db.typedSubmits03().retainFirstAck(row, byteArrayOf(1)) { check(++checks < 2) } }
        assertEquals(row, db.typedSubmits03().get(row.attemptId))
    }

    @Test fun anotherAttemptCannotReplaceTheSameMessageAfterPermanentClosure(): Unit = memory().use { db ->
        val row = reserve(db); val command = row.command()
        db.typedSubmits03().closeBeforeEntry(row, id(810), command.observedMs + 1)
        val replacement = TypedSubmit03Command.create(command.accountId, command.deviceId, id(811), command.messageId,
            id(812), command.fetchSha256, command.originalSessionSha256, command.segmentCount, command.observedMs)
        assertThrows(android.database.sqlite.SQLiteConstraintException::class.java) {
            db.typedSubmits03().reserve(TypedSubmit03Record.candidate(replacement, bytes(fixture.getString("enrolled_point")))) {} }
        assertEquals("closed_no_submit", db.typedSubmits03().get(row.attemptId)!!.phase)
        assertNull(db.typedSubmits03().get(replacement.attemptId))
    }

    @Test fun duplicateAcknowledgementOrStatusMetadataCannotRearmEntry(): Unit = memory().use { db ->
        val first = reserve(db); val acknowledged = ack(db, first)
        assertFalse(db.typedSubmits03().retainFirstAck(first, byteArrayOf(1, 2, 3)) {})
        assertTrue(db.typedSubmits03().retainPlatformEntry(acknowledged, first.command().observedMs + 2) {})
        assertFalse(db.typedSubmits03().retainPlatformEntry(acknowledged, first.command().observedMs + 3) {})
        val retained = db.typedSubmits03().get(first.attemptId)!!
        assertEquals(retained, db.typedSubmits03().reserve(candidate()) {})
        assertNull(db.typedSubmits03().closeBeforeEntry(retained, id(802), first.command().observedMs + 4))
    }

    @Test fun actualSameWriterEntryAndNegativeClosureHaveOnlyOneWinner(): Unit = memory().use { db ->
        val row = ack(db, reserve(db)); val pool = Executors.newFixedThreadPool(2); val start = CyclicBarrier(2)
        try {
            val entry = pool.submit<Boolean> { start.await(5, TimeUnit.SECONDS)
                db.typedSubmits03().retainPlatformEntry(row, row.command().observedMs + 1) {} }
            val closure = pool.submit<TypedSubmit03Record?> { start.await(5, TimeUnit.SECONDS)
                db.typedSubmits03().closeBeforeEntry(row, id(803), row.command().observedMs + 2) }
            val entered = entry.get(10, TimeUnit.SECONDS); val closed = closure.get(10, TimeUnit.SECONDS)
            assertTrue(entered xor (closed != null))
            val final = db.typedSubmits03().get(row.attemptId)!!
            assertEquals(if (entered) "platform_entry_reserved" else "closed_no_submit", final.phase)
            assertFalse(db.typedSubmits03().retainFirstAck(final, byteArrayOf(1)) {})
        } finally { pool.shutdownNow() }
    }

    @Test fun callbackBeforeEntryOrAfterClosureIsPermanentContraryEvidence(): Unit = memory().use { db ->
        val row = reserve(db); val closed = db.typedSubmits03().closeBeforeEntry(row, id(804), row.command().observedMs + 1)!!
        val dao = db.typedSubmits03()
        assertTrue(dao.recordCallback(row.attemptId, 0, false, Activity.RESULT_OK, null, row.command().observedMs + 2))
        val retained = dao.get(row.attemptId)!!
        assertEquals(closed.phase, retained.phase); assertEquals(closed.closureSha256, retained.closureSha256); assertTrue(retained.conflict)
        assertTrue(db.attempts().controlledTestEvents(row.attemptId).isEmpty())
        assertFalse(dao.retainPlatformEntry(retained, row.command().observedMs + 3) {})
    }

    @Test fun immutableCallbackFactsAllowUnverifiedDeliveryToResolveWithoutInventingSuccess(): Unit = memory().use { db ->
        val row = ack(db, reserve(db)); val dao = db.typedSubmits03()
        assertTrue(dao.retainPlatformEntry(row, row.command().observedMs + 1) {})
        val now = row.command().observedMs + 2
        assertTrue(dao.recordCallback(row.attemptId, 0, true, Activity.RESULT_OK, DeliveryStatus.UNVERIFIED, now))
        assertTrue(dao.recordCallback(row.attemptId, 0, true, Activity.RESULT_OK, DeliveryStatus.RECEIVED, now + 1))
        assertFalse(dao.get(row.attemptId)!!.conflict); assertEquals(2, dao.callbacks(row.attemptId).size)
        assertTrue(dao.recordCallback(row.attemptId, 0, true, Activity.RESULT_OK, DeliveryStatus.RECEIVED, now + 2))
        assertEquals(2, dao.callbacks(row.attemptId).size)
        assertTrue(dao.recordCallback(row.attemptId, 0, true, Activity.RESULT_OK, DeliveryStatus.FAILED, now + 3))
        assertTrue(dao.get(row.attemptId)!!.conflict); assertEquals(3, dao.callbacks(row.attemptId).size)
        assertNull(dao.get(row.attemptId)!!.closureB64url)
    }

    @Test fun everyLegacyDriverTimerPumpAndPruneLeavesClassifiedHistoryAlone(): Unit = memory().use { db ->
        val row = reserve(db); val command = row.command(); legacy(db, row)
        val dao = db.attempts(); val initial = dao.getAttempt(row.attemptId)!!
        assertNull(dao.nextAlphaEvent(command.accountId, command.deviceId, "synthetic-origin"))
        assertNull(dao.latestControlledTest(command.deviceId, "synthetic-origin"))
        assertFalse(dao.acknowledgeAlphaIntent(id(900), true, 20)); assertEquals(0, dao.acknowledgeAlphaEvent(id(900), 20))
        assertEquals(0, dao.consumeRadioStart(row.attemptId, command.messageId, 3, command.segmentCount, 20))
        assertEquals(0, dao.recordSent(row.attemptId, 0, Activity.RESULT_OK))
        assertEquals(0, dao.recordDelivery(row.attemptId, 0, Activity.RESULT_OK, DeliveryStatus.RECEIVED))
        dao.recordCallback(row.attemptId, 0, false, Activity.RESULT_OK, null, 20)
        dao.setState(row.attemptId, AttemptState.FAILED, 20); dao.markInterrupted(20); dao.markUnsentReservations(20)
        dao.markStalledSubmission(row.attemptId, 20); dao.markTimedOutDeliveries(19, 20); dao.retireOrphanedAlphaIntents(20)
        assertEquals(0, dao.markCallbackConflict(row.attemptId, 20))
        dao.pruneAcknowledgedEvidence(1_000_000, 10)
        assertEquals(initial, dao.getAttempt(row.attemptId)); assertEquals(row, db.typedSubmits03().get(row.attemptId))
        assertNull(dao.getAlphaEvent(id(900))!!.acknowledgedAtMs)
    }

    @Test fun coldCallbackClassificationSurvivesRestartAndNeverBecomesLegacyEvidence() {
        val name = "ts-${UUID.randomUUID().toString().take(8)}.db"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build()
        try {
            open().use { db -> val row = reserve(db); db.typedSubmits03().closeBeforeEntry(row, id(805), row.command().observedMs + 1) }
            open().use { db -> val dao = db.typedSubmits03(); val row = dao.get(command().attemptId)!!
                SmsCallbackJournal.record(db, row.attemptId, 0, false, Activity.RESULT_OK, null, row.command().observedMs + 2)
                assertTrue(dao.get(row.attemptId)!!.conflict); assertEquals("closed_no_submit", dao.get(row.attemptId)!!.phase)
                assertNull(db.attempts().getAttempt(row.attemptId)); assertTrue(db.attempts().controlledTestEvents(row.attemptId).isEmpty()) }
        } finally { app.deleteDatabase(name) }
    }

    @Test fun terminalLegacyPruningCannotDeleteTheTypedOriginalOrItsSeparateFacts(): Unit = memory().use { db ->
        val row = reserve(db); legacy(db, row)
        db.openHelper.writableDatabase.apply {
            execSQL("UPDATE sms_attempts SET state = 'failed' WHERE attemptId = ?", arrayOf(row.attemptId))
            execSQL("UPDATE alpha_radio_events SET acknowledgedAtMs = 11 WHERE attemptId = ?", arrayOf(row.attemptId))
        }
        SmsCallbackJournal.record(db, row.attemptId, 0, false, Activity.RESULT_OK, null, row.command().observedMs + 1)
        db.attempts().pruneAcknowledgedEvidence(1_000_000, 10)
        assertNotNull(db.attempts().getAttempt(row.attemptId))
        assertEquals("reserved", db.typedSubmits03().get(row.attemptId)!!.phase)
        assertTrue(db.typedSubmits03().get(row.attemptId)!!.conflict)
        assertEquals(1, db.typedSubmits03().callbacks(row.attemptId).size)
    }

    @Test fun additiveMigrationPreservesOldUnknownAndCreatesNoTypedAttemptOrAck() {
        val name = "tm-${UUID.randomUUID().toString().take(8)}.db"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
            .addMigrations(SmsJournalDatabase.MIGRATION_21_22).build()
        val original = SmsAttempt(id(806), 3, 1, AttemptState.UNKNOWN, 10, 10)
        try {
            open().use { db ->
                db.attempts().insertAttempt(original)
                db.openHelper.writableDatabase.apply {
                    execSQL("DROP TABLE typed_callback03"); execSQL("DROP TABLE typed_submit03")
                    execSQL("DROP TABLE room_master_table"); version = 21
                }
            }
            open().use { db ->
                assertEquals(22, db.openHelper.readableDatabase.version)
                assertEquals(original, db.attempts().getAttempt(original.attemptId))
                assertNull(db.typedSubmits03().get(original.attemptId))
                assertTrue(db.typedSubmits03().callbacks(original.attemptId).isEmpty())
                assertFalse(db.typedSubmits03().recordCallback(original.attemptId, 0, false, Activity.RESULT_OK, null, 20))
            }
        } finally { app.deleteDatabase(name) }
    }
}
