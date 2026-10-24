// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import androidx.room.Room
import java.util.UUID
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Real Room and actual nonce/clock component paths, over a synthetic socket. Metadata ACKs
 * are not a submit permission or a radio capability. No platform sender is present. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedHistory03JournalTest {
    private val app get() = RuntimeEnvironment.getApplication()
    private fun memory() = Room.inMemoryDatabaseBuilder(app, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }
    private fun record(db: SmsJournalDatabase, row: TypedSubmit03Record, index: Int = 0,
        delivery: Boolean = false, result: Int = Activity.RESULT_OK, status: Int? = null, wall: Long = 1): TypedSubmit03Record {
        assertTrue(db.typedSubmits03().recordCallback(row.attemptId, index, delivery, result, status, wall))
        return db.typedSubmits03().get(row.attemptId)!!
    }

    @Test fun rawBackwardZeroAndFutureWallTimesKeepTheirActualSameWriterOrder() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            var row = f.entered(db)
            row = record(db, row, wall = Long.MAX_VALUE)
            row = record(db, row, result = 1, wall = -1)
            row = record(db, row, delivery = true, status = DeliveryStatus.UNVERIFIED, wall = 0)
            val raw = db.typedSubmits03().callbacks(row.attemptId).sortedBy { it.arrivalOrdinal }
            assertEquals(listOf(Long.MAX_VALUE, -1L, 0L), raw.map { it.observedMs })
            assertEquals(listOf(1L, 2L, 3L), raw.map { it.arrivalOrdinal })
            assertEquals(3L, row.lastCallbackOrdinal)
            assertEquals(setOf(0, 1, 5), db.typedHistory03().sources(row.attemptId).map { it.evidence }.toSet())
            val conflict = db.typedHistory03().sources(row.attemptId).single { it.evidence == 5 }
            assertFalse(conflict.eventId in raw.map { it.eventId })
            conflict.requireRaw(row.command(), raw)
            assertTrue(db.typedHistory03().clocks(row.attemptId).isEmpty())
        } }
    }

    @Test fun firstAuthenticatedAssertionKeepsTheRawIdentityWithoutRetimestampingTheFact() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val row = record(db, f.entered(db), wall = -5)
            val source = db.typedHistory03().sources(row.attemptId).single()
            val raw = db.typedSubmits03().callbacks(row.attemptId).single()
            val (sample, request) = f.read(db, row, source.eventId)
            val completed = db.typedHistory03().retainFirstAssertion(source, sample)!!
            val command = TypedOutcome03Command.decode(TypedSubmit03Record.unbase(completed.assertionB64url!!))
            assertEquals(raw.eventId, command.eventId)
            assertEquals(3_000_110L, command.assertionMs)
            assertEquals(-5L, db.typedSubmits03().callbacks(row.attemptId).single().observedMs)
            assertNull(db.typedHistory03().retainFirstAssertion(source, sample))
            assertEquals(request.requestId, completed.assertionClockRequestId)
            assertEquals(completed, db.typedHistory03().source(source.slot))
        } }
    }

    @Test fun completeDeliveryGetsItsOwnDerivedIdentityWithoutInventingSentFacts() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val six = TypedSubmit03Command.decode(TypedHistory03Fixture.bytes(
                f.fixture.getJSONArray("cases").getJSONObject(1).getString("submit")))
            var row = f.reserve(db, six)
            assertTrue(db.typedSubmits03().retainFirstAck(row, byteArrayOf(1)) {})
            row = db.typedSubmits03().get(row.attemptId)!!
            assertTrue(db.typedSubmits03().retainPlatformEntry(row, six.observedMs + 1) {})
            row = db.typedSubmits03().get(row.attemptId)!!
            for (index in 0..4) row = record(db, row, index, true, status = DeliveryStatus.RECEIVED, wall = 100L - index)
            assertTrue(db.typedHistory03().sources(row.attemptId).isEmpty())
            row = record(db, row, 5, true, status = DeliveryStatus.RECEIVED, wall = -10)
            val source = db.typedHistory03().sources(row.attemptId).single()
            val raw = db.typedSubmits03().callbacks(row.attemptId)
            assertTrue(raw.all { it.delivery })
            assertEquals(2, source.evidence); assertEquals(-1, source.segmentIndex)
            assertEquals(6, source.rawEventIds.split(',').size)
            assertFalse(source.eventId in raw.map { it.eventId })
            source.requireRaw(six, raw)
            record(db, row, 5, true, status = DeliveryStatus.RECEIVED, wall = Long.MAX_VALUE)
            assertEquals(source, db.typedHistory03().source(source.slot))
        } }
    }

    @Test fun missingOldSourceHistoryCannotBeRecreatedByAnotherCompatibleCallback() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            var row = record(db, f.entered(db), result = 1)
            val source = db.typedHistory03().sources(row.attemptId).single()
            db.openHelper.writableDatabase.execSQL("DELETE FROM typed_history03_sources WHERE slot = ?", arrayOf(source.slot))
            row = record(db, row, result = 2)
            assertNull(db.typedHistory03().source(source.slot))
            assertEquals(2, db.typedSubmits03().callbacks(row.attemptId).size)
            assertTrue(db.typedHistory03().clocks(row.attemptId).isEmpty())
            assertTrue(db.protectionOrigins().hasPriorLocalActivity())
        } }
    }

    @Test fun barrierPermanentlyBlocksEntryBeforeThereIsAnyClockOrFinalClosure() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val original = f.reserve(db)
            val barrier = db.typedSubmits03().beginClosing(original, TypedHistory03Fixture.id(800))!!
            assertEquals("pre_entry_closing", barrier.phase)
            assertNull(barrier.closureB64url)
            assertFalse(db.typedSubmits03().retainFirstAck(original, byteArrayOf(1)) {})
            assertFalse(db.typedSubmits03().retainPlatformEntry(barrier, original.command().observedMs + 1) {})
            assertEquals(0, f.sends)
            assertEquals(barrier, db.typedSubmits03().reserve(f.row()) {})
        } }
    }

    @Test fun barrierAndEntryCompeteInTheSameWriterAndOnlyOneCanWin() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val original = f.reserve(db)
            assertTrue(db.typedSubmits03().retainFirstAck(original, byteArrayOf(1)) {})
            val row = db.typedSubmits03().get(original.attemptId)!!
            val gate = CyclicBarrier(2)
            val pool = Executors.newFixedThreadPool(2)
            try {
                val entry = pool.submit<Boolean> { gate.await(5, TimeUnit.SECONDS)
                    db.typedSubmits03().retainPlatformEntry(row, row.command().observedMs + 1) {} }
                val close = pool.submit<Boolean> { gate.await(5, TimeUnit.SECONDS)
                    db.typedSubmits03().beginClosing(row, TypedHistory03Fixture.id(801)) != null }
                val entered = entry.get(10, TimeUnit.SECONDS); val closed = close.get(10, TimeUnit.SECONDS)
                assertTrue(entered.xor(closed))
                val current = db.typedSubmits03().get(row.attemptId)!!
                assertEquals(if (entered) "platform_entry_reserved" else "pre_entry_closing", current.phase)
            } finally { pool.shutdownNow() }
        } }
    }

    @Test fun anActualClockCanFinalizeOnlyTheOriginalZeroCallbackBarrier() {
        TypedHistory03Fixture(version = 1).use { f -> memory().use { db ->
            val original = f.reserve(db)
            val barrier = db.typedSubmits03().beginClosing(original, TypedHistory03Fixture.id(802))!!
            f.beforeReply = { assertFalse(db.inTransaction()) }
            val (sample, request) = f.read(db, barrier, barrier.closingId!!, "closure")
            val closed = db.typedSubmits03().finishClosing(barrier, request, sample)!!
            val exact = TypedNoSubmit03Record.decode(TypedSubmit03Record.unbase(closed.closureB64url!!))
            assertEquals("closed_no_submit", closed.phase)
            assertEquals(barrier.closingId, exact.closureId)
            assertEquals(0, exact.closedFrom); assertEquals(3_000_110L, exact.closedMs)
            assertFalse(db.typedSubmits03().retainPlatformEntry(closed, exact.closedMs + 1) {})
            assertNull(db.typedSubmits03().finishClosing(barrier, request, sample))
            assertEquals(closed, db.typedSubmits03().reserve(f.row()) {})
        } }
    }

    @Test fun callbackDuringClockWaitKeepsTheBarrierUnknownAndNeverReleasesEntry() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val original = f.reserve(db)
            val barrier = db.typedSubmits03().beginClosing(original, TypedHistory03Fixture.id(803))!!
            f.beforeReply = { record(db, barrier, wall = -100) }
            val (sample, request) = f.read(db, barrier, barrier.closingId!!, "closure")
            assertNull(db.typedSubmits03().finishClosing(barrier, request, sample))
            val current = db.typedSubmits03().get(original.attemptId)!!
            assertEquals("pre_entry_closing", current.phase); assertTrue(current.conflict)
            assertNull(current.closureB64url)
            assertFalse(db.typedSubmits03().retainPlatformEntry(current, f.primary + 1) {})
        } }
    }

    @Test fun expiryAtThePostWriterGuardRollsBackTheFirstAssertionWithoutChangingTheFact() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val row = record(db, f.entered(db), wall = Long.MAX_VALUE)
            val source = db.typedHistory03().sources(row.attemptId).single()
            val (sample, _) = f.read(db, row, source.eventId)
            var calls = 0
            f.elapsedRead = { if (calls++ == 0) f.elapsed.get() else f.elapsed.get() + 30_000 }
            assertThrows(IllegalArgumentException::class.java) { db.typedHistory03().retainFirstAssertion(source, sample) }
            assertEquals(source, db.typedHistory03().source(source.slot))
            assertNull(db.typedOutcomes03().report(source.eventId))
            assertEquals(Long.MAX_VALUE, db.typedSubmits03().callbacks(row.attemptId).single().observedMs)
        } }
    }

    @Test fun returnedClockHistoryMaySurviveActorWithdrawalButCannotCreateAnAssertion() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val row = record(db, f.entered(db))
            val source = db.typedHistory03().sources(row.attemptId).single()
            val (original, entry) = f.pending(db, row, source.eventId)
            val entered = db.typedHistory03().clock(original.requestId)!!
            val sample = f.host.request(row, entry)
            f.actor.set(false)
            assertTrue(db.typedHistory03().retainClockReply(entered, sample.bytes()))
            assertThrows(IllegalStateException::class.java) { db.typedHistory03().retainFirstAssertion(source, sample) }
            assertEquals(source, db.typedHistory03().source(source.slot))
            assertNotNull(db.typedHistory03().clock(original.requestId)!!.replyB64url)
        } }
    }

    @Test fun aGenuineClockBeforeTheOriginalSubmitCannotBeClampedIntoAClosureOrAssertion() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val original = f.reserve(db)
            val barrier = db.typedSubmits03().beginClosing(original, TypedHistory03Fixture.id(804))!!
            f.primary = original.command().observedMs - f.roundTrip - 1
            val (sample, request) = f.read(db, barrier, barrier.closingId!!, "closure")
            assertEquals(original.command().observedMs - 1, sample.nowFor(barrier, request))
            assertThrows(IllegalArgumentException::class.java) { db.typedSubmits03().finishClosing(barrier, request, sample) }
            assertEquals(barrier, db.typedSubmits03().get(original.attemptId))
            assertFalse(db.typedSubmits03().retainPlatformEntry(barrier, original.command().observedMs + 1) {})
        } }
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val row = record(db, f.entered(db))
            val source = db.typedHistory03().sources(row.attemptId).single()
            f.primary = row.command().observedMs - f.roundTrip - 1
            val (sample, _) = f.read(db, row, source.eventId)
            assertThrows(IllegalArgumentException::class.java) { db.typedHistory03().retainFirstAssertion(source, sample) }
            assertEquals(source, db.typedHistory03().source(source.slot))
            assertEquals(1, db.typedSubmits03().callbacks(row.attemptId).size)
        } }
    }

    @Test fun additiveMigrationRetainsOldOriginAndOrderAsUnknownInsteadOfAdoptingTheReportingHost() {
        val name = "thm23-${UUID.randomUUID().toString().take(10)}"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
            .addMigrations(SmsJournalDatabase.MIGRATION_22_23, SmsJournalDatabase.MIGRATION_23_24, SmsJournalDatabase.MIGRATION_24_25).build()
        try {
            TypedHistory03Fixture().use { f ->
                val old = TypedSubmit03Record.candidate(f.command, f.point)
                val rawId = TypedHistory03Fixture.id(805)
                val observed = f.command.observedMs + 1
                open().use { db ->
                    db.openHelper.writableDatabase.apply {
                        LegacyTypedJournalFixture.removeEmptyFutureTables(this)
                        SmsJournalDatabase.MIGRATION_21_22.migrate(this)
                        execSQL("INSERT INTO typed_submit03 (attemptId,eventId,accountId,deviceId,messageId,commandB64url,commandSha256,originalEnrolledPoint,originalEnrolledKeyId,phase,conflict) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                            arrayOf<Any>(old.attemptId, old.eventId, old.accountId, old.deviceId, old.messageId, old.commandB64url,
                                old.commandSha256, old.originalEnrolledPoint, old.originalEnrolledKeyId, old.phase, 0))
                        execSQL("INSERT INTO typed_callback03 (eventId,attemptId,segmentIndex,delivery,resultCode,deliveryStatus,observedMs) VALUES (?,?,?,?,?,?,?)",
                            arrayOf<Any>(rawId, old.attemptId, 0, 0, Activity.RESULT_OK, -1, observed))
                        execSQL("DROP TABLE room_master_table"); version = 22
                    }
                }
                open().use { db ->
                    assertEquals(25, db.openHelper.readableDatabase.version)
                    val retained = db.typedSubmits03().get(old.attemptId)!!
                    assertEquals(old, retained)
                    val raw = db.typedSubmits03().callbacks(old.attemptId).single()
                    assertEquals(rawId, raw.eventId); assertEquals(observed, raw.observedMs)
                    assertNull(raw.arrivalOrdinal); assertNull(retained.originalOriginSha256)
                    assertNull(retained.lastCallbackOrdinal)
                    assertTrue(db.typedHistory03().sources(old.attemptId).isEmpty())
                    assertTrue(db.typedHistory03().clocks(old.attemptId).isEmpty())
                    assertThrows(IllegalArgumentException::class.java) { f.host.requireOriginal(retained) }
                    assertEquals(0, f.sends)
                }
            }
        } finally { app.deleteDatabase(name) }
    }

    @Test fun coldEnteredClockAndBarrierStayBurnedWithoutRecreatingTheirTransportTicket() {
        val name = "thc23-${UUID.randomUUID().toString().take(10)}"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build()
        try {
            var saved: TypedSubmit03Record? = null
            var pending: TypedHistory03Request? = null
            TypedHistory03Fixture().use { f -> open().use { db ->
                val barrier = db.typedSubmits03().beginClosing(f.reserve(db), TypedHistory03Fixture.id(806))!!
                saved = barrier
                pending = f.pending(db, barrier, barrier.closingId!!, "closure").first
                assertEquals(0, f.sends)
            } }
            TypedHistory03Fixture(epoch = 13).use { f -> open().use { db ->
                val barrier = saved!!
                assertEquals(barrier, db.typedSubmits03().get(barrier.attemptId))
                assertNull(db.typedHistory03().enterClock(pending!!, f.host::requireCurrent))
                assertTrue(db.typedHistory03().clock(pending!!.requestId)!!.entered)
                assertFalse(db.typedSubmits03().retainFirstAck(barrier, byteArrayOf(1)) {})
                assertFalse(db.typedSubmits03().retainPlatformEntry(barrier, f.primary) {})
                assertEquals(0, f.sends)
                assertNull(db.typedSubmits03().get(barrier.attemptId)!!.closureB64url)
            } }
        } finally { app.deleteDatabase(name) }
    }

    @Test fun completedColdCommandRemainsExactAndCannotAcquireAnotherClockForThatSource() {
        val name = "th23-${UUID.randomUUID().toString().take(12)}"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build()
        try {
            var saved: TypedHistory03Source? = null
            TypedHistory03Fixture().use { f -> open().use { db ->
                val row = record(db, f.entered(db), wall = -1)
                val source = db.typedHistory03().sources(row.attemptId).single()
                val (sample, _) = f.read(db, row, source.eventId)
                saved = db.typedHistory03().retainFirstAssertion(source, sample)
            } }
            TypedHistory03Fixture(epoch = 13).use { f -> open().use { db ->
                val original = saved!!
                assertEquals(original, db.typedHistory03().source(original.slot))
                assertEquals(1, db.typedHistory03().clocks(original.attemptId).size)
                assertTrue(db.typedHistory03().pendingAttempts(f.identity.accountId, f.identity.deviceId,
                    f.identity.originHash, TypedSubmit03Record.base(f.point), "").isEmpty())
                assertEquals(0, f.sends)
            } }
        } finally { app.deleteDatabase(name) }
    }
}
