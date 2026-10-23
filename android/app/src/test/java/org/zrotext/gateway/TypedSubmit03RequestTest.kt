// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Actual Room burns and rollback. These public command tickets confer no current,
 * native recipient, authenticated ACK or platform permission. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedSubmit03RequestTest {
    private fun memory() = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
        .allowMainThreadQueries().build()
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }
    private fun candidate(f: TypedSubmit03WireTest.Fixture) = TypedSubmit03Record.candidateWithOrigin(f.command,
        Profile03ExecutionFixture.point(f.f.enrollment), f.f.origins.routingHash)
    private fun request(f: TypedSubmit03WireTest.Fixture, row: TypedSubmit03Record) = TypedSubmit03Request(row.attemptId,
        row.eventId, row.commandSha256, f.f.session.connectionEpoch,
        TypedSubmit03Record.base(TypedSubmit03Wire.request(f.command, f.f.grant, f.f.session)))

    @Test fun onlyANewClassificationMayBurnOneExactTransportEntryAndNoReplayRemintsIt() {
        TypedSubmit03WireTest.Fixture().use { f -> memory().use { db ->
            val dao = db.typedSubmits03(); val row = candidate(f); val request = request(f, row)
            assertTrue(dao.reserveNewSubmit(row) {})
            assertFalse(dao.reserveNewSubmit(row) {})
            val ticket = checkNotNull(dao.enterSubmit(row, request) {})
            assertEquals(request, dao.submitRequest(row.attemptId))
            assertNull(dao.enterSubmit(row, request) {})
            assertArrayEquals(request.bytes(), ticket.consume())
            assertThrows(IllegalStateException::class.java) { ticket.consume() }
            assertEquals("reserved", dao.get(row.attemptId)!!.phase)
            assertTrue(db.attempts().getAlphaEvent(row.eventId) == null)
            assertNull(db.attempts().getAttempt(row.attemptId))
        } }
    }

    @Test fun withdrawalAfterTheInsertRollsBackTheBurnAndCannotReturnATransportTicket() {
        TypedSubmit03WireTest.Fixture().use { f -> memory().use { db ->
            val dao = db.typedSubmits03(); val row = candidate(f)
            var calls = 0
            assertThrows(IllegalStateException::class.java) {
                dao.reserveNewSubmit(row) { calls++; check(calls != 2) }
            }
            assertNull(dao.get(row.attemptId))
            assertTrue(dao.reserveNewSubmit(row) {})
            calls = 0
            assertThrows(IllegalStateException::class.java) {
                dao.enterSubmit(row, request(f, row)) { calls++; check(calls != 2) }
            }
            assertNull(dao.submitRequest(row.attemptId))
            assertEquals(row, dao.get(row.attemptId))
        } }
    }

    @Test fun aClosedOrConflictingOriginalCannotEnterTransportOrBeReplacedByANewCommand() {
        TypedSubmit03WireTest.Fixture().use { f -> memory().use { db ->
            val dao = db.typedSubmits03(); val row = candidate(f)
            assertTrue(dao.reserveNewSubmit(row) {})
            val closing = checkNotNull(dao.beginClosing(row, java.util.UUID.randomUUID().toString()))
            assertEquals("pre_entry_closing", closing.phase)
            assertNull(dao.enterSubmit(row, request(f, row)) {})
            assertFalse(dao.reserveNewSubmit(row) {})
            assertNull(dao.submitRequest(row.attemptId))
            assertEquals(closing, dao.get(row.attemptId))
        } }
    }

    @Test fun reboundRequestOrMissingOriginalOriginRefusesBeforeAnyEntryRecord() {
        TypedSubmit03WireTest.Fixture().use { f -> memory().use { db ->
            val dao = db.typedSubmits03(); val row = candidate(f)
            val old = row.copy(originalOriginSha256 = null, lastCallbackOrdinal = null)
            assertThrows(IllegalArgumentException::class.java) { dao.reserveNewSubmit(old) {} }
            assertTrue(dao.reserveNewSubmit(row) {})
            val request = request(f, row)
            for (changed in listOf(request.copy(eventId = java.util.UUID.randomUUID().toString()),
                request.copy(commandSha256 = "a".repeat(64)), request.copy(connectionEpoch = request.connectionEpoch + 1)))
                assertThrows(IllegalArgumentException::class.java) { dao.enterSubmit(row, changed) {} }
            assertNull(dao.submitRequest(row.attemptId))
            assertEquals(row, dao.get(row.attemptId))
        } }
    }

    @Test fun committedEntrySurvivesActualCloseAndReopenWithoutAnotherTransportTicket() {
        val app = RuntimeEnvironment.getApplication<android.app.Application>()
        val name = "tsr-${java.util.UUID.randomUUID().toString().take(10)}"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build()
        try {
            TypedSubmit03WireTest.Fixture().use { f ->
                val row = candidate(f); val request = request(f, row)
                open().use { db ->
                    assertTrue(db.typedSubmits03().reserveNewSubmit(row) {})
                    assertNotNull(db.typedSubmits03().enterSubmit(row, request) {})
                } // Lost returned result: the permanent original entry is still authoritative.
                open().use { db ->
                    val dao = db.typedSubmits03()
                    assertEquals(row, dao.get(row.attemptId))
                    assertEquals(request, dao.submitRequest(row.attemptId))
                    assertNull(dao.enterSubmit(row, request) {})
                    assertFalse(dao.reserveNewSubmit(row) {})
                    assertNull(db.attempts().getAttempt(row.attemptId))
                }
            }
        } finally { app.deleteDatabase(name) }
    }

    @Test fun additiveMigrationPreservesOriginalRowsWithoutInventingAnySubmitEntry() {
        val app = RuntimeEnvironment.getApplication<android.app.Application>()
        val name = "tsm-${java.util.UUID.randomUUID().toString().take(10)}"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
            .addMigrations(SmsJournalDatabase.MIGRATION_23_24).build()
        try {
            TypedSubmit03WireTest.Fixture().use { f ->
                val row = candidate(f)
                open().use { db ->
                    assertTrue(db.typedSubmits03().reserveNewSubmit(row) {})
                    db.openHelper.writableDatabase.apply {
                        execSQL("DROP TABLE typed_submit03_requests")
                        execSQL("DROP TABLE room_master_table")
                        version = 23
                    }
                }
                open().use { db ->
                    assertEquals(24, db.openHelper.readableDatabase.version)
                    assertEquals(row, db.typedSubmits03().get(row.attemptId))
                    assertNull(db.typedSubmits03().submitRequest(row.attemptId))
                    assertFalse(db.typedSubmits03().reserveNewSubmit(row) {})
                    assertNull(db.attempts().getAttempt(row.attemptId))
                }
            }
        } finally { app.deleteDatabase(name) }
    }
}
