// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Real Room writer/close/reopen checks, synthetic socket and original public facts.
 * No service authentication, nonexportable signer or platform effect is simulated here. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedOutcome03JournalTest {
    private val app get() = RuntimeEnvironment.getApplication()
    private fun memory() = Room.inMemoryDatabaseBuilder(app, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }

    @Test fun firstAssertionAndAutomaticClassificationCommitTogetherBeforeAnyOutcomeIo() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, fact) = TypedOutcome03TestFixture.completed(db, f)
            val report = db.typedOutcomes03().report(fact.eventId)!!
            report.requireSource(fact); assertTrue(report.automaticFirst)
            assertTrue(db.typedOutcomes03().uploads(fact.eventId).isEmpty())
            assertEquals(1, f.sends) // Only the actual passive clock request.
            val candidate = TypedOutcome03TestFixture.upload(row, fact, f.epoch)
            val entry = db.typedOutcomes03().enter(row, fact, candidate, false, f.host::requireCurrent)!!
            assertEquals(candidate, db.typedOutcomes03().get(candidate.requestId))
            assertArrayEquals(candidate.bytes(), entry.consume())
            assertThrows(IllegalStateException::class.java) { entry.consume() }
            assertNull(db.typedOutcomes03().enter(row, fact, TypedOutcome03TestFixture.upload(row, fact, f.epoch),
                false, f.host::requireCurrent))
            assertEquals(fact, db.typedHistory03().source(fact.slot))
        } }
    }

    @Test fun withdrawalDuringWriterRollsBackTheEnvelopeAndCreatesNoSendTicket() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, fact) = TypedOutcome03TestFixture.completed(db, f)
            val candidate = TypedOutcome03TestFixture.upload(row, fact, f.epoch)
            var checks = 0
            assertThrows(IllegalStateException::class.java) {
                db.typedOutcomes03().enter(row, fact, candidate, false) { check(++checks == 1) }
            }
            assertNull(db.typedOutcomes03().get(candidate.requestId))
            assertEquals(fact, db.typedHistory03().source(fact.slot)); assertEquals(1, f.sends)
        } }
    }

    @Test fun originalPacketSubstitutionCannotBurnOrAcknowledgeAnotherFact() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, fact) = TypedOutcome03TestFixture.completed(db, f)
            val candidate = TypedOutcome03TestFixture.upload(row, fact, f.epoch)
            assertThrows(IllegalArgumentException::class.java) {
                db.typedOutcomes03().enter(row, fact, candidate.copy(assertionSha256 = "11".repeat(32)), false) {}
            }
            assertNotNull(db.typedOutcomes03().enter(row, fact, candidate, false) {})
            val bad = TypedOutcome03TestFixture.ack(row.command(), candidate.assertion(), f.epoch)
                .put("submit_event_id", TypedHistory03Fixture.id(990)).toString().toByteArray()
            assertThrows(IllegalArgumentException::class.java) { db.typedOutcomes03().retainAck(candidate, bad) }
            assertNull(db.typedOutcomes03().get(candidate.requestId)!!.ackB64url)
            assertNull(db.attempts().getAttempt(row.attemptId))
        } }
    }

    @Test fun actualReceiptIsHistoricalAndPreventsFurtherAutomaticOrExplicitUploads() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, fact) = TypedOutcome03TestFixture.completed(db, f)
            TypedOutcome03TestFixture.reply(f, row, fact)
            assertTrue(TypedOutcome03Uploader.report(db, f.host, fact, false))
            assertEquals(2, f.sends)
            assertFalse(TypedOutcome03Uploader.report(db, f.host, fact, false))
            assertFalse(TypedOutcome03Uploader.report(db, f.host, fact, true))
            assertEquals(2, f.sends)
            assertNotNull(db.typedOutcomes03().uploads(fact.eventId).single().ackB64url)
            assertEquals(row, db.typedSubmits03().get(row.attemptId))
            assertEquals(-7L, db.typedSubmits03().callbacks(row.attemptId).single().observedMs)
            assertEquals(fact, db.typedHistory03().source(fact.slot))
        } }
    }

    @Test fun coldUnknownBurnSurvivesReopenAndOnlyExplicitSame211MayUseANewEpoch() {
        val name = "tou-${java.util.UUID.randomUUID().toString().take(10)}"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build()
        try {
            lateinit var row: TypedSubmit03Record; lateinit var fact: TypedHistory03Source
            TypedHistory03Fixture().use { f -> open().use { db ->
                val completed = TypedOutcome03TestFixture.completed(db, f); row = completed.first; fact = completed.second
                assertNotNull(db.typedOutcomes03().enter(row, fact, TypedOutcome03TestFixture.upload(row, fact, f.epoch), false) {})
            } }
            TypedHistory03Fixture(epoch = 13).use { later -> open().use { db ->
                assertFalse(TypedOutcome03Uploader.report(db, later.host, fact, false))
                assertEquals(0, later.sends)
                TypedOutcome03TestFixture.reply(later, row, fact)
                assertTrue(TypedOutcome03Uploader.report(db, later.host, fact, true))
                val all = db.typedOutcomes03().uploads(fact.eventId)
                assertEquals(setOf(12L, 13L), all.map { it.connectionEpoch }.toSet())
                assertTrue(all.all { it.assertionB64url == fact.assertionB64url && it.assertionSha256 == fact.assertionSha256 })
                assertEquals(1, later.sends)
                assertEquals(fact, db.typedHistory03().source(fact.slot))
            } }
        } finally { app.deleteDatabase(name) }
    }

    @Test fun genuineVersion24CompletedHistoryDoesNotAcquireAutomaticFirstIoOnUpgrade() {
        val name = "tom-${java.util.UUID.randomUUID().toString().take(10)}"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
            .addMigrations(SmsJournalDatabase.MIGRATION_24_25).build()
        try {
            TypedHistory03Fixture().use { f ->
                lateinit var row: TypedSubmit03Record; lateinit var fact: TypedHistory03Source
                open().use { db ->
                    val first = f.entered(db)
                    assertTrue(db.typedSubmits03().recordCallback(first.attemptId, 0, false,
                        android.app.Activity.RESULT_OK, null, -7))
                    row = db.typedSubmits03().get(first.attemptId)!!
                    val source = db.typedHistory03().sources(row.attemptId).single()
                    val (sample, request) = f.read(db, row, source.eventId)
                    val assertion = TypedOutcome03Command.create(row.command(), source.eventId, source.evidence,
                        source.segmentIndex, sample.nowFor(row, request))
                    fact = source.copy(assertionB64url = TypedSubmit03Record.base(assertion.bytes()),
                        assertionSha256 = TypedSubmit03Record.hex(assertion.commitment()), assertionClockRequestId = request.requestId)
                    fact.requireShape()
                    // Model the real prior schema: its completed211 existed, new report
                    // classification did not. Preserve the original typed/source/raw rows.
                    db.openHelper.writableDatabase.apply {
                        execSQL("UPDATE typed_history03_sources SET assertionB64url=?,assertionSha256=?,assertionClockRequestId=? WHERE slot=?",
                            arrayOf<Any>(fact.assertionB64url!!, fact.assertionSha256!!, fact.assertionClockRequestId!!, fact.slot))
                        LegacyTypedJournalFixture.removeEmptyOutcomeTables(this)
                        execSQL("DROP TABLE room_master_table"); version = 24
                    }
                }
                open().use { db ->
                    assertEquals(25, db.openHelper.readableDatabase.version)
                    assertEquals(row, db.typedSubmits03().get(row.attemptId))
                    assertEquals(fact, db.typedHistory03().source(fact.slot))
                    assertNull(db.typedOutcomes03().report(fact.eventId))
                    assertFalse(TypedOutcome03Uploader.report(db, f.host, fact, false))
                    assertEquals(1, f.sends)
                    TypedOutcome03TestFixture.reply(f, row, fact)
                    assertTrue(TypedOutcome03Uploader.report(db, f.host, fact, true))
                    assertFalse(db.typedOutcomes03().report(fact.eventId)!!.automaticFirst)
                    assertEquals(2, f.sends)
                }
            }
        } finally { app.deleteDatabase(name) }
    }
}
