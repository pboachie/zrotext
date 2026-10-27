// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Actual Room selector + production explicit-page component. Synthetic retained facts and
 * burned unknown report envelopes do not establish service authentication or a radio effect. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedOutcome03PagesTest {
    private fun memory() = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
        SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }
    private fun pending(db: SmsJournalDatabase, f: TypedHistory03Fixture, index: Int): TypedHistory03Source {
        val original = f.command
        val command = TypedSubmit03Command.create(original.accountId, original.deviceId,
            TypedHistory03Fixture.id(2000L + index), TypedHistory03Fixture.id(3000L + index),
            TypedHistory03Fixture.id(4000L + index), original.fetchSha256, original.originalSessionSha256, 1, original.observedMs)
        var row = f.reserve(db, command)
        assertTrue(db.typedSubmits03().retainFirstAck(row, byteArrayOf(1)) {})
        row = db.typedSubmits03().get(row.attemptId)!!
        assertTrue(db.typedSubmits03().retainPlatformEntry(row, command.observedMs + 1) {})
        assertTrue(db.typedSubmits03().recordCallback(row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -7))
        row = db.typedSubmits03().get(row.attemptId)!!
        val source = db.typedHistory03().sources(row.attemptId).single()
        val (clock, _) = f.read(db, row, source.eventId)
        val fact = db.typedHistory03().retainFirstAssertion(source, clock)!!
        assertNotNull(db.typedOutcomes03().enter(row, fact, TypedOutcome03TestFixture.upload(row, fact, f.epoch), true) {})
        return fact
    }
    private fun query(db: SmsJournalDatabase, f: TypedHistory03Fixture, after: String) =
        db.typedOutcomes03().unacknowledged(f.identity.accountId, f.identity.deviceId, f.identity.originHash,
            TypedSubmit03Record.base(f.point), after)
    private fun actions(db: SmsJournalDatabase, f: TypedHistory03Fixture, count: Int): List<List<String>> {
        var after = ""
        return (0 until count).map {
            val page = TypedOutcome03Pages.select(after, f.host::requireCurrent) { cursor -> query(db, f, cursor) }
            page.forEach { after = it }
            if (page.size < 16) after = ""
            page
        }
    }

    @Test fun exactSixteenAndMultiplesNeverProduceFalseEmptyWhileOriginalsRemainUnknown() {
        for (count in listOf(16, 32)) TypedHistory03Fixture().use { f -> memory().use { db ->
            val facts = (0 until count).map { pending(db, f, it) }
            val pages = actions(db, f, 4)
            assertEquals(listOf(16, 16, 16, 16), pages.map { it.size })
            assertEquals(pages[0], pages[if (count == 16) 1 else 2])
            assertTrue(pages.flatten().all { slot -> facts.any { it.slot == slot } })
            for (fact in facts) {
                assertEquals(fact, db.typedHistory03().source(fact.slot))
                assertNull(db.typedOutcomes03().uploads(fact.eventId).single().ackB64url)
            }
            assertEquals(count, f.sends) // Clock reads only; page navigation never uploads.
        } }
    }

    @Test fun partialSuffixPreservesFairNavigationBeforeTheNextExplicitWrap() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            repeat(17) { pending(db, f, it) }
            val pages = actions(db, f, 4)
            assertEquals(listOf(16, 1, 16, 1), pages.map { it.size })
            assertTrue(pages[0].intersect(pages[1].toSet()).isEmpty())
            assertEquals(pages[0], pages[2]); assertEquals(pages[1], pages[3])
        } }
    }

    @Test fun anAcknowledgedOriginalStaysExcludedOnEveryExplicitWrap() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val facts = (0 until 17).map { pending(db, f, it) }
            val acknowledged = facts.first()
            val row = db.typedSubmits03().get(acknowledged.attemptId)!!
            val upload = db.typedOutcomes03().uploads(acknowledged.eventId).single()
            assertTrue(db.typedOutcomes03().retainAck(upload, TypedOutcome03TestFixture.ack(row.command(),
                upload.assertion(), f.epoch, "history_only").toString().toByteArray()))
            val pages = actions(db, f, 3)
            assertEquals(listOf(16, 16, 16), pages.map { it.size })
            assertFalse(acknowledged.slot in pages.flatten())
            assertEquals(acknowledged, db.typedHistory03().source(acknowledged.slot))
        } }
    }

    @Test fun actorWithdrawalDuringEmptySuffixReadPreventsWrapAndAnyReportEntry() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val facts = (0 until 16).map { pending(db, f, it) }
            val after = facts.map { it.slot }.max()
            var queries = 0
            assertThrows(IllegalStateException::class.java) {
                TypedOutcome03Pages.select(after, f.host::requireCurrent) { cursor ->
                    queries++; query(db, f, cursor).also { f.actor.set(false) }
                }
            }
            assertEquals(1, queries); assertEquals(16, f.sends)
            for (fact in facts) assertEquals(1, db.typedOutcomes03().uploads(fact.eventId).size)
        } }
    }
}
