// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedOutcome03TransportTest {
    private fun memory() = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
        SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }

    @Test fun actualPassiveSocketCorrelatesOutcomeRatherThanSubmitStatusOrAnUnrelatedEvent() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, fact) = TypedOutcome03TestFixture.completed(db, f)
            val upload = TypedOutcome03TestFixture.upload(row, fact, f.epoch)
            val entry = db.typedOutcomes03().enter(row, fact, upload, false, f.host::requireCurrent)!!
            f.respond = {
                val unrelated = TypedOutcome03TestFixture.ack(row.command(), upload.assertion(), f.epoch)
                    .put("event_id", TypedHistory03Fixture.id(991))
                f.host.acceptOutcome(unrelated.toString().toByteArray())
                f.host.acceptOutcome(TypedOutcome03TestFixture.ack(row.command(), upload.assertion(), f.epoch,
                    "history_only", null).toString().toByteArray())
            }
            val ack = f.host.report(entry)
            assertTrue(ack.historyOnly); assertNull(ack.resultingState)
            assertTrue(db.typedOutcomes03().retainAck(upload, ack.bytes()))
            assertThrows(IllegalStateException::class.java) { f.host.report(entry) }
            assertEquals(2, f.sends)
            assertEquals(row, db.typedSubmits03().get(row.attemptId))
            assertEquals(1, db.typedHistory03().clocks(row.attemptId).size)
        } }
    }

    @Test fun actorWithdrawalAfterCommitButBeforeSocketEntryKeepsBurnAndSendsNothing() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, fact) = TypedOutcome03TestFixture.completed(db, f)
            val upload = TypedOutcome03TestFixture.upload(row, fact, f.epoch)
            val entry = db.typedOutcomes03().enter(row, fact, upload, false, f.host::requireCurrent)!!
            f.actor.set(false)
            assertThrows(IllegalStateException::class.java) { f.host.report(entry) }
            assertEquals(1, f.sends)
            assertEquals(upload, db.typedOutcomes03().get(upload.requestId))
            assertEquals(fact, db.typedHistory03().source(fact.slot))
        } }
    }

    @Test fun malformedSameEventAckCannotPublishSuccessAndNeverAutomaticallyResends() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, fact) = TypedOutcome03TestFixture.completed(db, f)
            f.respond = {
                f.host.acceptOutcome(TypedOutcome03TestFixture.ack(row.command(),
                    TypedOutcome03Command.decode(TypedSubmit03Record.unbase(fact.assertionB64url!!)), f.epoch)
                    .put("type", "payload_profile_submit_status03").toString().toByteArray())
            }
            assertThrows(Exception::class.java) { TypedOutcome03Uploader.report(db, f.host, fact, false) }
            assertEquals(2, f.sends)
            assertNull(db.typedOutcomes03().uploads(fact.eventId).single().ackB64url)
            assertFalse(TypedOutcome03Uploader.report(db, f.host, fact, false))
            assertEquals(2, f.sends)
        } }
    }

    @Test fun aDifferentRoutingOriginCannotAdoptTheSavedAssertionForPassiveReporting() {
        memory().use { db ->
            lateinit var fact: TypedHistory03Source
            TypedHistory03Fixture().use { f -> fact = TypedOutcome03TestFixture.completed(db, f).second }
            TypedHistory03Fixture(endpoint = "wss://another.example.test/device").use { other ->
                assertThrows(IllegalArgumentException::class.java) { TypedOutcome03Uploader.report(db, other.host, fact, true) }
                assertEquals(0, other.sends)
                assertTrue(db.typedOutcomes03().uploads(fact.eventId).isEmpty())
            }
        }
    }
}
