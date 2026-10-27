// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Actual entry/sample brands over synthetic transport; no server/device authentication or
 * current effect permission is established by the fixture's controlled actor callback. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedHistory03ConnectionsTest {
    private fun memory() = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(),
        SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }
    private fun source(db: SmsJournalDatabase, f: TypedHistory03Fixture): Pair<TypedSubmit03Record, TypedHistory03Source> {
        val row = f.entered(db)
        check(db.typedSubmits03().recordCallback(row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -1))
        return checkNotNull(db.typedSubmits03().get(row.attemptId)) to db.typedHistory03().sources(row.attemptId).single()
    }

    @Test fun aCommittedNewEntryCanSendOnlyOnceAndColdRowsCannotMintItAgain() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, source) = source(db, f)
            val (original, entry) = f.pending(db, row, source.eventId)
            val sample = f.host.request(row, entry)
            assertEquals(1, f.sends)
            assertThrows(IllegalStateException::class.java) { f.host.request(row, entry) }
            assertNull(db.typedHistory03().enterClock(original, f.host::requireCurrent))
            val entered = db.typedHistory03().clock(original.requestId)!!
            assertTrue(entered.entered); assertNull(entered.replyB64url)
            assertTrue(db.typedHistory03().retainClockReply(entered, sample.bytes()))
            assertEquals(1, f.sends)
        } }
    }

    @Test fun actualRoundTripAndMonotonicRegressionRefuseWithoutCreatingACommand() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, source) = source(db, f)
            f.roundTrip = 2001
            val (_, tooSlow) = f.pending(db, row, source.eventId)
            assertThrows(IllegalArgumentException::class.java) { f.host.request(row, tooSlow) }
            assertNull(db.typedHistory03().source(source.slot)!!.assertionB64url)
            f.roundTrip = 10
            val (sample, request) = f.read(db, row, source.eventId)
            assertTrue(sample.nowFor(row, request) > f.primary)
            f.elapsed.incrementAndGet(); sample.nowFor(row, request)
            f.elapsed.decrementAndGet()
            assertThrows(IllegalArgumentException::class.java) { sample.nowFor(row, request) }
            assertNull(db.typedHistory03().source(source.slot)!!.assertionB64url)
        } }
    }

    @Test fun aDifferentConfiguredOriginCannotAdoptTheOriginalAttemptOrRequestAClock() {
        memory().use { db ->
            val row = TypedHistory03Fixture().use { first -> source(db, first).first }
            TypedHistory03Fixture(endpoint = "wss://different.example.test/device").use { other ->
                assertThrows(IllegalArgumentException::class.java) { other.host.requireOriginal(row) }
                assertThrows(IllegalArgumentException::class.java) { db.typedSubmits03().reserve(other.row()) {} }
                assertEquals(0, other.sends)
                assertTrue(db.typedHistory03().clocks(row.attemptId).isEmpty())
                assertEquals(row, db.typedSubmits03().get(row.attemptId))
            }
        }
    }

    @Test fun lateOldNonceHistoryCannotSatisfyTheNewActualActorRead() {
        memory().use { db ->
            var old: ByteArray? = null
            var retained: TypedSubmit03Record? = null
            var retainedSource: TypedHistory03Source? = null
            TypedHistory03Fixture().use { first ->
                val original = source(db, first); retained = original.first; retainedSource = original.second
                old = first.read(db, original.first, original.second.eventId).first.bytes()
            }
            TypedHistory03Fixture(epoch = 13).use { next ->
                next.primary++
                next.respond = { request ->
                    next.host.accept(old!!)
                    next.host.accept(next.frame(request).toString().toByteArray())
                }
                val (sample, request) = next.read(db, retained!!, retainedSource!!.eventId)
                assertTrue(sample.nowFor(retained!!, request) >= next.primary)
                assertEquals(2, db.typedHistory03().clocks(retained!!.attemptId).size)
                assertNull(db.typedHistory03().source(retainedSource!!.slot)!!.assertionB64url)
            }
        }
    }

    @Test fun primaryFloorsAreDistinctFromPriorRttUpperAndFailedReadsCannotLowerThem() {
        TypedHistory03Fixture().use { f -> memory().use { db ->
            val (row, source) = source(db, f)
            f.roundTrip = 1900
            val (first, firstRequest) = f.read(db, row, source.eventId)
            val firstUpper = first.nowFor(row, firstRequest)
            f.roundTrip = 0; f.primary++
            val (second, secondRequest) = f.read(db, row, source.eventId)
            assertTrue(second.nowFor(row, secondRequest) < firstUpper)
            assertThrows(IllegalStateException::class.java) { first.nowFor(row, firstRequest) }
            f.primary--
            val (_, rollback) = f.pending(db, row, source.eventId)
            assertThrows(IllegalArgumentException::class.java) { f.host.request(row, rollback) }
            assertTrue(second.nowFor(row, secondRequest) >= f.primary + 1)
            assertNull(db.typedHistory03().source(source.slot)!!.assertionB64url)
        } }
    }

    @Test fun constructorAndHistoricalReplyCannotForgeAnActualPublishedSample() {
        TypedHistory03Fixture(version = 1).use { f -> memory().use { db ->
            val (row, source) = source(db, f)
            val (real, request) = f.read(db, row, source.eventId)
            val reply = TypedHistory03Wire.decode(real.bytes(), request.query(), row.accountId, row.deviceId,
                f.epoch, f.version, f.point)
            val forged = TypedHistory03Clock.Sample(f.host, request.copy(replyB64url = null), reply,
                f.elapsed.get(), 0, real.bytes())
            assertThrows(IllegalStateException::class.java) { forged.nowFor(row, request) }
            assertTrue(real.nowFor(row, request) >= f.primary)
            f.actor.set(false)
            assertThrows(IllegalStateException::class.java) { real.nowFor(row, request) }
        } }
    }
}
