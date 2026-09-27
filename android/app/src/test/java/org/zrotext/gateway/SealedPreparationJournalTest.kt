// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SealedPreparationJournalTest {
    private val context: Context get() = RuntimeEnvironment.getApplication()
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }
    private fun memory() = Room.inMemoryDatabaseBuilder(context, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private fun file(name: String) = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name)
        .allowMainThreadQueries().addMigrations(SmsJournalDatabase.MIGRATION_11_12).build()
    private fun record(f: PreparationFixture) = f.grant().let {
        SealedPreparationRecord(it.accountId, it.messageId, it.attemptId, it.unsignedDigest, it.identity())
    }

    @Test fun syntheticSoftwareCompositionPreparesMetadataAndNeverCreatesAlphaEffectState() {
        val f = PreparationFixture()
        memory().use { db ->
            assertTrue(db.attempts().installVerifiedLineBinding(f.binding(), listOf(ActiveSimCard(3, 7))))
            val dao = db.sealedPreparations()
            val r = record(f)
            dao.reserve(r) { assertEquals(f.binding(), it) }
            val proof = f.proof()
            val clear = Draft02Body.open(proof, f.softwareCek(proof))
            try {
                assertEquals("Candidate sealed text ✓", String(clear))
                dao.finish(r, 1) { assertEquals(f.binding(), it) }
            } finally { clear.fill('\u0000') }
            assertEquals("prepared", dao.find(r.accountId, r.messageId)?.state)
            assertEquals(1, dao.find(r.accountId, r.messageId)?.segmentCount)
            assertNull(db.attempts().getAttempt(r.attemptId))
            assertEquals(0, db.openHelper.readableDatabase.query("SELECT COUNT(*) FROM alpha_radio_events").use { it.moveToFirst(); it.getInt(0) })
            assertFalse(db.attempts().acknowledgeAlphaIntent(r.attemptId, true, f.now))
            assertEquals(0, db.attempts().consumeRadioStart(r.attemptId, r.messageId, 3, 1, f.now))
            assertThrows(Exception::class.java) { dao.reserve(r) {} }
            assertThrows(Exception::class.java) { dao.reserve(r.copy(attemptId = UUID.randomUUID().toString())) {} }
            assertThrows(Exception::class.java) { dao.reserve(r.copy(unsignedDigest = "cd".repeat(32))) {} }
            assertThrows(Exception::class.java) { dao.finish(r, 1) {} }
        }
    }

    @Test fun twoDatabaseInstancesReserveOnlyOnceAndColdRowsCannotResume() {
        val name = "p-r-${UUID.randomUUID().toString().take(8)}.db"
        val pool = Executors.newFixedThreadPool(2)
        val r = record(PreparationFixture())
        val one = file(name); val two = file(name)
        try {
            one.openHelper.writableDatabase; two.openHelper.writableDatabase
            val start = CountDownLatch(1)
            val jobs = listOf(one, two).map { db -> pool.submit<Boolean> {
                check(start.await(5, TimeUnit.SECONDS))
                runCatching { db.sealedPreparations().reserve(r) {} }.isSuccess
            } }
            start.countDown()
            assertEquals(1, jobs.count { it.get(10, TimeUnit.SECONDS) })
            assertEquals(1, one.sealedPreparations().count())
        } finally { one.close(); two.close(); pool.shutdownNow() }
        try {
            file(name).use { db ->
                assertEquals("preparing", db.sealedPreparations().find(r.accountId, r.messageId)?.state)
                assertThrows(Exception::class.java) { db.sealedPreparations().reserve(r) {} }
                // A new attempt also cannot turn process death into permission to retry.
                assertThrows(Exception::class.java) { db.sealedPreparations().reserve(r.copy(attemptId = UUID.randomUUID().toString())) {} }
            }
        } finally { context.deleteDatabase(name) }
    }

    @Test fun hardCapacityNeverPrunesOrReusesReplayFences() {
        memory().use { db ->
            val dao = db.sealedPreparations()
            val base = record(PreparationFixture())
            db.runInTransaction {
                repeat(SealedPreparationDao.CAPACITY) { n ->
                    val id = UUID(1, n.toLong() + 1).toString()
                    dao.reserve(base.copy(messageId = id, attemptId = id)) {}
                }
            }
            assertEquals(1024, dao.count())
            assertThrows(Exception::class.java) { dao.reserve(base) {} }
            assertEquals(1024, dao.count())
            assertNotNull(dao.find(base.accountId, UUID(1, 1).toString()))
        }
    }

    @Test fun lineChangeClockFailureAndSqlWriteFaultRollbackFinalCas() {
        val f = PreparationFixture()
        memory().use { db ->
            val dao = db.sealedPreparations(); val r = record(f)
            assertTrue(db.attempts().installVerifiedLineBinding(f.binding(), listOf(ActiveSimCard(3, 7))))
            dao.reserve(r) {}
            assertTrue(db.attempts().installVerifiedLineBinding(f.binding().copy(generation = 2), listOf(ActiveSimCard(3, 7))))
            assertThrows(Exception::class.java) { dao.finish(r, 1) { require(it?.generation == 1L) } }
            var checks = 0
            assertThrows(Exception::class.java) { dao.finish(r, 1) { check(++checks < 2) } }
            assertEquals(2, checks)
            assertEquals("preparing", dao.find(r.accountId, r.messageId)?.state)
            db.openHelper.writableDatabase.execSQL("CREATE TRIGGER preparation_fault BEFORE UPDATE ON sealed_preparations BEGIN SELECT RAISE(ABORT, 'synthetic fault'); END")
            assertThrows(Exception::class.java) { dao.finish(r, 1) {} }
            assertEquals("preparing", dao.find(r.accountId, r.messageId)?.state)
            db.openHelper.writableDatabase.execSQL("DROP TRIGGER preparation_fault")
            dao.abort(r.accountId, r.messageId, r.attemptId)
            assertThrows(Exception::class.java) { dao.finish(r, 1) {} }
        }
    }

    @Test fun blockingTransactionAcquisitionPrecedesFinalContextCheck() {
        val name = "p-w-${UUID.randomUUID().toString().take(8)}.db"
        val one = file(name); val two = file(name)
        val pool = Executors.newFixedThreadPool(2)
        val locked = CountDownLatch(1); val release = CountDownLatch(1)
        val attempted = CountDownLatch(1)
        val valid = java.util.concurrent.atomic.AtomicBoolean(true)
        val checks = java.util.concurrent.atomic.AtomicInteger()
        val r = record(PreparationFixture())
        try {
            one.sealedPreparations().reserve(r) {}; two.openHelper.writableDatabase
            val holder = pool.submit { one.runInTransaction { locked.countDown(); check(release.await(10, TimeUnit.SECONDS)) } }
            assertTrue(locked.await(5, TimeUnit.SECONDS))
            val waiter = pool.submit<Boolean> {
                attempted.countDown()
                runCatching { two.sealedPreparations().finish(r, 1) { checks.incrementAndGet(); check(valid.get()) } }.isSuccess
            }
            assertTrue(attempted.await(5, TimeUnit.SECONDS))
            assertThrows(java.util.concurrent.TimeoutException::class.java) { waiter.get(200, TimeUnit.MILLISECONDS) }
            assertEquals(0, checks.get()) // Callback cannot run before the transaction lock is obtained.
            valid.set(false); release.countDown()
            holder.get(10, TimeUnit.SECONDS)
            assertFalse(waiter.get(10, TimeUnit.SECONDS))
            assertEquals(1, checks.get())
            assertEquals("preparing", one.sealedPreparations().find(r.accountId, r.messageId)?.state)
        } finally { release.countDown(); pool.shutdownNow(); one.close(); two.close(); context.deleteDatabase(name) }
    }

    @Test fun versionElevenUpgradePreservesAlphaAndIntroducesEmptyCandidateTable() {
        val name = "p-u-${UUID.randomUUID().toString().take(8)}.db"
        val f = PreparationFixture(); val r = record(f)
        try {
            file(name).use { db ->
                db.attempts().reserve(r.attemptId, 3, 1, f.now)
                // v12 differs from v11 only by this additive table/index. Reconstruct that old schema.
                db.openHelper.writableDatabase.execSQL("DROP TABLE sealed_preparations")
                db.openHelper.writableDatabase.version = 11
            }
            file(name).use { db ->
                assertNotNull(db.attempts().getAttempt(r.attemptId))
                assertEquals(0, db.sealedPreparations().count())
                assertEquals(12, db.openHelper.readableDatabase.version)
                db.sealedPreparations().reserve(r) {}
                assertEquals(AttemptState.SUBMITTING, db.attempts().getAttempt(r.attemptId)?.state)
            }
        } finally { context.deleteDatabase(name) }
    }
}
