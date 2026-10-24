// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedNoSubmit03JournalTest {
    @Test fun newLineagePrecedesChallengeIoAndColdBurnCannotMintAnotherInvocationTicket() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val original = f.closed(db); val dao = db.typedNoSubmits03()
            val oldAction = f.action(original)
            val receipt = dao.first(original, TypedNoSubmit03Fixture.id(), oldAction::requireCurrent)!!
            val row = receipt.after; val p = receipt.proof
            val action = oldAction.afterFirst(receipt)
            assertEquals(original.copy(closureProofState = "started:${p.requestId}"), row)
            assertEquals("eligible:${p.closureId}", original.closureProofState)
            assertArrayEquals(original.command().bytes(), row.command().bytes()); assertEquals(original.closureB64url, row.closureB64url)
            assertNull(dao.first(original, TypedNoSubmit03Fixture.id(), oldAction::requireCurrent))
            assertNull(dao.first(row, TypedNoSubmit03Fixture.id(), action::requireCurrent))
            assertEquals(p.requestId, dao.lineage(p.closureId)!!.currentRequestId)
            assertNull(p.coreB64url); assertEquals("unused", p.signatureState); assertTrue(dao.history(p.requestId).isEmpty())
            val io = TypedNoSubmit03Io(TypedNoSubmit03Fixture.id(), p.requestId, p.closureId, "challenge", f.epoch,
                TypedSubmit03Record.base(TypedNoSubmit03Wire.challengeRequest(row, p, f.epoch)))
            val entry = dao.enter(row, p, io, action::requireCurrent)!!
            assertEquals(io, dao.io(io.requestId)); assertArrayEquals(io.bytes(), entry.consume())
            assertThrows(IllegalStateException::class.java) { entry.consume() }
            assertNull(dao.enter(row, p, io, {})); assertEquals(1, f.sends)
            // Lose the returned first-COMMIT receipt: the old displayed action cannot
            // adopt an arbitrary later SELECT. A NEW explicit decision may resume SAME ID.
            assertThrows(IllegalStateException::class.java) { TypedNoSubmit03Reporter(db, f::sign).report(oldAction) }
            val displayed = db.typedSubmits03().get(row.attemptId)!!
            assertTrue(TypedNoSubmit03Reporter(db, f::sign).report(f.action(displayed)).completed)
            assertEquals(p.requestId, dao.lineage(p.closureId)!!.rootRequestId)
            assertEquals(1, f.signs)
        } }
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val original = f.closed(db); val checks = java.util.concurrent.atomic.AtomicInteger()
            assertThrows(IllegalStateException::class.java) {
                db.typedNoSubmits03().first(original, TypedNoSubmit03Fixture.id()) {
                    if (checks.incrementAndGet() == 2) error("Withdraw during first writer")
                }
            }
            // A failed pre-COMMIT guard rolled back ALL first-transition mutations.
            assertEquals(original, db.typedSubmits03().get(original.attemptId))
            assertNull(db.typedNoSubmits03().lineage(original.closingId!!))
            assertEquals(1, f.sends); assertEquals(0, f.signs)
            assertNotNull(db.typedNoSubmits03().first(original, TypedNoSubmit03Fixture.id()) {})
        } }
    }
    @Test fun competingWriterDecisionsWinExactlyOneIrreversibleSignatureReservation() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); val barrier = CyclicBarrier(2); val pool = Executors.newFixedThreadPool(2)
            try {
                val work = (0..1).map { pool.submit<Boolean> { barrier.await(5, TimeUnit.SECONDS)
                    db.typedNoSubmits03().reserveSignature(ready.action.row, ready.proof, ready.status, ready.context) != null } }
                assertEquals(1, work.count { it.get(10, TimeUnit.SECONDS) })
                assertEquals("reserved", db.typedNoSubmits03().proof(ready.proof.requestId)!!.signatureState)
                assertEquals(0, f.signs)
            } finally { pool.shutdownNow() }
        } }
    }
    @Test fun callbackAndEntryFactsCompeteWithTheSameNegativeWriterAndCannotBeErased() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); val original = ready.action.row
            SmsCallbackJournal.record(db, original.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -9)
            val changed = db.typedSubmits03().get(original.attemptId)!!
            assertTrue(changed.conflict); assertEquals(1L, changed.lastCallbackOrdinal)
            assertEquals(original.closureB64url, changed.closureB64url)
            assertThrows(IllegalStateException::class.java) { ready.context.requireCurrent(original, ready.proof) }
            assertFalse(db.typedSubmits03().retainPlatformEntry(original, 1) {})
        } }
    }
    @Test fun missingLineageAndMigratedAbsenceCannotAdoptAnExistingProofAsUnused() {
        // Every damaged schedule begins with an ACTUAL three-generation command chain.
        // No synthetic missing ancestor can be interpreted as a first or unused command.
        for (damage in listOf("lineage", "grandparent", "corrupt", "orphan", "signature", "all")) {
            TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
                val first = f.prepared(db); val dao = db.typedNoSubmits03()
                if (damage == "signature") {
                    val entry = dao.reserveSignature(first.action.row, first.proof, first.status, first.context)!!
                    assertNotNull(dao.retainSignature(entry.proof, f.sign(entry, first.context)))
                }
                val original = first.proof
                val retainedFirst = first.copy(proof = dao.proof(original.requestId)!!)
                val third = f.successor(db, f.successor(db, retainedFirst))
                val raw = db.openHelper.writableDatabase
                assertEquals(3L, dao.lineage(original.closureId)!!.proofCount)
                when (damage) {
                    "lineage" -> raw.execSQL("DELETE FROM typed_no_submit03_lineages")
                    "grandparent" -> raw.execSQL("DELETE FROM typed_no_submit03_proofs WHERE requestId=?", arrayOf(original.requestId))
                    "corrupt" -> raw.execSQL("UPDATE typed_no_submit03_proofs SET nonceB64url=? WHERE requestId=?",
                        arrayOf(TypedSubmit03Record.base(ByteArray(32) { 7 }), original.requestId))
                    "orphan" -> raw.execSQL("INSERT INTO typed_no_submit03_io (requestId,proofRequestId,closureId,kind,connectionEpoch,requestB64url) VALUES (?,?,?,?,?,?)",
                        arrayOf<Any>(TypedNoSubmit03Fixture.id(), TypedNoSubmit03Fixture.id(), original.closureId, "status", f.epoch, "eA"))
                    "signature" -> raw.execSQL("DELETE FROM typed_no_submit03_io WHERE requestId=?", arrayOf(original.requestId))
                    "all" -> for (table in listOf("typed_no_submit03_io", "typed_no_submit03_proofs", "typed_no_submit03_lineages")) raw.execSQL("DELETE FROM $table")
                }
                val signs = f.signs; val sends = f.sends
                val rejected = runCatching { dao.reserveSignature(third.action.row, third.proof, third.status, third.context) }
                assertTrue("Corrupt history must refuse $damage", rejected.isFailure || rejected.getOrNull() == null)
                val packet = TypedNoSubmit03Io(TypedNoSubmit03Fixture.id(), third.proof.requestId, original.closureId, "status", f.epoch,
                    TypedSubmit03Record.base(TypedNoSubmit03Wire.statusRequest(third.action.row, third.proof, TypedNoSubmit03Fixture.id(), f.epoch)))
                // Use its OWN request identity; malformed packets are not the reason for refusal.
                val exact = packet.copy(requestB64url = TypedSubmit03Record.base(TypedNoSubmit03Wire.statusRequest(third.action.row, third.proof, packet.requestId, f.epoch)))
                val entered = runCatching { dao.enter(third.action.row, third.proof, exact, third.action::requireCurrent) }
                assertTrue(entered.isFailure || entered.getOrNull() == null)
                assertNull(dao.first(third.action.row, TypedNoSubmit03Fixture.id()) {})
                if (damage in setOf("lineage", "all")) {
                    val status = TypedNoSubmit03Reporter(db, f::sign).status(f.action(third.action.row))
                    assertFalse(status.completed); assertTrue(status.text.contains("unavailable"))
                }
                assertEquals(third.action.row, db.typedSubmits03().get(original.attemptId))
                assertEquals(first.action.row.closureB64url, third.action.row.closureB64url)
                assertEquals(signs, f.signs); assertEquals(sends, f.sends)
            } }
        }
    }
    @Test fun uncertainProofIoIsImmutableAndDoesNotProvideAnotherSignatureOrEntry() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); val dao = db.typedNoSubmits03()
            val entry = dao.reserveSignature(ready.action.row, ready.proof, ready.status, ready.context)!!
            val p = dao.retainSignature(entry.proof, f.sign(entry, ready.context))!!
            val io = TypedNoSubmit03Io(TypedNoSubmit03Fixture.id(), p.requestId, p.closureId, "proof", f.epoch,
                TypedSubmit03Record.base(TypedNoSubmit03Wire.proofRequest(p, f.epoch)))
            assertNotNull(dao.enter(ready.action.row, p, io, {}, ready.context))
            assertNull(dao.enter(ready.action.row, p, io, {}, ready.context))
            assertNull(dao.reserveSignature(ready.action.row, p, ready.status, ready.context))
            assertNull(dao.io(io.requestId)!!.replyB64url); assertEquals(1, f.signs)
        } }
    }
    @Test fun lateActualSignatureIsRetainedAfterWithdrawalButCannotEnterProofTransport() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); f.afterSign = { f.foreground.update(false); f.foreground.update(true) }
            assertThrows(IllegalStateException::class.java) { TypedNoSubmit03Reporter(db, f::sign).report(f.action(row)) }
            val p = db.typedNoSubmits03().proof(db.typedNoSubmits03().lineage(row.closingId!!)!!.currentRequestId)!!
            assertEquals("result", p.signatureState); assertNotNull(p.signatureB64url)
            assertFalse(db.typedNoSubmits03().history(p.requestId).any { it.kind == "proof" }); assertEquals(1, f.signs)
        } }
    }
    @Test fun lostProviderResultStaysReservedAcrossExplicitStatusAndCannotResignThatCore() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val reporter = TypedNoSubmit03Reporter(db) { entry, context -> f.sign(entry, context); error("Lost provider return") }
            assertThrows(IllegalStateException::class.java) { reporter.report(f.action(row)) }
            val dao = db.typedNoSubmits03(); val p = dao.proof(dao.lineage(row.closingId!!)!!.currentRequestId)!!
            assertEquals("reserved", p.signatureState); assertNull(p.signatureB64url)
            val refreshed = db.typedSubmits03().get(row.attemptId)!! // NEW explicit decision reads actual committed metadata.
            assertFalse(TypedNoSubmit03Reporter(db, f::sign).report(f.action(refreshed)).completed)
            assertEquals(p, dao.proof(p.requestId)); assertEquals(1, f.signs)
        } }
    }
    @Test fun realMigrationAndReopenPreserveNegativeFactsWithoutInventingAnyProofLineage() {
        val app = RuntimeEnvironment.getApplication(); val name = "cancellation-${TypedNoSubmit03Fixture.id().take(8)}"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().addMigrations(SmsJournalDatabase.MIGRATION_25_26).build()
        try { TypedNoSubmit03Fixture().use { f ->
            lateinit var old: TypedSubmit03Record
            open().let { db -> try {
                val current = f.closed(db)
                old = current.copy(closureProofState = null) // Historical25 had no affirmative eligibility witness.
                val raw = db.openHelper.writableDatabase
                assertEquals("eligible:${current.closingId}", current.closureProofState)
                raw.execSQL("ALTER TABLE typed_submit03 DROP COLUMN closureProofState")
                for (table in listOf("typed_no_submit03_io", "typed_no_submit03_proofs", "typed_no_submit03_lineages")) raw.query("SELECT COUNT(*) FROM $table").use { assertTrue(it.moveToFirst()); assertEquals(0L, it.getLong(0)) }
                for (table in listOf("typed_no_submit03_io", "typed_no_submit03_proofs", "typed_no_submit03_lineages")) raw.execSQL("DROP TABLE $table")
                raw.execSQL("DROP TABLE room_master_table"); raw.version = 25
            } finally { db.close() } }
            open().let { db -> try {
                assertEquals(26, db.openHelper.readableDatabase.version); assertEquals(old, db.typedSubmits03().get(old.attemptId))
                assertNull(db.typedNoSubmits03().lineage(old.closingId!!)); assertEquals(1, f.sends)
                assertNull(db.typedNoSubmits03().first(old, TypedNoSubmit03Fixture.id()) {})
                assertEquals(old.closureB64url, db.typedSubmits03().get(old.attemptId)!!.closureB64url)
                assertEquals(old.commandB64url, db.typedSubmits03().get(old.attemptId)!!.commandB64url)
                assertEquals(1, db.typedHistory03().clocks(old.attemptId).size)
            } finally { db.close() } }
        } } finally { app.deleteDatabase(name) }
    }
}
