// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedNoSubmit03CallbackLifetimeTest {
    @Test fun newTapRefusesWhileAnActualArrivalIsHeldBeforeEnqueueUntilTheWriterReturns() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); val row = ready.action.row; val dao = db.typedNoSubmits03()
            val request = TypedNoSubmit03Fixture.id()
            val io = TypedNoSubmit03Io(request, ready.proof.requestId, ready.proof.closureId, "status", f.epoch,
                TypedSubmit03Record.base(TypedNoSubmit03Wire.statusRequest(row, ready.proof, request, f.epoch)))
            val transport = dao.enter(row, ready.proof, io, ready.action::requireCurrent)!!
            val arrival = TypedNoSubmit03Lifetimes.callbackArriving() // Actual receiver-entry API, before enqueue.
            val queued = CountDownLatch(1); val release = CountDownLatch(1); val pool = Executors.newSingleThreadExecutor()
            val pending = pool.submit {
                queued.countDown(); check(release.await(5, TimeUnit.SECONDS))
                SmsCallbackJournal.record(db, row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -90, arrival)
            }
            val sends = f.sends
            try {
                assertTrue(queued.await(5, TimeUnit.SECONDS))
                assertTrue(db.typedSubmits03().callbacks(row.attemptId).isEmpty())
                assertThrows(IllegalStateException::class.java) { f.action(row) } // NEW tap at latest epoch.
                assertThrows(IllegalStateException::class.java) { dao.reserveSignature(row, ready.proof, ready.status, ready.context) }
                assertThrows(IllegalStateException::class.java) { f.host.exchangeClosure(transport, ready.action::requireCurrent) }
                assertEquals("unused", dao.proof(ready.proof.requestId)!!.signatureState)
                assertEquals(sends, f.sends); assertEquals(0, f.signs)
            } finally { release.countDown(); try { pending.get(5, TimeUnit.SECONDS) } finally { pool.shutdownNow() } }
            assertThrows(IllegalStateException::class.java) { ready.action.requireCurrent() }
            val changed = db.typedSubmits03().get(row.attemptId)!!
            f.action(changed).requireCurrent() // RAM guard is available again; durable conflict still refuses proof.
            assertTrue(changed.conflict); assertEquals(row.closureB64url, changed.closureB64url)
            assertEquals(-90L, db.typedSubmits03().callbacks(row.attemptId).single().observedMs)
        } }
    }
    @Test fun newTapAndAlreadyBurnedProofIoRefuseWhileTheRealRoomWriterHoldsTheCallback() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); val row = ready.action.row; val dao = db.typedNoSubmits03()
            val sign = dao.reserveSignature(row, ready.proof, ready.status, ready.context)!!
            val proof = dao.retainSignature(sign.proof, f.sign(sign, ready.context))!!
            val id = TypedNoSubmit03Fixture.id()
            val io = TypedNoSubmit03Io(id, proof.requestId, proof.closureId, "proof", f.epoch,
                TypedSubmit03Record.base(TypedNoSubmit03Wire.proofRequest(proof, f.epoch)))
            val transport = dao.enter(row, proof, io, ready.action::requireCurrent, ready.context)!!
            val holding = CountDownLatch(1); val release = CountDownLatch(1); val called = CountDownLatch(1)
            val pool = Executors.newFixedThreadPool(2)
            val writer = pool.submit { db.runInTransaction { holding.countDown(); check(release.await(5, TimeUnit.SECONDS)) } }
            assertTrue(holding.await(5, TimeUnit.SECONDS))
            val arrival = TypedNoSubmit03Lifetimes.callbackArriving()
            val callback = pool.submit { called.countDown()
                SmsCallbackJournal.record(db, row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -91, arrival) }
            val sends = f.sends; val signs = f.signs
            try {
                assertTrue(called.await(5, TimeUnit.SECONDS)); assertFalse(callback.isDone)
                assertThrows(IllegalStateException::class.java) { f.action(row) }
                assertThrows(IllegalStateException::class.java) { ready.context.requireCurrent(row, proof) }
                assertThrows(IllegalStateException::class.java) { f.host.exchangeClosure(transport) { ready.context.requireCurrent(row, proof) } }
                assertEquals(sends, f.sends); assertEquals(signs, f.signs)
            } finally { release.countDown(); try { writer.get(5, TimeUnit.SECONDS); callback.get(5, TimeUnit.SECONDS) } finally { pool.shutdownNow() } }
            assertThrows(IllegalStateException::class.java) { ready.action.requireCurrent() }
            assertEquals(proof.signatureB64url, dao.proof(proof.requestId)!!.signatureB64url)
            assertNull(dao.io(io.requestId)!!.replyB64url)
            assertEquals(-91L, db.typedSubmits03().callbacks(row.attemptId).single().observedMs)
        } }
    }
    @Test fun overlappingActualArrivalsCannotReleaseEachOtherOrRestoreAnOldDecision() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val old = f.action(row)
            val first = TypedNoSubmit03Lifetimes.callbackArriving(); val second = TypedNoSubmit03Lifetimes.callbackArriving()
            var one = false; var two = false
            try {
                SmsCallbackJournal.record(db, row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -92, first); one = true
                assertThrows(IllegalStateException::class.java) {
                    SmsCallbackJournal.record(db, row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -92, first)
                } // Replaying the completed first token cannot release the second arrival.
                assertEquals(1, db.typedSubmits03().callbacks(row.attemptId).size)
                assertThrows(IllegalStateException::class.java) { f.action(db.typedSubmits03().get(row.attemptId)!!) }
                SmsCallbackJournal.record(db, row.attemptId, 0, true, android.app.Activity.RESULT_OK, DeliveryStatus.RECEIVED, -93, second); two = true
            } finally {
                if (!one) SmsCallbackJournal.record(db, row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -92, first)
                if (!two) SmsCallbackJournal.record(db, row.attemptId, 0, true, android.app.Activity.RESULT_OK, DeliveryStatus.RECEIVED, -93, second)
            }
            assertThrows(IllegalStateException::class.java) { old.requireCurrent() }
            val changed = db.typedSubmits03().get(row.attemptId)!!
            f.action(changed).requireCurrent()
            val facts = db.typedSubmits03().callbacks(row.attemptId)
            assertEquals(listOf(1L, 2L), facts.map { it.arrivalOrdinal })
            assertEquals(listOf(-92L, -93L), facts.map { it.observedMs })
            assertEquals(row.commandB64url, changed.commandB64url); assertEquals(row.closureB64url, changed.closureB64url)
            assertTrue(changed.conflict); assertEquals(0, f.signs)
        } }
    }
    @Test fun rejectedQueueFailedStorageAndLostCompletionStayUnknownWithoutAnyReset() {
        // The SAME coordinator implementation, explicitly test-local so permanent UNKNOWN
        // failure controls do not poison the production singleton or fabricate a COMMIT.
        val rejected = TypedNoSubmit03CallbackLifetime(); val queued = rejected.begin()
        val executor = Executor { throw RejectedExecutionException("Synthetic rejected callback queue") }
        assertThrows(RejectedExecutionException::class.java) { queued.guard { executor.execute { error("Must not run") } } }
        assertThrows(IllegalStateException::class.java) { rejected.capture() }
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val lost = TypedNoSubmit03CallbackLifetime(); val arrival = lost.begin()
            assertThrows(IllegalStateException::class.java) { arrival.guard {
                assertTrue(db.typedSubmits03().recordCallback(row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -94))
                error("Return lost before the outer route observed its completion")
            } }
            assertThrows(IllegalStateException::class.java) { lost.capture() }
            assertEquals(-94L, db.typedSubmits03().callbacks(row.attemptId).single().observedMs)
            val other = lost.begin()
            SmsCallbackJournal.record(db, row.attemptId, 0, true, android.app.Activity.RESULT_OK,
                DeliveryStatus.RECEIVED, -96, other) // A different genuine completion cannot retire UNKNOWN.
            assertThrows(IllegalStateException::class.java) { lost.capture() }
            assertEquals(listOf(-94L, -96L), db.typedSubmits03().callbacks(row.attemptId).map { it.observedMs })
            assertTrue(db.typedSubmits03().get(row.attemptId)!!.conflict); assertEquals(0, f.signs)
        } }
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val failed = TypedNoSubmit03CallbackLifetime(); val arrival = failed.begin()
            db.close() // Genuine unavailable Room, not a fake successful writer.
            assertTrue(runCatching { SmsCallbackJournal.record(db, row.attemptId, 0, false,
                android.app.Activity.RESULT_OK, null, -95, arrival) }.isFailure)
            assertThrows(IllegalStateException::class.java) { failed.capture() }
            assertEquals(0, f.signs)
        } }
    }
}
