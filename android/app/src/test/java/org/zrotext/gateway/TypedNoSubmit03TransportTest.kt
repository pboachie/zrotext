// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedNoSubmit03TransportTest {
    @Test fun unrelatedLateStatusCannotCompleteAnotherDurablyCorrelatedPendingRead() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            var unrelated = 0
            f.beforeReply = { reply -> if (reply.optString("type") == "payload_profile_no_submit_status03") {
                unrelated++; f.host.acceptClosure(JSONObject(reply.toString()).put("request_id", TypedNoSubmit03Fixture.id()).toString().toByteArray())
            } }
            val ready = f.prepared(db)
            assertEquals(1, unrelated); ready.context.requireCurrent(ready.action.row, ready.proof)
            assertNotNull(ready.status.replyB64url); assertEquals(0, f.signs)
        } }
    }
    @Test fun foregroundWithdrawalAfterWriterEntryCausesZeroActualSocketSendsAndKeepsTheBurn() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val original = f.closed(db); val captured = f.action(original); val dao = db.typedNoSubmits03()
            val receipt = dao.first(original, TypedNoSubmit03Fixture.id(), captured::requireCurrent)!!
            val action = captured.afterFirst(receipt); val row = action.row; val p = receipt.proof
            val io = TypedNoSubmit03Io(TypedNoSubmit03Fixture.id(), p.requestId, p.closureId, "challenge", f.epoch,
                TypedSubmit03Record.base(TypedNoSubmit03Wire.challengeRequest(row, p, f.epoch)))
            val entry = dao.enter(row, p, io, action::requireCurrent)!!
            val before = f.sends; f.foreground.update(false)
            assertThrows(IllegalStateException::class.java) { f.host.exchangeClosure(entry, action::requireCurrent) }
            assertEquals(before, f.sends); assertEquals(io, dao.io(io.requestId)); assertNull(dao.io(io.requestId)!!.replyB64url)
            assertThrows(IllegalStateException::class.java) { entry.consume() }
        } }
    }
    @Test fun historicalChallengeAndWrongSubjectCannotBeReconstructedAsAPresentClock() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db)
            assertThrows(IllegalStateException::class.java) { f.clock(db, ready.action.row, ready.proof.closureId, "closure") }
            assertEquals(0, f.signs)
            assertNull(ready.proof.signatureB64url)
            val p = ready.proof
            val io = TypedNoSubmit03Io(TypedNoSubmit03Fixture.id(), p.requestId, p.closureId, "proof", f.epoch, "eA")
            assertThrows(Exception::class.java) { db.typedNoSubmits03().enter(ready.action.row, p, io, {}) }
        } }
    }
    @Test fun acceptedExactReceiptAfterGenuineSamePointReconnectNeverSignsOrReturnsAPermit() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val reporter = TypedNoSubmit03Reporter(db, f::sign)
            assertTrue(reporter.report(f.action(row)).completed)
            val dao = db.typedNoSubmits03(); val p = dao.proof(dao.lineage(row.closingId!!)!!.currentRequestId)!!
            val exact = p.signatureB64url; val signs = f.signs; val oldEpoch = f.epoch
            f.reconnect(); assertTrue(f.epoch > oldEpoch)
            val refreshed = db.typedSubmits03().get(row.attemptId)!!
            val result = reporter.status(f.action(refreshed))
            assertTrue(result.completed); assertEquals(signs, f.signs)
            assertEquals(exact, dao.proof(p.requestId)!!.signatureB64url)
            assertEquals("closed_no_submit", db.typedSubmits03().get(row.attemptId)!!.phase)
        } }
    }
    @Test fun unacceptedOldProofLeaseRefusesNewSignatureUnderANewConnection() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); f.reconnect()
            assertThrows(IllegalArgumentException::class.java) { TypedNoSubmit03Reporter(db, f::sign).report(f.action(ready.action.row)) }
            assertEquals(0, f.signs); assertEquals(ready.proof, db.typedNoSubmits03().proof(ready.proof.requestId))
            assertFalse(db.typedNoSubmits03().history(ready.proof.requestId).any { it.kind == "proof" })
        } }
    }
}
