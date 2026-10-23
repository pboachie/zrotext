// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedNoSubmit03ReporterTest {
    @Test fun explicitActualRoomHostClockAndSignerFlowReportsOnlyAfterTheExactReceiptIsDurable() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db)
            val result = TypedNoSubmit03Reporter(db, f::sign).report(f.action(row))
            assertTrue(result.completed); assertEquals(1, f.signs); assertEquals(5, f.sends)
            val dao = db.typedNoSubmits03(); val p = dao.proof(dao.lineage(row.closingId!!)!!.currentRequestId)!!
            assertNotNull(p.acceptedMs); assertTrue(dao.history(p.requestId).single { it.kind == "proof" }.replyB64url != null)
            assertTrue(ConversationContentCrypto.verifyRaw(TypedSubmit03Record.unbase(p.signatureB64url!!), f.point, p.challenge().core.transcript()))
            assertEquals(row.copy(closureProofState = "started:${p.requestId}"), db.typedSubmits03().get(row.attemptId)); assertNull(db.attempts().getAttempt(row.attemptId))
            assertTrue(result.text.contains("does not retry or send"))
        } }
    }
    @Test fun serverOnlyAcceptedStatusCannotFillALostSignatureOrTriggerANewSignature() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db)
            f.beforeReply = { reply -> if (reply.optString("type") == "payload_profile_no_submit_challenge03") {
                val core = TypedNoSubmit03Core.decode(TypedSubmit03Record.unbase(reply.getString("core")))
                f.acceptedSignature = f.rawSign(core); f.state = "accepted"
            } }
            assertThrows(IllegalArgumentException::class.java) { TypedNoSubmit03Reporter(db, f::sign).report(f.action(row)) }
            val dao = db.typedNoSubmits03(); val p = dao.proof(dao.lineage(row.closingId!!)!!.currentRequestId)!!
            assertNull(p.signatureB64url); assertNull(p.acceptedMs); assertEquals(0, f.signs)
            assertFalse(dao.history(p.requestId).any { it.kind == "proof" })
        } }
    }
    @Test fun lostProofAckIsRecoveredOnlyByExplicitExactStatusWithoutResigningOrRearming() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val reporter = TypedNoSubmit03Reporter(db, f::sign)
            f.beforeReply = { reply -> if (reply.optString("type") == "payload_profile_no_submit_ack03") error("Lost actual ACK") }
            assertThrows(IllegalStateException::class.java) { reporter.report(f.action(row)) }
            val dao = db.typedNoSubmits03(); val p = dao.proof(dao.lineage(row.closingId!!)!!.currentRequestId)!!
            assertNotNull(p.signatureB64url); assertNull(p.acceptedMs)
            assertNull(dao.history(p.requestId).single { it.kind == "proof" }.replyB64url)
            val before = f.sends; assertEquals(1, f.signs)
            f.beforeReply = {}
            val refreshed = db.typedSubmits03().get(row.attemptId)!!
            assertTrue(reporter.status(f.action(refreshed)).completed)
            assertEquals(before + 1, f.sends); assertEquals(1, f.signs)
            assertEquals(p.signatureB64url, dao.proof(p.requestId)!!.signatureB64url)
            assertEquals(refreshed, db.typedSubmits03().get(row.attemptId))
        } }
    }
    @Test fun newSuccessorMustCertifyItsExactExpiredPredecessorAndOldSupersededStatusCannotSkipIds() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val dao = db.typedNoSubmits03()
            assertThrows(IllegalStateException::class.java) { TypedNoSubmit03Reporter(db) { e, c -> f.sign(e, c); error("Original result lost") }.report(f.action(row)) }
            val old = dao.proof(dao.lineage(row.closingId!!)!!.currentRequestId)!!
            val refreshed = db.typedSubmits03().get(row.attemptId)!!
            f.state = "superseded"
            assertThrows(IllegalArgumentException::class.java) { TypedNoSubmit03Reporter(db, f::sign).report(f.action(refreshed)) }
            assertEquals(old.requestId, dao.lineage(old.closureId)!!.currentRequestId); assertEquals(1, f.signs)
            f.state = "challenged"; f.primary = old.challenge().core.expiresMs
            assertTrue(TypedNoSubmit03Reporter(db, f::sign).report(f.action(refreshed)).completed)
            val next = dao.proof(dao.lineage(old.closureId)!!.currentRequestId)!!
            assertNotEquals(old.requestId, next.requestId); assertEquals(old.requestId, next.previousRequestId)
            assertEquals(old.challenge().core.challengeId, next.previousChallengeId)
            assertEquals(old.challenge().core.expiresMs, next.challenge().predecessor!!.closedMs)
            assertEquals(next.challenge().core.issuedMs, next.challenge().predecessor!!.closedMs)
            assertEquals(old, dao.proof(old.requestId)); assertEquals(2, f.signs)
        } }
    }
    @Test fun blockedProviderReturnsHistoryAfterPauseAndCallbackButCannotProduceOutgoingProof() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val action = f.action(row)
            val returned = CountDownLatch(1); val release = CountDownLatch(1); val pool = Executors.newSingleThreadExecutor()
            f.afterSign = { returned.countDown(); check(release.await(10, TimeUnit.SECONDS)) }
            try {
                val future = pool.submit<Boolean> { try { TypedNoSubmit03Reporter(db, f::sign).report(action); true } catch (_: IllegalStateException) { false } }
                assertTrue(returned.await(10, TimeUnit.SECONDS))
                f.foreground.update(false); f.foreground.update(true)
                SmsCallbackJournal.record(db, row.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -12)
                release.countDown(); assertFalse(future.get(10, TimeUnit.SECONDS))
                val dao = db.typedNoSubmits03(); val p = dao.proof(dao.lineage(row.closingId!!)!!.currentRequestId)!!
                assertEquals("result", p.signatureState); assertNotNull(p.signatureB64url)
                assertFalse(dao.history(p.requestId).any { it.kind == "proof" }); assertEquals(1, f.signs)
                assertEquals(-12L, db.typedSubmits03().callbacks(row.attemptId).single().observedMs)
            } finally { release.countDown(); pool.shutdownNow() }
        } }
    }
    @Test fun selectedRowAndNewForegroundActionStayBoundAndStatusCannotAllocateAProofCommand() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val row = f.closed(db); val action = f.action(row)
            val reporter = TypedNoSubmit03Reporter(db, f::sign)
            val status = reporter.status(action)
            assertFalse(status.completed); assertNull(db.typedNoSubmits03().lineage(row.closingId!!)); assertEquals(1, f.sends)
            assertTrue(status.text.contains("unchanged")); assertEquals(row, action.row)
            f.foreground.update(false); f.foreground.update(true)
            assertThrows(IllegalStateException::class.java) { reporter.report(action) }
            assertNull(db.typedNoSubmits03().lineage(row.closingId)); assertEquals(0, f.signs)
            assertEquals(row, db.typedSubmits03().get(row.attemptId))
        } }
    }
}
