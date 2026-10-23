// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedNoSubmit03ContextTest {
    @Test fun actualPendingStatusAndProofClockBindBothSupportedFullLeaseVersions() {
        for (version in listOf(1, 2)) TypedNoSubmit03Fixture(version = version).use { f -> withDatabase { db ->
            val ready = f.prepared(db)
            ready.context.requireCurrent(ready.action.row, ready.proof)
            assertNotNull(db.typedNoSubmits03().reserveSignature(ready.action.row, ready.proof, ready.status, ready.context))
            assertEquals(0, f.signs); assertEquals(version, f.host.lineVersion)
            assertTrue(db.typedHistory03().clocks(ready.action.row.attemptId).single { it.subjectKind == "proof" }.entered)
        } }
    }
    @Test fun actualPrimaryBelowCoreIssueRefusesEvenWhenRoundTripUpperWouldHideTheRegression() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            f.issuedOffset = 5; f.rtt = 10
            assertThrows(IllegalArgumentException::class.java) { f.prepared(db) }
            assertEquals(0, f.signs)
            val p = db.typedNoSubmits03().choices(f.identity.accountId, f.identity.deviceId, f.identity.originHash,
                TypedSubmit03Record.base(f.point), "").single()
            assertEquals("unused", db.typedNoSubmits03().proof(db.typedNoSubmits03().lineage(p.closingId!!)!!.currentRequestId)!!.signatureState)
        } }
    }
    @Test fun equalityAtOriginalExpiryRefusesInsteadOfRenewingTheCoreOrClampingTime() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            f.proofLifetime = 10; f.rtt = 10
            assertThrows(IllegalArgumentException::class.java) { f.prepared(db) }
            assertEquals(0, f.signs)
            val row = db.typedNoSubmits03().choices(f.identity.accountId, f.identity.deviceId, f.identity.originHash,
                TypedSubmit03Record.base(f.point), "").single()
            val p = db.typedNoSubmits03().proof(db.typedNoSubmits03().lineage(row.closingId!!)!!.currentRequestId)!!
            assertEquals(10L, p.challenge().core.expiresMs - p.challenge().core.issuedMs)
        } }
    }
    @Test fun proofEpochPointOriginAndActualHostCannotBeSelectedFromColdOrUnrelatedFields() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            f.wrongProofEpoch = true
            assertThrows(IllegalArgumentException::class.java) { f.prepared(db) }
            val row = f.row()
            assertThrows(IllegalArgumentException::class.java) { f.host.requireOriginal(row.copy(originalOriginSha256 = "11".repeat(32))) }
            TypedNoSubmit03Fixture(endpoint = "wss://other-proof.example.test/device").use { other ->
                assertThrows(IllegalArgumentException::class.java) { other.host.requireOriginal(row) }
                assertThrows(IllegalStateException::class.java) { f.host.requireCurrent() }
            }
            assertEquals(0, f.signs)
        } }
    }
    @Test fun pauseResumeAbaPermanentlyWithdrawsThatExactForegroundDecision() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db); f.foreground.update(false); f.foreground.update(true)
            assertThrows(IllegalStateException::class.java) { ready.context.requireCurrent(ready.action.row, ready.proof) }
            assertThrows(IllegalStateException::class.java) { db.typedNoSubmits03().reserveSignature(ready.action.row, ready.proof, ready.status, ready.context) }
            assertEquals("unused", db.typedNoSubmits03().proof(ready.proof.requestId)!!.signatureState)
        } }
    }
    @Test fun newerObservationAndPreWriterCallbackWithdrawalInvalidateAnOlderContext() {
        TypedNoSubmit03Fixture().use { f -> withDatabase { db ->
            val ready = f.prepared(db)
            f.clock(db, ready.action.row, ready.proof.requestId, "proof")
            assertThrows(IllegalStateException::class.java) { ready.context.requireCurrent(ready.action.row, ready.proof) }
            val p = db.typedNoSubmits03().proof(ready.proof.requestId)!!
            val row = ready.action.row
            // Callback arrival invalidates RAM before a potentially blocked writer records it.
            TypedNoSubmit03Lifetimes.callbackArriving()
            assertThrows(IllegalStateException::class.java) { ready.action.requireCurrent() }
            assertEquals(p, db.typedNoSubmits03().proof(p.requestId)); assertEquals(row, db.typedSubmits03().get(row.attemptId))
            assertEquals(0, f.signs)
        } }
    }
}
