// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import javax.crypto.spec.SecretKeySpec

/** Actual Room and GCM storage tests; no hardware, authenticated server or installed capability. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ConversationInterval03JournalTest {
    private class Fixture : AutoCloseable {
        val f = ConversationInterval03TestFixture()
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), ConversationInterval03Database::class.java)
            .allowMainThreadQueries().build()
        val dao get() = db.intervals()
        val store = ConversationInterval03Store(RuntimeEnvironment.getApplication(),
            ConversationExistingJournalProtection { SecretKeySpec(ByteArray(32) { 11 }, "AES") },
            ConversationExistingSuppressionTokens { SecretKeySpec(ByteArray(32) { 12 }, "HmacSHA256") })
        val full = f.proof()
        val initial = ConversationInterval03Proof(full.statement, full.ownerSignature(), full.requestedMs)
        val reserved = store.record(initial, "approval_reserved", f.f.now)
        val signed = store.record(initial.withPhone(checkNotNull(full.phoneSignature())), "approval_signed", f.f.now)
        val approved = store.record(initial.withPhone(checkNotNull(full.phoneSignature())).approved(checkNotNull(full.approvedMs)), "approved", f.f.now)
        val installReserved = approved.copy(state = "install_reserved")
        val installSigned = store.record(initial.withPhone(checkNotNull(full.phoneSignature())).approved(checkNotNull(full.approvedMs))
            .withInstalled(checkNotNull(full.installedSignature())), "install_signed", f.f.now)
        val active = store.record(full, "active", f.f.now)
        fun reserve(row: ConversationInterval03Record, now: Long, current: () -> Unit) = dao.reserve(row.copy(reservedMs = 0), now, current)
        override fun close() { store.close(); db.close(); f.close() }
    }
    @Test fun originalPhasesAreDurableBeforeSignatureReleaseAndCannotBeSkippedOrReopened(): Unit = Fixture().use { v ->
        v.reserve(v.reserved, v.f.f.now) {}
        assertTrue(checkNotNull(v.dao.find(v.reserved.intervalId)).same(v.reserved))
        assertThrows(Exception::class.java) { v.reserve(v.reserved, v.f.f.now) {} }
        assertThrows(Exception::class.java) { v.dao.advance(v.reserved, v.active) {} }
        v.dao.advance(v.reserved, v.signed) {}; v.dao.advance(v.signed, v.approved) {}
        v.dao.advance(v.approved, v.installReserved) {}; v.dao.advance(v.installReserved, v.installSigned) {}
        v.dao.advance(v.installSigned, v.active) {}
        assertTrue(checkNotNull(v.dao.find(v.active.intervalId)).same(v.active))
        assertThrows(Exception::class.java) { v.dao.advance(v.installSigned, v.active) {} }
    }
    @Test fun originalSignaturesTimesScopeReceiptAndNonceCommitmentsCannotChangeAcrossTransitions(): Unit = Fixture().use { v ->
        v.reserve(v.reserved, v.f.f.now) {}; v.dao.advance(v.reserved, v.signed) {}
        for (changed in listOf(v.approved.copy(ownerSignatureSha256 = "a".repeat(64)), v.approved.copy(requestedMs = v.approved.requestedMs + 1),
            v.approved.copy(phoneSignatureSha256 = "b".repeat(64)), v.approved.copy(scopeToken = "c".repeat(64)),
            v.approved.copy(receiptId = java.util.UUID(0, 999).toString()), v.approved.copy(statementNonceSha256 = "d".repeat(64))))
            assertThrows(Exception::class.java) { v.dao.advance(v.signed, changed) {} }
        assertTrue(checkNotNull(v.dao.find(v.signed.intervalId)).same(v.signed))
    }
    @Test fun roomWaitLosingRamCurrentRollsBackBothReservationAndPhaseAdvance(): Unit = Fixture().use { v ->
        var calls = 0
        assertThrows(Exception::class.java) { v.reserve(v.reserved, v.f.f.now) { check(++calls < 2) } }
        assertNull(v.dao.find(v.reserved.intervalId))
        v.reserve(v.reserved, v.f.f.now) {}; calls = 0
        assertThrows(Exception::class.java) { v.dao.advance(v.reserved, v.signed) { check(++calls < 2) } }
        assertTrue(checkNotNull(v.dao.find(v.reserved.intervalId)).same(v.reserved))
    }
    @Test fun setupExpiryNeverInfersUnacceptedOutcomeAndStopKeepsProofsButRefusesLateAck(): Unit = Fixture().use { v ->
        v.reserve(v.reserved, v.f.f.now) {}; v.dao.advance(v.reserved, v.signed) {}
        val next = v.f.proof(v.f.statement(88))
        val pending = v.store.record(ConversationInterval03Proof(next.statement, next.ownerSignature(), next.requestedMs), "approval_reserved")
        assertThrows(Exception::class.java) { v.reserve(pending, v.full.statement.setupExpiresMs + 1) {} }
        v.dao.stop(v.reserved.intervalId)
        val stopped = checkNotNull(v.dao.find(v.reserved.intervalId))
        assertEquals("stopped", stopped.state)
        assertArrayEquals(v.signed.protectedProof, stopped.protectedProof)
        assertThrows(Exception::class.java) { v.dao.advance(v.signed, v.approved) {} }
        assertArrayEquals(v.initial.statement.bytes(), v.store.proof(stopped).statement.bytes())
    }
    @Test fun ciphertextIsAuthenticatedToOriginalIntervalAndStatementAndMissingKeyNeverCreatesOne(): Unit = Fixture().use { v ->
        assertArrayEquals(v.full.bytes(), v.store.proof(v.active).bytes())
        val changed = v.active.protectedProof.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { v.store.proof(v.active.copy(protectedProof = changed)) }
        assertThrows(Exception::class.java) { v.store.proof(v.active.copy(intervalId = java.util.UUID(0, 999).toString())) }
        assertThrows(Exception::class.java) { v.store.proof(v.active.copy(statementSha256 = "a".repeat(64))) }
        val missing = ConversationExistingJournalProtection { error("Existing key missing") }
        assertThrows(Exception::class.java) { missing.requireAvailable() }
        assertThrows(Exception::class.java) { missing.seal("synthetic", "nonempty-aad") }
    }
    @Test fun dailyBudgetSurvivesStopsAndReconnectWhileAllHistoricalRowsRemainDurable(): Unit = Fixture().use { v ->
        val originals = (0..15).map { index ->
            val issued = 100_000L + index * 1000
            val proof = v.f.proof(v.f.statement(100L + index, issued + 800, issued))
            val initial = ConversationInterval03Proof(proof.statement, proof.ownerSignature(), proof.requestedMs)
            v.reserve(v.store.record(initial, "approval_reserved"), issued + 20) {}
        }
        // A different actual connection changes the live scope, never the daily budget scope.
        val reconnected = ConversationInterval03TestFixture(v.f.f, ByteArray(32) { 45 })
        val proof = reconnected.proof(reconnected.statement(500, 116_800, 116_000))
        val fresh = v.store.record(ConversationInterval03Proof(proof.statement, proof.ownerSignature(), proof.requestedMs), "approval_reserved")
        assertEquals(originals.first().budgetToken, fresh.budgetToken)
        assertNotEquals(originals.first().scopeToken, fresh.scopeToken)
        v.dao.stop(originals.last().intervalId)
        assertThrows(Exception::class.java) { v.reserve(fresh, 116_020) {} }
        assertThrows(Exception::class.java) { v.reserve(originals.first(), 116_020) {} } // Exact retry does not allocate.
        originals.forEach { assertNotNull(v.dao.find(it.intervalId)) }
        // Exclusive rolling boundary releases exactly the old allocation, never deletes history.
        val at = 100_020L + 86_400_000L
        val later = reconnected.proof(reconnected.statement(501, at + 800, at - 20))
        val allocated = v.reserve(v.store.record(ConversationInterval03Proof(later.statement,
            later.ownerSignature(), later.requestedMs), "approval_reserved"), at) {}
        assertEquals(at, allocated.reservedMs)
        originals.forEach { assertNotNull(v.dao.find(it.intervalId)) }
        val blocked = reconnected.proof(reconnected.statement(502, at + 800, at - 20))
        assertThrows(Exception::class.java) { v.reserve(v.store.record(ConversationInterval03Proof(blocked.statement,
            blocked.ownerSignature(), blocked.requestedMs), "approval_reserved"), at) {} }
    }
    @Test fun writerCapturesAllocationTimeAndTransitionsCannotRewriteBudgetOrReservation(): Unit = Fixture().use { v ->
        assertThrows(Exception::class.java) { v.dao.reserve(v.reserved, v.f.f.now) {} }
        v.reserve(v.reserved, v.f.f.now) {}
        for (changed in listOf(v.signed.copy(reservedMs = v.signed.reservedMs + 1), v.signed.copy(budgetToken = "e".repeat(64))))
            assertThrows(Exception::class.java) { v.dao.advance(v.reserved, changed) {} }
        assertTrue(checkNotNull(v.dao.find(v.reserved.intervalId)).same(v.reserved))
    }
}
