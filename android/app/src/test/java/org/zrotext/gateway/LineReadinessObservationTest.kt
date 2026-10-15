// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class LineReadinessObservationTest {
    private val lineA = UUID.nameUUIDFromBytes("line-a".toByteArray())
    private val lineB = UUID.nameUUIDFromBytes("line-b".toByteArray())
    private val threshold = 300_000L

    private fun store(seed: Long = 1_999_000L): LineReadinessStore {
        val s = LineReadinessStore { now }
        s.register(listOf(lineA, lineB))
        s.onAuthenticatedObservation(lineA, seed)
        s.onAuthenticatedObservation(lineB, seed)
        return s
    }

    private var now = 2_000_000L

    @Test
    fun aFreshlyObservedLineIsReady() {
        val s = store()
        val observation = s.observe(lineA, now, threshold)
        assertEquals(LineReadinessKind.READY, observation.kind)
        assertEquals(1_000L, observation.sinceObservationMs)
    }

    @Test
    fun aLinePastItsOfflineThresholdIsNotReady() {
        val s = store()
        val observation = s.observe(lineA, now + threshold, threshold)
        assertEquals(LineReadinessKind.OFFLINE_PAST_THRESHOLD, observation.kind)
    }

    @Test
    fun aLineWithNoObservationFailsClosedAsOffline() {
        val s = LineReadinessStore { now }
        s.register(listOf(lineA))
        val observation = s.observe(lineA, now, threshold)
        assertEquals(LineReadinessKind.OFFLINE_PAST_THRESHOLD, observation.kind)
        assertEquals(null, observation.sinceObservationMs)
    }

    @Test
    fun eachReadinessCaseNamesItsOwnStableCode() {
        val fresh = LineReadinessObservation(lineA, LineReadinessKind.READY, 1L, 2L)
        val cases = mapOf(
            LineReadinessKind.INACTIVE to "line_not_ready_inactive",
            LineReadinessKind.BINDING_NOT_ACTIVE to "line_not_ready_binding_not_active",
            LineReadinessKind.CONTINUITY_PENDING to "line_not_ready_continuity_pending",
            LineReadinessKind.CARD_CHANGED to "line_not_ready_card_changed",
            LineReadinessKind.OFFLINE_PAST_THRESHOLD to "line_not_ready_offline",
            LineReadinessKind.READY to "line_ready",
        )
        for ((kind, code) in cases) {
            val o = if (kind == LineReadinessKind.OFFLINE_PAST_THRESHOLD)
                LineReadinessObservation(lineA, kind, null, 2L)
            else LineReadinessObservation(lineA, kind, 1L, 2L)
            assertEquals(code, o.code())
            assertEquals(kind, o.kind)
        }
        assertEquals("line_ready", fresh.code())
    }

    @Test
    fun aReadyObservationRequiresAFreshObservation() {
        assertThrows(IllegalArgumentException::class.java) {
            LineReadinessObservation(lineA, LineReadinessKind.READY, null, 2L)
        }
        assertThrows(IllegalArgumentException::class.java) {
            LineReadinessObservation(lineA, LineReadinessKind.INACTIVE, null, 2L)
        }
    }

    @Test
    fun linesAreIndependent() {
        val s = store()
        s.onAuthenticatedObservation(lineA, now)
        // lineB keeps its old observation and goes offline while lineA stays
        // ready; the refresh of one line never refreshes another.
        val snapshot = s.snapshot(now + 1_000, threshold)
        assertEquals(LineReadinessKind.READY, snapshot[0].kind)
        assertEquals(
            LineReadinessKind.OFFLINE_PAST_THRESHOLD,
            s.observe(lineB, now + threshold + 1, threshold).kind,
        )
        assertEquals(2, snapshot.size)
    }

    @Test
    fun aRevokedLineReportsInactiveBeforeAnyOtherCase() {
        val s = store()
        s.onActivationState(lineA, active = false)
        assertEquals(LineReadinessKind.INACTIVE, s.observe(lineA, now, threshold).kind)
    }

    @Test
    fun aDroppedBindingReportsBindingNotActive() {
        val s = store()
        s.onBindingState(lineA, bindingActive = false)
        assertEquals(
            LineReadinessKind.BINDING_NOT_ACTIVE,
            s.observe(lineA, now, threshold).kind,
        )
    }

    @Test
    fun aChangedCardIsStickyUntilOwnerReapproval() {
        val s = store()
        s.onCardChanged(lineA)
        assertEquals(LineReadinessKind.CARD_CHANGED, s.observe(lineA, now, threshold).kind)
        // A later heartbeat does not clear a changed card: freshness is not authority.
        s.onAuthenticatedObservation(lineA, now)
        assertEquals(LineReadinessKind.CARD_CHANGED, s.observe(lineA, now + 1, threshold).kind)
        s.onBindingReapproved(lineA)
        assertEquals(LineReadinessKind.READY, s.observe(lineA, now + 2, threshold).kind)
    }

    @Test
    fun aPendingContinuityCheckReportsContinuityPending() {
        val s = store()
        s.onContinuityCheck(lineA, pending = true)
        assertEquals(
            LineReadinessKind.CONTINUITY_PENDING,
            s.observe(lineA, now, threshold).kind,
        )
        s.onContinuityCheck(lineA, pending = false)
        assertEquals(LineReadinessKind.READY, s.observe(lineA, now, threshold).kind)
    }

    @Test
    fun aNonMonotonicClockCannotRollFreshnessBack() {
        val s = store(seed = 5_000_000L)
        s.onAuthenticatedObservation(lineA, atMs = 1_000L) // stale timestamp, ignored
        val observation = s.observe(lineA, now, threshold)
        assertEquals(LineReadinessKind.READY, observation.kind)
        assertEquals(0L, observation.sinceObservationMs)
    }

    @Test
    fun reregisteringReplacesTheRosterWithoutInheritingEvents() {
        val s = store()
        s.onCardChanged(lineB)
        s.register(listOf(lineA))
        assertEquals(true, s.isRegistered)
        assertThrows(IllegalArgumentException::class.java) { s.observe(lineB, now, threshold) }
        // lineA's own state survived the roster change.
        assertEquals(LineReadinessKind.READY, s.observe(lineA, now, threshold).kind)
        val empty = LineReadinessStore { now }
        assertEquals(false, empty.isRegistered)
    }

    @Test
    fun preimagesBindIdentityKindFreshnessAndTime() {
        val a = LineReadinessObservation(lineA, LineReadinessKind.READY, 100L, 200L)
        val same = LineReadinessObservation(lineA, LineReadinessKind.READY, 100L, 200L)
        val otherLine = LineReadinessObservation(lineB, LineReadinessKind.READY, 100L, 200L)
        val stale = LineReadinessObservation(lineA, LineReadinessKind.OFFLINE_PAST_THRESHOLD, null, 200L)
        assertArrayEquals(a.digest(), same.digest())
        assertNotEquals(a.digest().contentToString(), otherLine.digest().contentToString())
        assertNotEquals(a.digest().contentToString(), stale.digest().contentToString())
    }

    @Test
    fun toStringNeverCarriesLineIdentity() {
        val o = LineReadinessObservation(lineA, LineReadinessKind.CARD_CHANGED, 10L, 20L)
        assertEquals(false, o.toString().contains(lineA.toString()))
    }

    private fun assertArrayEquals(expected: ByteArray, actual: ByteArray) {
        assertEquals(expected.contentToString(), actual.contentToString())
    }
}
