// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class GatewaySummaryStateTest {
    private val device = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    private val other = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    private fun snapshot(selected: UUID = device, remaining: Long = 30_000) = GatewaySummarySnapshot(selected,
        0, 86_400_000, 86_400_000 - remaining, GatewaySummaryCount(0, false), GatewaySummaryCount(1_000, true), GatewaySummaryCount(1, false))
    private fun state() = GatewaySummaryState().apply { select(device); resume() }
    @Test fun absentReaderAndPausedLifecycleCannotStartRequests() {
        val state = GatewaySummaryState()
        assertNull(state.begin(1, 1))
        state.select(device)
        assertNull(state.begin(1, 1))
        state.resume()
        assertNotNull(state.begin(1, 1))
        assertNull(state.begin(2, 2))
        state.pause()
        assertNull(state.begin(3, 3))
    }
    @Test fun zeroAndCappedValuesStayDistinctFromUnavailable() {
        val state = state()
        assertEquals(GatewaySummaryState.Phase.UNAVAILABLE, state.view(0, 0).phase)
        val ticket = state.begin(1_000, 5_000)!!
        assertTrue(state.complete(ticket, snapshot()))
        assertEquals(GatewaySummaryState.Phase.FRESH, state.view(1_001, 5_001).phase)
        assertEquals("0", state.view(1_001, 5_001).snapshot!!.submittedToday.label())
        assertEquals("1000+ (capped)", state.view(1_001, 5_001).snapshot!!.pending.label())
    }
    @Test fun latencyAndUtcBoundaryExpireObservationBeforeThirtySeconds() {
        val state = state()
        val ticket = state.begin(1_000, 5_000)!!
        assertTrue(state.complete(ticket, snapshot(remaining = 2_000)))
        assertEquals(GatewaySummaryState.Phase.FRESH, state.view(2_999, 6_999).phase)
        assertEquals(GatewaySummaryState.Phase.STALE, state.view(3_000, 7_000).phase)
    }
    @Test fun expiredObservationCannotReviveAfterClockRollback() {
        val state = state()
        state.complete(state.begin(1_000, 5_000)!!, snapshot())
        assertEquals(GatewaySummaryState.Phase.STALE, state.view(31_000, 35_000).phase)
        assertEquals(GatewaySummaryState.Phase.STALE, state.view(1_001, 5_001).phase)
    }
    @Test fun suspendWallTimeAndMonotonicResetBothRefuseFreshness() {
        val state = state()
        state.complete(state.begin(1_000, 5_000)!!, snapshot())
        assertEquals(GatewaySummaryState.Phase.STALE, state.view(1_001, 35_000).phase)
        val reset = state()
        reset.complete(reset.begin(1_000, 5_000)!!, snapshot())
        assertEquals(GatewaySummaryState.Phase.STALE, reset.view(999, 5_001).phase)
    }
    @Test fun changedScopeDiscardsDelayedResponseAndPreviousCounts() {
        val state = state()
        val ticket = state.begin(1, 1)!!
        state.select(other)
        assertFalse(state.complete(ticket, snapshot()))
        assertFalse(state.fail(ticket))
        assertNull(state.view(2, 2).snapshot)
        val next = state.begin(3, 3)!!
        assertFalse(state.complete(next, snapshot()))
        assertTrue(state.complete(next, snapshot(other)))
    }
    @Test fun pauseInvalidatesRequestAndRetainsOnlyHistoricalObservation() {
        val state = state()
        state.complete(state.begin(1, 1)!!, snapshot())
        val ticket = state.begin(2, 2)!!
        state.pause()
        assertFalse(state.complete(ticket, snapshot()))
        state.resume()
        assertEquals(GatewaySummaryState.Phase.STALE, state.view(3, 3).phase)
        state.clear()
        assertNull(state.view(3, 3).snapshot)
        assertNull(state.begin(3, 3))
    }
    @Test fun failedRefreshMarksHistoricalCountsWithoutInventingZero() {
        val state = state()
        state.complete(state.begin(1, 1)!!, snapshot())
        val request = state.begin(2, 2)!!
        assertEquals(GatewaySummaryState.Phase.LOADING, state.view(2, 2).phase)
        assertTrue(state.fail(request))
        assertEquals(GatewaySummaryState.Phase.STALE, state.view(3, 3).phase)
        assertEquals(1_000L, state.view(3, 3).snapshot!!.pending.value)
    }
}
