// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Roadmap #628: trusted session time is anchored, bounded and invalidated like the issue demands. */
class SealedSessionClockTest {
    private val anchor = SealedSessionClock.establish(77L, 1_800_000_000_000L, 500_000L)

    @Test
    fun timeTracksTheMonotonicClockFromTheTrustedAnchor() {
        assertEquals(1_800_000_000_001L, anchor!!.nowMs(500_001))
        assertEquals(1_800_000_030_000L, anchor.nowMs(530_000))
        assertEquals(1_800_000_060_000L, anchor.nowMs(560_000))
    }

    @Test
    fun aMonotonicReadingAtOrBelowTheAnchorIsARebootAndRefusesTime() {
        assertNull(anchor!!.nowMs(500_000))
        assertNull(anchor.nowMs(499_999))
        assertNull(anchor.nowMs(0))
    }

    @Test
    fun anAgedOutAnchorRefusesTimeInsteadOfExtrapolating() {
        val stale = anchor!!.nowMs(500_000 + SealedSessionClock.MAX_ANCHOR_AGE_MS)
        assertEquals(1_800_000_060_000L, stale)
        assertNull(anchor.nowMs(500_001 + SealedSessionClock.MAX_ANCHOR_AGE_MS))
    }

    @Test
    fun theClockOnlyVouchesForItsOwnConnectionEpoch() {
        assertTrue(anchor!!.isCurrentSession(77L))
        assertFalse(anchor.isCurrentSession(76L))
        assertFalse(anchor.isCurrentSession(78L))
    }

    @Test
    fun aBrokenAnchorIsRefusedAtEstablishment() {
        assertNull(SealedSessionClock.establish(0L, 1_800_000_000_000L, 1L))
        assertNull(SealedSessionClock.establish(77L, 0L, 1L))
        assertNull(SealedSessionClock.establish(77L, -5L, 1L))
        assertNull(SealedSessionClock.establish(77L, 1_800_000_000_000L, -1L))
    }
}
