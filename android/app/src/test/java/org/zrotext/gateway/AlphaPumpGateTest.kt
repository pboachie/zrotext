// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AlphaPumpGateTest {
    @Test
    fun idleTicksNeverTouchTheJournal() {
        val gate = AlphaPumpGate()
        gate.onConnectionReset()
        repeat(20) { assertNull(gate.takeWork()) }
    }

    @Test
    fun sessionStartRunsQuarantineRetirementAndOneQueryOnly() {
        val gate = AlphaPumpGate()
        gate.onSessionStart()
        assertEquals(AlphaPumpWork(quarantineForeign = true, retireOrphans = true),
            gate.takeWork())
        assertNull(gate.takeWork())
    }

    @Test
    fun journalWriteOrGrantRequestsExactlyOneQueryWithoutMaintenance() {
        val gate = AlphaPumpGate()
        gate.onSessionStart()
        gate.takeWork()
        gate.requestQuery()
        assertEquals(AlphaPumpWork(quarantineForeign = false, retireOrphans = false),
            gate.takeWork())
        assertNull(gate.takeWork())
    }

    @Test
    fun grantExpiryRetiresOrphansWithoutReQuarantining() {
        val gate = AlphaPumpGate()
        gate.onSessionStart()
        gate.takeWork()
        gate.onGrantExpiry()
        assertEquals(AlphaPumpWork(quarantineForeign = false, retireOrphans = true),
            gate.takeWork())
        assertNull(gate.takeWork())
    }

    @Test
    fun connectionResetDropsPendingWork() {
        val gate = AlphaPumpGate()
        gate.onSessionStart()
        gate.onGrantExpiry()
        gate.onConnectionReset()
        assertNull(gate.takeWork())
    }

    @Test
    fun signalDeliversJournalWritesOnlyToTheInstalledListener() {
        var pumps = 0
        JournalWriteSignal.replace { pumps += 1 }
        JournalWriteSignal.alphaEventRecorded()
        JournalWriteSignal.alphaEventRecorded()
        JournalWriteSignal.replace(null)
        JournalWriteSignal.alphaEventRecorded()
        JournalWriteSignal.replace(null)
        assertEquals(2, pumps)
    }
}
