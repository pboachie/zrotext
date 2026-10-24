// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

class ConversationInterval03ForegroundTest {
    @Test fun everyPausePermanentlyWithdrawsAllEarlierDecisions() {
        val foreground = ConversationInterval03Foreground()
        assertThrows(IllegalStateException::class.java) { foreground.decision() }
        foreground.update(true)
        val first = foreground.decision(); val second = foreground.decision()
        assertTrue(first.isCurrent()); assertTrue(second.isCurrent())
        foreground.update(false); foreground.update(true)
        assertFalse(first.isCurrent()); assertFalse(second.isCurrent())
        val afterResume = foreground.decision(); assertTrue(afterResume.isCurrent())
        foreground.update(false); foreground.update(true)
        assertFalse(afterResume.isCurrent()); assertFalse(first.isCurrent())
    }
    @Test fun disposalAndDisplayReplacementNeverReviveAnEarlierDecision() {
        val old = ConversationInterval03Foreground().apply { update(true) }
        val decision = old.decision(); old.close(); old.update(true)
        assertFalse(decision.isCurrent())
        assertThrows(IllegalStateException::class.java) { old.decision() }
        val replacement = ConversationInterval03Foreground().apply { update(true) }
        assertTrue(replacement.decision().isCurrent()); assertFalse(decision.isCurrent())
        replacement.close()
    }
}
