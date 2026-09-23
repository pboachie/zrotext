// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CallbackEvidenceTest {
    @Test fun replayedAndContradictorySentCallbacks() {
        assertEquals(CallbackEvidence.Decision.STORE, CallbackEvidence.sent(null, -1))
        assertEquals(CallbackEvidence.Decision.IGNORE, CallbackEvidence.sent(-1, -1))
        assertEquals(CallbackEvidence.Decision.CONFLICT, CallbackEvidence.sent(-1, 1))
        assertEquals(CallbackEvidence.Decision.CONFLICT, CallbackEvidence.sent(1, -1))
    }

    @Test fun pendingDeliveryReportCanResolveButSettledContradictionCannot() {
        val unverified = DeliveryStatus.UNVERIFIED
        val received = DeliveryStatus.RECEIVED
        val failed = DeliveryStatus.FAILED
        assertEquals(CallbackEvidence.Decision.STORE, CallbackEvidence.delivery(null, unverified))
        assertEquals(CallbackEvidence.Decision.STORE, CallbackEvidence.delivery(unverified, received))
        assertEquals(CallbackEvidence.Decision.IGNORE, CallbackEvidence.delivery(received, received))
        assertEquals(CallbackEvidence.Decision.IGNORE, CallbackEvidence.delivery(received, unverified))
        assertEquals(CallbackEvidence.Decision.CONFLICT, CallbackEvidence.delivery(received, failed))
    }

    @Test fun selectedSubscriptionMustStillBeActive() {
        assertTrue(SimSelection.isActive(3, listOf(3, 8)))
        assertFalse(SimSelection.isActive(5, listOf(3, 8)))
        assertFalse(SimSelection.isActive(-1, listOf(3, 8)))
        assertFalse(SimSelection.isActive(3, emptyList()))
    }
}
