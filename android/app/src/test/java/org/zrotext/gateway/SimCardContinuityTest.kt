// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SimCardContinuityTest {
    private val approved = ActivatedSimCard(subscriptionId = 7, cardId = 42)

    @Test fun sameSubscriptionWithDifferentCardIsNotTheApprovedSim() {
        assertFalse(SimCardContinuity.matches(approved, listOf(ActiveSimCard(7, 43))))
    }

    @Test fun embeddedProfileCannotUseSharedEuiccCardIdAsLineProof() {
        val embedded = listOf(ActiveSimCard(7, 42, isEmbedded = true))
        assertNull(SimCardContinuity.activationCandidate(embedded))
        assertFalse(SimCardContinuity.matches(approved, embedded))
    }

    @Test fun unchangedPublicCardObservationAcrossSyntheticRebootStillMatches() {
        val beforeReboot = listOf(ActiveSimCard(7, 42))
        val afterReboot = listOf(ActiveSimCard(7, 42))
        assertTrue(SimCardContinuity.activationCandidate(beforeReboot) == approved)
        assertTrue(SimCardContinuity.matches(approved, beforeReboot))
        assertTrue(SimCardContinuity.matches(approved, afterReboot))
        assertFalse(SimCardContinuity.matches(approved, listOf(ActiveSimCard(8, 42))))
    }

    @Test fun absentUnreadableOrAmbiguousSimCannotAttributeAnEvent() {
        assertFalse(SimCardContinuity.matches(approved, null))
        assertFalse(SimCardContinuity.matches(approved, emptyList()))
        assertFalse(SimCardContinuity.matches(approved,
            listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))))
        assertFalse(SimCardContinuity.matches(null, listOf(ActiveSimCard(7, 42))))
    }

    @Test fun unsupportedOrUninitializedCardIdCannotAttributeAnEvent() {
        for (id in listOf(null, -1, -2)) {
            assertFalse(SimCardContinuity.matches(approved, listOf(ActiveSimCard(7, id))))
            assertNull(SimCardContinuity.activationCandidate(listOf(ActiveSimCard(7, id))))
        }
        assertFalse(SimCardContinuity.matches(ActivatedSimCard(7, -1),
            listOf(ActiveSimCard(7, -1))))
        assertFalse(SimCardContinuity.matches(ActivatedSimCard(7, -2),
            listOf(ActiveSimCard(7, -2))))
    }
}
