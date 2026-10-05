// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic public subscription/card observations; no device, credentials or SMS. */
class SelectedSimContinuityAcceptanceTest {
    private val selected = ActivatedSimCard(7, 42)

    @Test fun explicitlySelectedPhysicalCardSurvivesDistinctSecondSimAndOrderChange() {
        val cards = listOf(ActiveSimCard(8, 43), ActiveSimCard(7, 42))
        assertEquals(selected, SimCardContinuity.activationCandidate(cards, 7))
        assertTrue(SimCardContinuity.matches(selected, cards))
        assertTrue(SimCardContinuity.matches(selected, cards.reversed()))
        assertEquals(ActivatedSimCard(8, 43), SimCardContinuity.activationCandidate(cards, 8))
    }

    @Test fun unscopedDualSimObservationNeverChoosesEitherLine() {
        assertNull(SimCardContinuity.activationCandidate(listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))))
        assertNull(SimCardContinuity.activationCandidate(listOf(ActiveSimCard(7, 42), ActiveSimCard(8, null))))
    }

    @Test fun unrelatedEmbeddedUnknownOrChangedPeerDoesNotGrantOrRevokeSelectedCard() {
        for (peer in listOf(ActiveSimCard(8, 43, true), ActiveSimCard(8, null), ActiveSimCard(9, -1))) {
            assertTrue(SimCardContinuity.matches(selected, listOf(ActiveSimCard(7, 42), peer)))
            assertNull(SimCardContinuity.activationCandidate(listOf(ActiveSimCard(7, 42), peer), peer.subscriptionId))
        }
    }

    @Test fun missingChangedEmbeddedOrUnknownSelectedCardNeverFallsBackToPeer() {
        for (cards in listOf(null, emptyList(), listOf(ActiveSimCard(8, 43)),
            listOf(ActiveSimCard(7, 43), ActiveSimCard(8, 42)),
            listOf(ActiveSimCard(7, 42, true), ActiveSimCard(8, 43)),
            listOf(ActiveSimCard(7, null), ActiveSimCard(8, 43)),
            listOf(ActiveSimCard(7, -1), ActiveSimCard(8, 43)))) {
            assertFalse(SimCardContinuity.matches(selected, cards))
        }
        assertNull(SimCardContinuity.activationCandidate(listOf(ActiveSimCard(7, 42)), -1))
    }

    @Test fun anyDuplicateSubscriptionIdMakesSnapshotAmbiguous() {
        for (cards in listOf(listOf(ActiveSimCard(7, 42), ActiveSimCard(7, 43)),
            listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43), ActiveSimCard(8, 44)))) {
            assertNull(SimCardContinuity.activationCandidate(cards, 7))
            assertFalse(SimCardContinuity.matches(selected, cards))
        }
    }

    @Test fun anotherSubscriptionSharingSelectedCardCannotEstablishPhysicalContinuity() {
        for (peer in listOf(ActiveSimCard(8, 42), ActiveSimCard(8, 42, true))) {
            assertNull(SimCardContinuity.activationCandidate(listOf(ActiveSimCard(7, 42), peer), 7))
            assertFalse(SimCardContinuity.matches(selected, listOf(ActiveSimCard(7, 42), peer)))
        }
    }
}
