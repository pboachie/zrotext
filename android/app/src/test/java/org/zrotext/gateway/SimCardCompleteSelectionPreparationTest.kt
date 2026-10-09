// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

class SimCardCompleteSelectionPreparationTest {
    @Test fun explicitPhysicalAndEmbeddedUseHeldSetWithoutChangingLegacyCandidates() {
        val cards = listOf(ActiveSimCard(7, 101), ActiveSimCard(8, 202, true, 1, 1))
        assertNotNull(SimCardContinuity.activationCandidate(cards, 7))
        assertNull(SimCardContinuity.activationCandidate(cards, 8))
        for (selected in listOf(7, 8)) {
            CompletePreparationTestFixture(selected).use { fixture ->
                val prepared = requireNotNull(SimCardContinuity.prepareCompleteSelection(
                    fixture.bridge, selected, fixture.snapshot()))
                assertEquals(selected, prepared.selected.subscriptionId)
                assertEquals(2, prepared.activeRows.size)
                assertTrue(fixture.bridge.isCurrent(prepared))
            }
        }
        assertNotNull(SimCardContinuity.activationCandidate(cards, 7))
        assertNull(SimCardContinuity.activationCandidate(cards, 8))
    }

    @Test fun validLegacyPhysicalCardCannotSubstituteForRetiredCompleteObservation() {
        val cards = listOf(ActiveSimCard(7, 101), ActiveSimCard(8, 202))
        CompletePreparationTestFixture().use { fixture ->
            val held = fixture.snapshot()
            val prepared = requireNotNull(SimCardContinuity.prepareCompleteSelection(
                fixture.bridge, 7, held))
            fixture.source.permission = false
            fixture.adapter.permissionLost()
            assertNotNull(SimCardContinuity.activationCandidate(cards, 7))
            assertFalse(fixture.bridge.isCurrent(prepared))
            assertNull(SimCardContinuity.prepareCompleteSelection(fixture.bridge, 7, held))
        }
    }

    @Test fun remainingPeerNeverBecomesPreparedSelectionAfterSelectedDisappears() {
        val rows = listOf(ProfileSubscriptionObservation(7, 101, false, 0, 0),
            ProfileSubscriptionObservation(8, 202, false, 1, 1))
        CompletePreparationTestFixture(7, rows).use { fixture ->
            val held = fixture.snapshot()
            val prepared = requireNotNull(SimCardContinuity.prepareCompleteSelection(
                fixture.bridge, 7, held))
            fixture.source.rows = rows.filter { it.subscriptionId == 8 }
            fixture.source.changed()
            assertNotNull(SimCardContinuity.activationCandidate(listOf(ActiveSimCard(8, 202))))
            assertFalse(fixture.bridge.isCurrent(prepared))
            assertNull(SimCardContinuity.prepareCompleteSelection(fixture.bridge, 7, held))
            assertNull(fixture.adapter.observe())
        }
    }

    @Test fun matchingPublicCardCopiesDoNotRecoverAnotherObserversPreparation() {
        val cards = listOf(ActiveSimCard(7, 101), ActiveSimCard(8, 202))
        val legacy = SimCardContinuity.activationCandidate(cards, 7)
        assertTrue(SimCardContinuity.matches(legacy, cards.map { it.copy() }))
        CompletePreparationTestFixture().use { own ->
            CompletePreparationTestFixture().use { other ->
                val held = own.snapshot()
                assertNull(SimCardContinuity.prepareCompleteSelection(own.bridge, 7, other.snapshot()))
                val prepared = requireNotNull(SimCardContinuity.prepareCompleteSelection(own.bridge, 7, held))
                assertFalse(other.bridge.isCurrent(prepared))
                assertTrue(own.bridge.isCurrent(prepared))
            }
        }
    }
}
