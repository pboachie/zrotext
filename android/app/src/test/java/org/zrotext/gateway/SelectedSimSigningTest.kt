// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SelectedSimSigningTest {
    @Test fun signingPreservesExactChosenSimWhenUnrelatedPeerChanges() {
        var cards = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
        val result = SelectedSimSigning.sign(7, { 7 }, { cards }) {
            cards = listOf(ActiveSimCard(9, null, true), ActiveSimCard(7, 42))
            byteArrayOf(1, 2)
        }
        assertArrayEquals(byteArrayOf(1, 2), result)
    }

    @Test fun invalidSelectionOrAmbiguousObservationNeverInvokesKeyOperation() {
        var calls = 0
        for (cards in listOf(null, emptyList(), listOf(ActiveSimCard(8, 43)),
            listOf(ActiveSimCard(7, 42, true)), listOf(ActiveSimCard(7, null)),
            listOf(ActiveSimCard(7, 42), ActiveSimCard(7, 43)),
            listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 42)))) {
            assertThrows(IllegalStateException::class.java) {
                SelectedSimSigning.sign(7, { 7 }, { cards }) { calls++; byteArrayOf(1) }
            }
        }
        assertThrows(IllegalStateException::class.java) {
            SelectedSimSigning.sign(7, { 8 }, { listOf(ActiveSimCard(7, 42)) }) { calls++; byteArrayOf(1) }
        }
        assertEquals(0, calls)
    }

    @Test fun selectedCardOrSelectionChangeDuringKeyOperationNeverPublishesSignature() {
        for (mutation in 0..4) {
            var selected = 7
            var cards = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
            assertThrows(IllegalStateException::class.java) {
                SelectedSimSigning.sign(7, { selected }, { cards }) {
                    when (mutation) {
                        0 -> selected = 8
                        1 -> cards = listOf(ActiveSimCard(7, 44), ActiveSimCard(8, 43))
                        2 -> cards = listOf(ActiveSimCard(8, 43))
                        3 -> cards = listOf(ActiveSimCard(7, 42, true), ActiveSimCard(8, 43))
                        else -> cards = listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 42))
                    }
                    byteArrayOf(1)
                }
            }
        }
    }

    @Test fun selectionChangeInsideFinalObservationCannotPublishSignature() {
        var selected = 7
        var observations = 0
        assertThrows(IllegalStateException::class.java) {
            SelectedSimSigning.sign(7, { selected }, {
                observations++
                if (observations == 2) selected = 8
                listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
            }) { byteArrayOf(1) }
        }
        assertEquals(2, observations)
    }

    @Test fun selectionChangeInsideInitialObservationNeverInvokesKeyOperation() {
        var selected = 7
        var operations = 0
        assertThrows(IllegalStateException::class.java) {
            SelectedSimSigning.sign(7, { selected }, {
                selected = 8
                listOf(ActiveSimCard(7, 42), ActiveSimCard(8, 43))
            }) { operations++; byteArrayOf(1) }
        }
        assertEquals(0, operations)
    }
    @Test fun selectedProfileSigningNeverFallsBackToPeerAndCallbackRetiresSignature() {
        EsimProfileFixture().use { f ->
            assertArrayEquals(byteArrayOf(1), SelectedSimSigning.sign(7, { 7 }, f::cards) { byteArrayOf(1) })
            assertThrows(IllegalStateException::class.java) {
                SelectedSimSigning.sign(7, { 7 }, f::cards) {
                    f.tracker.onSubscriptionsChanged(); byteArrayOf(1)
                }
            }
        }
    }
    @Test fun publicCopyOfObservedCardCannotCarryItsOpaqueCapability() {
        EsimProfileFixture().use { f ->
            val original = f.cards()
            org.junit.Assert.assertNotNull(SimCardContinuity.activationCandidate(original, 7))
            org.junit.Assert.assertNull(SimCardContinuity.activationCandidate(original.map { it.copy() }, 7))
        }
    }

    @Test fun profileSelectionLabelsDistinguishSharedSlotAndNameWhilePhysicalLabelIsUnchanged() {
        assertEquals("SIM 1: synthetic carrier", selectedSimLabel(7, 0, "synthetic carrier", false, null))
        org.junit.Assert.assertNotEquals(selectedSimLabel(7, 0, "synthetic carrier", true, 0),
            selectedSimLabel(8, 0, "synthetic carrier", true, 1))
        org.junit.Assert.assertTrue(selectedSimLabel(7, 0, "synthetic carrier", true, null).contains("unavailable"))
    }

}
