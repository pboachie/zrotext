// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PhysicalSimBaselineTest {
    @Test fun absentBaselineIsTheOnlySkippableState() {
        assertEquals(PhysicalSimBaseline.Absent, PhysicalSimBaseline.parse(null, null))
    }

    @Test fun validBaselineIsAnActivatableCard() {
        assertEquals(PhysicalSimBaseline.Valid(ActivatedSimCard(7, 0)),
            PhysicalSimBaseline.parse("7", "0"))
        assertEquals(PhysicalSimBaseline.Valid(ActivatedSimCard(0, 42)),
            PhysicalSimBaseline.parse("0", "42"))
    }

    @Test fun negativeUnsupportedOrUninitializedValuesAreInvalid() {
        for ((sub, card) in listOf("7" to "-1", "7" to "-2", "-1" to "3", "-1" to "-1")) {
            assertTrue("$sub/$card", PhysicalSimBaseline.parse(sub, card) is PhysicalSimBaseline.Invalid)
        }
    }

    @Test fun malformedOrPartialValuesAreInvalidNotSkipped() {
        val cases = listOf("7" to null, null to "3", "" to "3", "7" to "", " 7" to "3",
            "7" to "3 ", "+7" to "3", "7.0" to "3", "0x7" to "3", "seven" to "3",
            "7" to "99999999999", "1234567890" to "3")
        for ((sub, card) in cases) {
            assertTrue("$sub/$card", PhysicalSimBaseline.parse(sub, card) is PhysicalSimBaseline.Invalid)
        }
    }

    /** A card ID the app never activates would make every refusal check pass vacuously. */
    @Test fun invalidCardWouldRefuseEvenTheUnchangedSimSoItMustNotBeAccepted() {
        val unchanged = listOf(ActiveSimCard(7, 0))
        assertFalse(SimCardContinuity.matches(ActivatedSimCard(7, -1), unchanged))
        assertTrue(PhysicalSimBaseline.parse("7", "-1") is PhysicalSimBaseline.Invalid)
        val valid = PhysicalSimBaseline.parse("7", "0") as PhysicalSimBaseline.Valid
        assertTrue(SimCardContinuity.matches(valid.card, unchanged))
    }
}
