// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/**
 * Operator-supplied reference card for the physical-SIM reboot, swap and absence device tests.
 *
 * The values must come from the `reference expected_sub=... expected_card=...` line that
 * `physicalSimActivatesInstallsAndStaysContinuousWithoutRadio` logs on the original card. A
 * baseline the app itself could never have activated (a negative or malformed value) would let a
 * refusal check pass without exercising anything, so it is rejected as [Invalid] and the device
 * test fails instead of skipping. Only a fully absent baseline ([Absent]) is a reason to skip.
 */
internal sealed interface PhysicalSimBaseline {
    object Absent : PhysicalSimBaseline

    data class Invalid(val reason: String) : PhysicalSimBaseline

    data class Valid(val card: ActivatedSimCard) : PhysicalSimBaseline

    companion object {
        private val DECIMAL = Regex("[0-9]{1,9}")

        fun parse(subscription: String?, card: String?): PhysicalSimBaseline {
            if (subscription == null && card == null) return Absent
            if (subscription == null || card == null) {
                return Invalid("expected_sub and expected_card must be supplied together")
            }
            if (!DECIMAL.matches(subscription) || !DECIMAL.matches(card)) {
                return Invalid("expected_sub and expected_card must be nonnegative decimal integers")
            }
            val baseline = ActivatedSimCard(subscription.toInt(), card.toInt())
            // Tie the operator input to the production activation rule: the baseline must be a
            // card the app would activate from a single physical line, or no refusal can be
            // attributed to the card difference.
            val activatable = SimCardContinuity.activationCandidate(
                listOf(ActiveSimCard(baseline.subscriptionId, baseline.cardId)))
            return if (activatable == baseline) Valid(baseline)
            else Invalid("the baseline is not a card the app could have activated")
        }
    }
}
