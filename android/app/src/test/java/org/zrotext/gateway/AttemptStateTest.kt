// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import org.junit.Assert.assertEquals
import org.junit.Test

class AttemptStateTest {
    private fun segment(index: Int, sent: Int?, delivery: Int? = null, status: Int? = null) =
        SmsSegment("attempt", index, sent, delivery, status)

    @Test fun unresolvedIntentBecomesUnknownOnRestart() {
        val evidence = listOf(segment(0, null), segment(1, null))
        assertEquals(AttemptState.SUBMITTING, AttemptState.fromEvidence(AttemptState.SUBMITTING, evidence))
        assertEquals(AttemptState.UNKNOWN, AttemptState.fromEvidence(AttemptState.UNKNOWN, evidence))
        assertEquals(AttemptState.UNKNOWN, AttemptState.fromEvidence(AttemptState.UNKNOWN,
            listOf(segment(0, Activity.RESULT_OK), segment(1, null))))
        assertEquals(AttemptState.NOT_SUBMITTED,
            AttemptState.fromEvidence(AttemptState.NOT_SUBMITTED, evidence))
    }

    @Test fun segmentCallbacksDistinguishSubmissionDeliveryAndPartialFailure() {
        val ok = Activity.RESULT_OK
        assertEquals(AttemptState.SUBMITTED, AttemptState.fromEvidence(AttemptState.UNKNOWN,
            listOf(segment(0, ok), segment(1, ok))))
        assertEquals(AttemptState.DELIVERED, AttemptState.fromEvidence(AttemptState.SUBMITTED,
            listOf(segment(0, ok, ok, DeliveryStatus.RECEIVED), segment(1, ok, ok, DeliveryStatus.RECEIVED))))
        assertEquals(AttemptState.PARTIAL_FAILURE, AttemptState.fromEvidence(AttemptState.UNKNOWN,
            listOf(segment(0, ok), segment(1, 1))))
        assertEquals(AttemptState.DELIVERY_FAILED, AttemptState.fromEvidence(AttemptState.SUBMITTED,
            listOf(segment(0, ok, ok, DeliveryStatus.RECEIVED), segment(1, ok, ok, DeliveryStatus.FAILED))))
        assertEquals(AttemptState.SUBMITTED, AttemptState.fromEvidence(AttemptState.SUBMITTED,
            listOf(segment(0, ok, ok, DeliveryStatus.UNVERIFIED))))
        assertEquals(AttemptState.UNKNOWN, AttemptState.fromEvidence(AttemptState.UNKNOWN,
            listOf(segment(0, ok, ok, DeliveryStatus.RECEIVED), segment(1, null))))
    }
}
