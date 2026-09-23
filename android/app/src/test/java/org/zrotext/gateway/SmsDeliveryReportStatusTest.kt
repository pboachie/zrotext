// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Test

class SmsDeliveryReportStatusTest {
    @Test fun receivedStatusMustMatchItsPduFormat() {
        assertEquals(DeliveryStatus.RECEIVED, SmsDeliveryReportStatus.classify("3gpp", 0))
        assertEquals(DeliveryStatus.RECEIVED, SmsDeliveryReportStatus.classify("3gpp2", 2 shl 16))
        assertEquals(DeliveryStatus.UNVERIFIED, SmsDeliveryReportStatus.classify("3gpp2", 0))
        assertEquals(DeliveryStatus.UNVERIFIED, SmsDeliveryReportStatus.classify("3gpp", 2 shl 16))
    }

    @Test fun failureRangeIsOnlyInterpretedForGsm() {
        assertEquals(DeliveryStatus.FAILED, SmsDeliveryReportStatus.classify("3gpp", 64))
        assertEquals(DeliveryStatus.UNVERIFIED, SmsDeliveryReportStatus.classify("3gpp2", 64))
        assertEquals(DeliveryStatus.UNVERIFIED, SmsDeliveryReportStatus.classify(null, 0))
    }
}
