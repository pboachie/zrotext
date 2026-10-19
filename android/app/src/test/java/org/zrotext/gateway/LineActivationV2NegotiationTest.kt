// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.*
import org.junit.Test

class LineActivationV2NegotiationTest {
    @Test fun oneCompositeSelectsExactlyOneImplementationTuple() {
        val offered = LineActivationV2Negotiation.offer(true, true)
        assertEquals(LineActivationV2Negotiation.Selection(DeviceStatusPublisher.PROTOCOL_V2, true, 2),
            LineActivationV2Negotiation.select(LineActivationV2Negotiation.SEALED_STATUS_LINE, offered))
        assertEquals(LineActivationV2Negotiation.Selection(DeviceStatusPublisher.PROTOCOL_V2, false, 2),
            LineActivationV2Negotiation.select(LineActivationV2Negotiation.STATUS_LINE, offered))
    }
    @Test fun legacySelectionCannotInheritV2FromOtherOfferedTokens() {
        val offered = LineActivationV2Negotiation.offer(true, true)
        for (token in listOf(DeviceStatusPublisher.PROTOCOL, DeviceStatusPublisher.PROTOCOL_V2, SealedSocketTime.PROTOCOL))
            assertEquals(1, LineActivationV2Negotiation.select(token, offered).lineVersion)
        assertEquals(LineActivationV2Negotiation.Selection(null, false, 1), LineActivationV2Negotiation.select(null, offered))
    }
    @Test fun uninstalledOrUnofferedCompositeIsRefused() {
        val offered = LineActivationV2Negotiation.offer(false, true)
        assertFalse(offered.contains(LineActivationV2Negotiation.STATUS_LINE))
        assertFalse(offered.contains(LineActivationV2Negotiation.SEALED_STATUS_LINE))
        for (token in listOf(LineActivationV2Negotiation.STATUS_LINE, "", "unknown", "${DeviceStatusPublisher.PROTOCOL_V2}, ${LineActivationV2Negotiation.STATUS_LINE}"))
            assertThrows(IllegalArgumentException::class.java) { LineActivationV2Negotiation.select(token, offered) }
    }
    @Test fun lineCompositeDoesNotMountAnUnofferedSealedConsumer() {
        val offered = LineActivationV2Negotiation.offer(true, false)
        assertFalse(offered.contains(LineActivationV2Negotiation.SEALED_STATUS_LINE))
        assertFalse(LineActivationV2Negotiation.select(LineActivationV2Negotiation.STATUS_LINE, offered).sealed)
    }
    @Test fun profile03AdvertisesOnlyWithActualCompleteV2ConsumerAndKeepsOldTuplesSeparate() {
        assertThrows(IllegalArgumentException::class.java) { LineActivationV2Negotiation.offer(false, true, true) }
        val offered = LineActivationV2Negotiation.offer(true, true, true)
        assertEquals(Profile03SessionTime.PROTOCOL, offered.first())
        val selected = LineActivationV2Negotiation.select(Profile03SessionTime.PROTOCOL, offered)
        assertEquals(2, selected.lineVersion); assertEquals(3, selected.sealedVersion)
        assertEquals(2, LineActivationV2Negotiation.select(SealedSocketTime.PROTOCOL, offered).sealedVersion)
        assertEquals(1, LineActivationV2Negotiation.select(SealedSocketTime.PROTOCOL, offered).lineVersion)
        assertThrows(IllegalArgumentException::class.java) {
            LineActivationV2Negotiation.select(Profile03SessionTime.PROTOCOL, LineActivationV2Negotiation.offer(true, true))
        }
        assertFalse(LineActivationV2Negotiation.offer(true, true).contains(Profile03SessionTime.PROTOCOL))
    }
}
