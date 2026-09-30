// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Test

class GatewayConnectionMoodTest {
    @Test fun onlyKnownAuthenticatedObservationsGetConnectedTreatment() {
        assertEquals(GatewayConnectionMood.CONNECTED, GatewayConnectionMood.from("Authenticated heartbeat only"))
        assertEquals(GatewayConnectionMood.CONNECTED, GatewayConnectionMood.from("Inbound metadata pilot active"))
        for (status in listOf("Unknown", "Alpha arm refused", "Heartbeat running; reboot resume unavailable",
            "Authenticated heartbeat; older device evidence quarantined", "Server unavailable; retrying device proof")) {
            assertEquals(status, GatewayConnectionMood.ATTENTION, GatewayConnectionMood.from(status))
        }
    }

    @Test fun pausedOfflineAndProofStatesStayDistinct() {
        assertEquals(GatewayConnectionMood.PAUSED, GatewayConnectionMood.from("Paused"))
        assertEquals(GatewayConnectionMood.OFFLINE, GatewayConnectionMood.from("Disconnected; waiting for network"))
        assertEquals(GatewayConnectionMood.CONNECTING, GatewayConnectionMood.from("Proving enrolled device key"))
    }
}
