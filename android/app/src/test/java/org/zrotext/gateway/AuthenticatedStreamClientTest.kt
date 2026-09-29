// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Test

class AuthenticatedStreamClientTest {
    @Test fun authenticatedStreamSendsNoWebSocketPingBesideTheHeartbeat() {
        // A zero interval means OkHttp never sends a protocol ping; the application
        // heartbeat and its 90 s ack watchdog are the only liveness path.
        assertEquals(0, AuthenticatedGatewayService.streamClient().pingIntervalMillis)
    }
}
