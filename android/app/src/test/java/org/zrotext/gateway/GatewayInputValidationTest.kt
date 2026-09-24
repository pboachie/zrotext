// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class GatewayInputValidationTest {
    @Test fun malformedOrNonWssTestEndpointsCannotReachTheSocketBuilder() {
        assertTrue(GatewayInputValidation.testEndpoint("wss://localhost:8443/m0/device-test"))
        for (candidate in listOf("", "wss://%", "wss://", "wss://localhost:70000/",
            "https://localhost:8443/m0/device-test", "wss://user@localhost/test",
            "wss://localhost/test#fragment")) {
            assertFalse(candidate, GatewayInputValidation.testEndpoint(candidate))
        }
    }

    @Test fun approvedDeviceIdMustUseCanonicalLowercaseUuid() {
        val id = UUID.fromString("00000000-0000-0000-0000-00000000000a")
        assertEquals(id, GatewayInputValidation.deviceId(id.toString()))
        assertNull(GatewayInputValidation.deviceId(id.toString().uppercase()))
        assertNull(GatewayInputValidation.deviceId("not-a-uuid"))
    }
}
