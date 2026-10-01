// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class GatewayPermissionPurposeTest {
    @Test fun simAndConnectionAccessNeverRequestsSms() {
        for (api in listOf(28, 32, 33, 36)) {
            assertFalse(GatewayPermissionPurpose.SIM.permissions(api).any { it.endsWith("SMS") })
        }
        assertEquals(listOf("android.permission.READ_PHONE_STATE"), GatewayPermissionPurpose.SIM.permissions(32))
        assertEquals(listOf("android.permission.READ_PHONE_STATE", "android.permission.POST_NOTIFICATIONS"), GatewayPermissionPurpose.SIM.permissions(33))
    }

    @Test fun sendingAndReceivingCanBeGrantedIndependently() {
        assertEquals(listOf("android.permission.SEND_SMS"), GatewayPermissionPurpose.SEND.permissions(36))
        assertEquals(listOf("android.permission.RECEIVE_SMS"), GatewayPermissionPurpose.RECEIVE.permissions(36))
    }
}
