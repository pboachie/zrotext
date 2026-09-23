// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceReconnectPolicyTest {
    @Test
    fun transportLossBacksOffWithBoundedJitterAndStableSessionResetsIt() {
        val policy = DeviceReconnectPolicy { 0.0 }
        assertEquals(DeviceReconnectPolicy.Action.Connect, policy.start(true))
        assertEquals(DeviceReconnectPolicy.Action.RetryAfter(800),
            policy.lost(DeviceReconnectPolicy.Loss.TRANSPORT, 0))
        assertEquals(DeviceReconnectPolicy.Action.NoChange, policy.networkChanged(true))
        assertEquals(DeviceReconnectPolicy.Action.Connect, policy.retryDue())
        assertEquals(DeviceReconnectPolicy.Action.RetryAfter(1_600),
            policy.lost(DeviceReconnectPolicy.Loss.TRANSPORT, 1))
        repeat(10) {
            assertEquals(DeviceReconnectPolicy.Action.Connect, policy.retryDue())
            val next = policy.lost(DeviceReconnectPolicy.Loss.TRANSPORT, it.toLong() + 2)
            if (it == 9) assertEquals(DeviceReconnectPolicy.Action.RetryAfter(48_000), next)
        }
        assertEquals(DeviceReconnectPolicy.Action.Connect, policy.retryDue())
        policy.authenticated(10_000)
        assertEquals(DeviceReconnectPolicy.Action.RetryAfter(800),
            policy.lost(DeviceReconnectPolicy.Loss.ACTIVE_CLOSE, 130_000))
    }

    @Test
    fun networkRecoveryRequiresARealTransitionAndNewProof() {
        val policy = DeviceReconnectPolicy { 0.5 }
        assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.start(false))
        assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.retryDue())
        assertEquals(DeviceReconnectPolicy.Action.Connect, policy.networkChanged(true))
        policy.authenticated(0)
        assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.networkChanged(false))
        assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.retryDue())
        assertEquals(DeviceReconnectPolicy.Action.Connect, policy.networkChanged(true))
        assertEquals(DeviceReconnectPolicy.Action.NoChange, policy.networkChanged(true))
    }

    @Test
    fun rejectedProofProtocolAndPauseNeverRetry() {
        for (reason in listOf(DeviceReconnectPolicy.Loss.AUTH_REJECTED,
            DeviceReconnectPolicy.Loss.PROTOCOL_REJECTED)) {
            val policy = DeviceReconnectPolicy { 0.5 }
            policy.start(true)
            assertEquals(DeviceReconnectPolicy.Action.Stop, policy.lost(reason, 0))
            assertEquals(DeviceReconnectPolicy.Action.Stop, policy.retryDue())
            assertEquals(DeviceReconnectPolicy.Action.Stop, policy.networkChanged(false))
        }
        val preSessionClose = DeviceReconnectPolicy { 0.5 }
        preSessionClose.start(true)
        assertEquals(DeviceReconnectPolicy.Action.Stop,
            preSessionClose.lost(DeviceReconnectPolicy.Loss.ACTIVE_CLOSE, 0))
        val paused = DeviceReconnectPolicy { 0.5 }
        paused.start(true)
        paused.pause()
        assertEquals(DeviceReconnectPolicy.Action.Stop, paused.retryDue())
        assertEquals(DeviceReconnectPolicy.Action.Stop, paused.networkChanged(false))
    }

    @Test
    fun activeCloseReauthenticatesOnceButRevokedProofStops() {
        val policy = DeviceReconnectPolicy { 1.0 }
        policy.start(true)
        policy.authenticated(0)
        assertEquals(DeviceReconnectPolicy.Action.RetryAfter(1_200),
            policy.lost(DeviceReconnectPolicy.Loss.ACTIVE_CLOSE, 1))
        assertEquals(DeviceReconnectPolicy.Action.Connect, policy.retryDue())
        assertEquals(DeviceReconnectPolicy.Action.Stop,
            policy.lost(DeviceReconnectPolicy.Loss.AUTH_REJECTED, 2))
        assertEquals(DeviceReconnectPolicy.Action.Stop, policy.retryDue())
    }
}
