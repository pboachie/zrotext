// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.EOFException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException

class DeviceReconnectPolicyTest {
    private val heartbeat = DeviceReconnectPolicy.Action.Connect(DeviceReconnectPolicy.PilotMode.HEARTBEAT_ONLY)

    @Test
    fun transportLossBacksOffWithBoundedJitterAndStableSessionResetsIt() {
        val policy = DeviceReconnectPolicy { 0.0 }
        assertEquals(heartbeat, policy.start(true))
        assertEquals(DeviceReconnectPolicy.Action.RetryAfter(800),
            policy.lost(DeviceReconnectPolicy.Loss.TRANSPORT, 0))
        assertEquals(DeviceReconnectPolicy.Action.NoChange, policy.networkChanged(true))
        assertEquals(heartbeat, policy.retryDue())
        assertEquals(DeviceReconnectPolicy.Action.RetryAfter(1_600),
            policy.lost(DeviceReconnectPolicy.Loss.TRANSPORT, 1))
        repeat(10) {
            assertEquals(heartbeat, policy.retryDue())
            val next = policy.lost(DeviceReconnectPolicy.Loss.TRANSPORT, it.toLong() + 2)
            if (it == 9) assertEquals(DeviceReconnectPolicy.Action.RetryAfter(48_000), next)
        }
        assertEquals(heartbeat, policy.retryDue())
        policy.authenticated(10_000)
        assertEquals(DeviceReconnectPolicy.Action.RetryAfter(800),
            policy.lost(DeviceReconnectPolicy.Loss.ACTIVE_CLOSE, 130_000))
    }

    @Test
    fun networkRecoveryRequiresARealTransitionAndNewProof() {
        val policy = DeviceReconnectPolicy { 0.5 }
        assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.start(false))
        assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.retryDue())
        assertEquals(heartbeat, policy.networkChanged(true))
        policy.authenticated(0)
        assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.networkChanged(false))
        assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.retryDue())
        assertEquals(heartbeat, policy.networkChanged(true))
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
        assertEquals(heartbeat, policy.retryDue())
        assertEquals(DeviceReconnectPolicy.Action.Stop,
            policy.lost(DeviceReconnectPolicy.Loss.AUTH_REJECTED, 2))
        assertEquals(DeviceReconnectPolicy.Action.Stop, policy.retryDue())
    }

    @Test
    fun jitterNeverExtendsRetryBeyondOneMinute() {
        val policy = DeviceReconnectPolicy { 1.0 }
        policy.start(true)
        repeat(10) {
            val delay = policy.lost(DeviceReconnectPolicy.Loss.TRANSPORT, it.toLong())
            if (it == 9) assertEquals(DeviceReconnectPolicy.Action.RetryAfter(60_000), delay)
            policy.retryDue()
        }
    }

    @Test
    fun manualAlphaAndInboundModesAreConsumedBeforeAnyReconnect() {
        for (mode in listOf(DeviceReconnectPolicy.PilotMode.ALPHA_ONCE,
            DeviceReconnectPolicy.PilotMode.INBOUND_UPLOAD)) {
            val policy = DeviceReconnectPolicy { 0.5 }
            assertEquals(DeviceReconnectPolicy.Action.Connect(mode), policy.start(true, mode))
            policy.authenticated(0)
            assertEquals(DeviceReconnectPolicy.Action.RetryAfter(1_000),
                policy.lost(DeviceReconnectPolicy.Loss.TRANSPORT, 1))
            assertEquals(heartbeat, policy.retryDue())
            assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy.networkChanged(false))
            assertEquals(heartbeat, policy.networkChanged(true))

            val offline = DeviceReconnectPolicy { 0.5 }
            assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, offline.start(false, mode))
            assertEquals(heartbeat, offline.networkChanged(true))
        }
    }

    @Test
    fun repeatedImmediateCloseForOneEvidenceRowQuarantinesThenHeartbeatsResume() {
        val policy = DeviceReconnectPolicy { 0.5 }
        policy.start(true, DeviceReconnectPolicy.PilotMode.INBOUND_UPLOAD)
        for (attempt in 1..3) {
            policy.authenticated(attempt.toLong())
            assertEquals(attempt == 3, policy.recordEvidenceClose("inbound:old-event", false))
            val reason = if (attempt == 3) DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINED
                else DeviceReconnectPolicy.Loss.ACTIVE_CLOSE
            assertEquals(DeviceReconnectPolicy.Action.RetryAfter(
                1_000L shl (attempt - 1)), policy.lost(reason, attempt.toLong() + 1))
            assertEquals(heartbeat, policy.retryDue())
        }
        policy.authenticated(10)
        assertEquals(true, policy.recordEvidenceClose("radio:new-event", true))
        assertEquals(DeviceReconnectPolicy.Action.RetryAfter(8_000),
            policy.lost(DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINED, 11))
        assertEquals(heartbeat, policy.retryDue())
        policy.authenticated(12)
        assertEquals(DeviceReconnectPolicy.Action.Stop,
            policy.lost(DeviceReconnectPolicy.Loss.EVIDENCE_QUARANTINE_FAILED, 13))
    }

    @Test
    fun unrelatedClosesDoNotCountTowardAnotherEvidenceRow() {
        val policy = DeviceReconnectPolicy { 0.5 }
        policy.start(true)
        assertEquals(false, policy.recordEvidenceClose("radio:first", false))
        assertEquals(false, policy.recordEvidenceClose("radio:second", false))
        policy.clearEvidenceCloseStreak()
        assertEquals(false, policy.recordEvidenceClose("radio:second", false))
    }
}

class DeviceDisconnectClassifierTest {
    @Test
    fun abruptTlsTruncationAndClosedActiveStreamRetry() {
        assertEquals(DeviceReconnectPolicy.Loss.TRANSPORT,
            DeviceDisconnectClassifier.failed(SSLException("stream truncated"), null))
        assertEquals(DeviceReconnectPolicy.Loss.TRANSPORT,
            DeviceDisconnectClassifier.failed(SSLHandshakeException("connection closed").apply {
                initCause(EOFException())
            }, null))
        assertEquals(DeviceReconnectPolicy.Loss.TRANSPORT,
            DeviceDisconnectClassifier.failed(EOFException(), 503))
        assertEquals(DeviceReconnectPolicy.Loss.ACTIVE_CLOSE,
            DeviceDisconnectClassifier.closed(1005, true))
        assertEquals(DeviceReconnectPolicy.Loss.AUTH_REJECTED,
            DeviceDisconnectClassifier.closed(1005, false))
        for (code in listOf(1011, 1012, 1013)) {
            assertEquals(DeviceReconnectPolicy.Loss.TRANSPORT,
                DeviceDisconnectClassifier.closed(code, false))
            val policy = DeviceReconnectPolicy { 0.5 }
            policy.start(true)
            assertEquals(DeviceReconnectPolicy.Action.RetryAfter(1_000),
                policy.lost(DeviceDisconnectClassifier.closed(code, false), 0))
        }
    }

    @Test
    fun tlsTrustHttpRejectionAndPolicyCloseStop() {
        assertEquals(DeviceReconnectPolicy.Loss.AUTH_REJECTED,
            DeviceDisconnectClassifier.failed(SSLHandshakeException("untrusted peer"), null))
        assertEquals(DeviceReconnectPolicy.Loss.AUTH_REJECTED,
            DeviceDisconnectClassifier.failed(EOFException(), 403))
        assertEquals(DeviceReconnectPolicy.Loss.AUTH_REJECTED,
            DeviceDisconnectClassifier.closed(1008, true))
        assertEquals(DeviceReconnectPolicy.Loss.AUTH_REJECTED,
            DeviceDisconnectClassifier.closed(1008, false))
    }
}
