// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.EOFException
import java.io.IOException
import java.net.SocketException
import java.security.cert.CertificateException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLProtocolException
import kotlin.math.min

/** One visible foreground run. A process restart never restores this state. */
internal class DeviceReconnectPolicy(private val jitter: () -> Double) {
    enum class PilotMode { HEARTBEAT_ONLY, ALPHA_ONCE, INBOUND_UPLOAD, LINE_OPT_OUT_UPLOAD }

    sealed interface Action {
        data class Connect(val pilotMode: PilotMode) : Action
        data class RetryAfter(val milliseconds: Long) : Action
        data object WaitForNetwork : Action
        data object NoChange : Action
        data object Stop : Action
    }

    enum class Loss { TRANSPORT, ACTIVE_CLOSE, AUTH_REJECTED, PROTOCOL_REJECTED,
        EVIDENCE_QUARANTINED, EVIDENCE_QUARANTINE_FAILED }

    private var running = false
    private var networkAvailable = false
    private var connected = false
    private var authenticatedAtMs: Long? = null
    private var failures = 0
    private var closingEvidenceId: String? = null
    private var closingEvidenceCount = 0

    fun start(hasNetwork: Boolean, pilotMode: PilotMode = PilotMode.HEARTBEAT_ONLY): Action {
        running = true
        networkAvailable = hasNetwork
        connected = hasNetwork
        authenticatedAtMs = null
        failures = 0
        clearEvidenceCloseStreak()
        return if (hasNetwork) Action.Connect(pilotMode) else Action.WaitForNetwork
    }

    fun authenticated(nowMs: Long) {
        check(running && connected)
        authenticatedAtMs = nowMs
    }

    /** An old writer without typed closes gets three immediate closes for one row. */
    @Synchronized
    fun recordEvidenceClose(eventKey: String, typed: Boolean): Boolean {
        require(eventKey.isNotBlank())
        if (typed) return true
        if (closingEvidenceId == eventKey) closingEvidenceCount += 1 else {
            closingEvidenceId = eventKey
            closingEvidenceCount = 1
        }
        return closingEvidenceCount >= 3
    }

    @Synchronized
    fun clearEvidenceCloseStreak() {
        closingEvidenceId = null
        closingEvidenceCount = 0
    }

    fun networkChanged(available: Boolean): Action {
        if (networkAvailable == available) return Action.NoChange
        networkAvailable = available
        if (!running) return Action.Stop
        if (!available) {
            connected = false
            authenticatedAtMs = null
            return Action.WaitForNetwork
        }
        if (connected) return Action.NoChange
        connected = true
        return Action.Connect(PilotMode.HEARTBEAT_ONLY)
    }

    fun lost(reason: Loss, nowMs: Long): Action {
        if (!running || !connected) return Action.NoChange
        connected = false
        val authenticatedAt = authenticatedAtMs
        authenticatedAtMs = null
        if (reason == Loss.AUTH_REJECTED || reason == Loss.PROTOCOL_REJECTED ||
            reason == Loss.EVIDENCE_QUARANTINE_FAILED ||
            (reason == Loss.ACTIVE_CLOSE && authenticatedAt == null)) {
            running = false
            return Action.Stop
        }
        if (!networkAvailable) return Action.WaitForNetwork
        if (authenticatedAt != null && nowMs - authenticatedAt >= STABLE_SESSION_MS) failures = 0
        val base = min(MAX_DELAY_MS, BASE_DELAY_MS shl min(failures, 6))
        failures = min(failures + 1, 7)
        val boundedJitter = jitter().coerceIn(0.0, 1.0)
        return Action.RetryAfter(min(MAX_DELAY_MS, (base * (0.8 + boundedJitter * 0.4)).toLong()))
    }

    fun retryDue(): Action {
        if (!running) return Action.Stop
        if (!networkAvailable) return Action.WaitForNetwork
        if (connected) return Action.NoChange
        connected = true
        return Action.Connect(PilotMode.HEARTBEAT_ONLY)
    }

    fun pause() {
        running = false
        connected = false
        authenticatedAtMs = null
        clearEvidenceCloseStreak()
    }

    companion object {
        const val BASE_DELAY_MS = 1_000L
        const val MAX_DELAY_MS = 60_000L
        const val STABLE_SESSION_MS = 120_000L
    }
}

/** A broken TLS stream is retryable; an untrusted peer or invalid protocol is not. */
internal object DeviceDisconnectClassifier {
    fun closed(code: Int, authenticated: Boolean): DeviceReconnectPolicy.Loss = when {
        code in listOf(1011, 1012, 1013) -> DeviceReconnectPolicy.Loss.TRANSPORT
        authenticated && code in listOf(1000, 1001, 1005, 1006) ->
            DeviceReconnectPolicy.Loss.ACTIVE_CLOSE
        else -> DeviceReconnectPolicy.Loss.AUTH_REJECTED
    }

    fun failed(error: Throwable, httpStatus: Int?): DeviceReconnectPolicy.Loss {
        val causes = generateSequence(error as Throwable?) { it.cause }.toList()
        val trustOrProtocolFailure = causes.any { it is SSLPeerUnverifiedException ||
            it is SSLProtocolException || it is CertificateException }
        val truncatedHandshake = causes.any { it is SSLHandshakeException } &&
            causes.any { it is EOFException || it is SocketException }
        val unexplainedHandshake = causes.any { it is SSLHandshakeException } && !truncatedHandshake
        return if (error is IOException && !trustOrProtocolFailure &&
            !unexplainedHandshake &&
            (httpStatus == null || httpStatus >= 500))
            DeviceReconnectPolicy.Loss.TRANSPORT
        else DeviceReconnectPolicy.Loss.AUTH_REJECTED
    }
}
