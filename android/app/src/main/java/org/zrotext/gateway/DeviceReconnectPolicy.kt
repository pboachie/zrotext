// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import kotlin.math.min

/** One visible foreground run. A process restart never restores this state. */
internal class DeviceReconnectPolicy(private val jitter: () -> Double) {
    enum class PilotMode { HEARTBEAT_ONLY, ALPHA_ONCE, INBOUND_UPLOAD }

    sealed interface Action {
        data class Connect(val pilotMode: PilotMode) : Action
        data class RetryAfter(val milliseconds: Long) : Action
        data object WaitForNetwork : Action
        data object NoChange : Action
        data object Stop : Action
    }

    enum class Loss { TRANSPORT, ACTIVE_CLOSE, AUTH_REJECTED, PROTOCOL_REJECTED }

    private var running = false
    private var networkAvailable = false
    private var connected = false
    private var authenticatedAtMs: Long? = null
    private var failures = 0

    fun start(hasNetwork: Boolean, pilotMode: PilotMode = PilotMode.HEARTBEAT_ONLY): Action {
        running = true
        networkAvailable = hasNetwork
        connected = hasNetwork
        authenticatedAtMs = null
        failures = 0
        return if (hasNetwork) Action.Connect(pilotMode) else Action.WaitForNetwork
    }

    fun authenticated(nowMs: Long) {
        check(running && connected)
        authenticatedAtMs = nowMs
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
    }

    companion object {
        const val BASE_DELAY_MS = 1_000L
        const val MAX_DELAY_MS = 60_000L
        const val STABLE_SESSION_MS = 120_000L
    }
}
