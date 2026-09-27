// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Android-reported service state, never SMS readiness or dispatch authority. */
internal enum class NetworkService(val wire: String) {
    IN_SERVICE("in_service"), OUT_OF_SERVICE("out_of_service"),
    EMERGENCY_ONLY("emergency_only"), POWER_OFF("power_off"), UNAVAILABLE("unavailable");

    companion object {
        // Android ServiceState constants, kept pure for exhaustive JVM regression tests.
        fun fromPlatform(state: Int): NetworkService = when (state) {
            0 -> IN_SERVICE
            1 -> OUT_OF_SERVICE
            2 -> EMERGENCY_ONLY
            3 -> POWER_OFF
            else -> UNAVAILABLE
        }
    }
}

/** A one-shot observation cannot outlive its subscription or monotonic deadline. */
internal class NetworkServiceCapture(private val selected: Int, private val startedMs: Long) {
    private var completed = false
    fun complete(current: Int?, nowMs: Long, value: NetworkService): NetworkService? {
        if (completed) return null
        completed = true
        return if (current == selected && startedMs >= 0 && nowMs >= startedMs &&
            nowMs - startedMs <= MAX_CAPTURE_MS) value else NetworkService.UNAVAILABLE
    }
    fun cancel() { completed = true }
    companion object { const val MAX_CAPTURE_MS = 5_000L }
}
