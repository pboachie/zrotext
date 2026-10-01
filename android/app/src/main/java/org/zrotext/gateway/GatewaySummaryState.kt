// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.util.UUID

internal data class GatewaySummaryCount(val value: Long, val capped: Boolean) {
    fun label(): String = if (capped) "$value+ (capped)" else value.toString()
}
internal data class GatewaySummarySnapshot(
    val device: UUID, val dayStartMs: Long, val dayEndMs: Long, val observedMs: Long,
    val submittedToday: GatewaySummaryCount, val pending: GatewaySummaryCount,
    val inFlight: GatewaySummaryCount
) {
    val remainingMs: Long get() = minOf(30_000L, dayEndMs - observedMs)
}
internal object GatewaySummaryParser {
    private const val DAY = 86_400_000L
    private const val MAX_TIME = 8_640_000_000_000_000L
    fun parse(text: String, selectedDevice: UUID): GatewaySummarySnapshot {
        require(selectedDevice != UUID(0, 0)) { "Invalid summary device" }
        val body = JSONObject(text)
        fields(body, setOf("scope", "device_id", "timezone", "day_start_ms", "day_end_ms",
            "observed_at_ms", "max_age_ms", "count_bound", "submitted_today", "pending", "in_flight"))
        require(body.get("scope") == "device" && body.get("device_id") == selectedDevice.toString() &&
            body.get("timezone") == "UTC") { "Summary scope mismatch" }
        require(integer(body, "max_age_ms") == 30_000L && integer(body, "count_bound") == 1_000L) { "Invalid summary bounds" }
        val start = integer(body, "day_start_ms")
        val end = integer(body, "day_end_ms")
        val observed = integer(body, "observed_at_ms")
        require(start in 0..MAX_TIME && end in 0..MAX_TIME && observed in start until end &&
            end - start == DAY && start % DAY == 0L) { "Invalid UTC summary interval" }
        return GatewaySummarySnapshot(selectedDevice, start, end, observed,
            count(body.getJSONObject("submitted_today")), count(body.getJSONObject("pending")), count(body.getJSONObject("in_flight")))
    }
    private fun count(body: JSONObject): GatewaySummaryCount {
        fields(body, setOf("value", "capped"))
        val value = integer(body, "value")
        val capped = body.get("capped")
        require(value in 0..1_000 && capped is Boolean && (!capped || value == 1_000L)) { "Invalid summary count" }
        return GatewaySummaryCount(value, capped)
    }
    private fun integer(body: JSONObject, name: String): Long {
        val value = body.get(name)
        require(value is Int || value is Long) { "Invalid summary integer" }
        return (value as Number).toLong()
    }
    private fun fields(body: JSONObject, expected: Set<String>) {
        require(body.keys().asSequence().toSet() == expected) { "Invalid summary fields" }
    }
}

/** Local display state only, never read or send authority. Tickets contain no credential. */
internal class GatewaySummaryState {
    enum class Phase { UNAVAILABLE, LOADING, FRESH, STALE }
    data class View(val phase: Phase, val snapshot: GatewaySummarySnapshot?, val freshForMs: Long = 0)
    class Ticket internal constructor(internal val generation: Long, internal val device: UUID,
        internal val startedElapsedMs: Long, internal val startedWallMs: Long)
    private var generation = 0L
    private var device: UUID? = null
    private var active = false
    private var pending: Ticket? = null
    private var snapshot: GatewaySummarySnapshot? = null
    private var accepted: Ticket? = null
    private var expired = false

    @Synchronized fun select(selected: UUID?) {
        require(selected != UUID(0, 0)) { "Invalid summary device" }
        generation++
        device = selected
        pending = null
        snapshot = null
        accepted = null
        expired = false
    }
    @Synchronized fun resume() { active = true }
    @Synchronized fun pause() {
        active = false
        generation++
        pending = null
        if (snapshot != null) expired = true
    }
    @Synchronized fun clear() { pause(); select(null) }
    @Synchronized fun begin(elapsedMs: Long, wallMs: Long): Ticket? {
        val selected = device ?: return null
        if (!active || pending != null) return null
        require(elapsedMs >= 0 && wallMs >= 0) { "Invalid summary clock" }
        return Ticket(generation, selected, elapsedMs, wallMs).also { pending = it }
    }
    @Synchronized fun complete(ticket: Ticket, value: GatewaySummarySnapshot): Boolean {
        if (!active || pending !== ticket || ticket.generation != generation || value.device != device) return false
        pending = null
        snapshot = value
        accepted = ticket
        expired = false
        return true
    }
    @Synchronized fun fail(ticket: Ticket): Boolean {
        if (pending !== ticket || ticket.generation != generation) return false
        pending = null
        if (snapshot != null) expired = true
        return true
    }
    @Synchronized fun view(elapsedMs: Long, wallMs: Long): View {
        val value = snapshot
        val timing = accepted
        if (value != null && timing != null) {
            // Includes request latency and suspended time. Clock rollback never
            // restores an expired observation, even after a later resume.
            val elapsed = maxOf(0L, elapsedMs - timing.startedElapsedMs, wallMs - timing.startedWallMs)
            expired = expired || elapsed >= value.remainingMs || elapsedMs < timing.startedElapsedMs
        }
        val remaining = if (value != null && timing != null && !expired && active)
            maxOf(0L, value.remainingMs - maxOf(0L, elapsedMs - timing.startedElapsedMs, wallMs - timing.startedWallMs)) else 0L
        return View(if (pending != null) Phase.LOADING else if (value == null) Phase.UNAVAILABLE
            else if (expired || !active) Phase.STALE else Phase.FRESH, value, remaining)
    }
}
