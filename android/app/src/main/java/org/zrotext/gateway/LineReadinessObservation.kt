// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/**
 * ADR 0004 implementation step 3: per-line readiness observations on the
 * phone. Readiness is an observation with source and freshness, never a
 * promise that a phone or carrier can send. Missing, stale or contradictory
 * observations fail closed: a line with no authenticated observation reports
 * not-ready-offline, exactly as the server-side routing decision treats it.
 *
 * The model carries device-local opaque line identifiers only. No SIM slot,
 * subscription identifier, ICCID, IMSI or phone number appears in any field,
 * preimage or log line.
 */
internal enum class LineReadinessKind(val code: Int) {
    /** The line's activation state is pending or revoked. */
    INACTIVE(1),
    /** The approved binding is missing or no longer active. */
    BINDING_NOT_ACTIVE(2),
    /** A card-continuity or re-pairing check is in progress. */
    CONTINUITY_PENDING(3),
    /** The approved binding's card changed; the old identity must not send. */
    CARD_CHANGED(4),
    /** No recent authenticated observation of the line's phone exists. */
    OFFLINE_PAST_THRESHOLD(5),
    /** The latest observations are fresh and none reports a failure. */
    READY(6),
}

internal data class LineReadinessObservation(
    val lineId: UUID,
    val kind: LineReadinessKind,
    /** Milliseconds since the freshest authenticated observation backing this
     * result, or null when no observation exists. The server's per-line
     * offline threshold consumes exactly this value. */
    val sinceObservationMs: Long?,
    val observedAtMs: Long,
) {
    init {
        require(lineId != UUID(0, 0))
        require(observedAtMs > 0)
        require(sinceObservationMs == null || sinceObservationMs >= 0)
        // A READY result must be backed by a fresh observation; a missing
        // observation can never report ready.
        if (kind == LineReadinessKind.READY) require(sinceObservationMs != null)
        if (sinceObservationMs == null) require(kind == LineReadinessKind.OFFLINE_PAST_THRESHOLD)
    }

    /** Stable refusal naming for logs and the future readiness frame. */
    fun code(): String = when (kind) {
        LineReadinessKind.INACTIVE -> "line_not_ready_inactive"
        LineReadinessKind.BINDING_NOT_ACTIVE -> "line_not_ready_binding_not_active"
        LineReadinessKind.CONTINUITY_PENDING -> "line_not_ready_continuity_pending"
        LineReadinessKind.CARD_CHANGED -> "line_not_ready_card_changed"
        LineReadinessKind.OFFLINE_PAST_THRESHOLD -> "line_not_ready_offline"
        LineReadinessKind.READY -> "line_ready"
    }

    /** Local-only canonical preimage for the step-4 readiness frame digest. */
    fun preimage(): ByteArray {
        val domain = "ZT/line/readiness/v1\u0000".toByteArray(Charsets.US_ASCII)
        val absent = sinceObservationMs == null
        val buffer = ByteBuffer.allocate(domain.size + 16 + 1 + 1 + (if (absent) 0 else 8) + 8)
        buffer.put(domain)
        buffer.putLong(lineId.mostSignificantBits)
        buffer.putLong(lineId.leastSignificantBits)
        buffer.put(kind.code.toByte())
        buffer.put(if (absent) 0.toByte() else 1.toByte())
        if (!absent) buffer.putLong(sinceObservationMs!!)
        buffer.putLong(observedAtMs)
        return buffer.array()
    }

    fun digest(): ByteArray = MessageDigest.getInstance("SHA-256").digest(preimage())

    override fun toString() = "LineReadinessObservation(line=redacted, kind=$kind, fresh=${sinceObservationMs != null})"
}

/**
 * Folds raw, independently sourced device events into the per-line
 * observation each heartbeat cycle ships upstream. Every input is
 * device-local; nothing here grants authority — the server's routing
 * decision independently consumes the observation.
 */
internal class LineReadinessStore(private val clock: () -> Long) {

    private class State(
        val lineId: UUID,
        var active: Boolean,
        var bindingActive: Boolean,
        var continuityPending: Boolean,
        var cardChanged: Boolean,
        var lastObservedMs: Long?,
    )

    private val lines = LinkedHashMap<UUID, State>()
    private var registered = false

    /** Registers the known lines. Registering replaces the roster; lines that
     * vanish from the roster stop producing observations instead of inheriting
     * another line's events. */
    fun register(lineIds: Collection<UUID>) {
        require(lineIds.all { it != UUID(0, 0) })
        require(lineIds.size == lineIds.toSet().size)
        val byId = lineIds.associateWith { id ->
            lines[id] ?: State(id, active = true, bindingActive = true,
                continuityPending = false, cardChanged = false, lastObservedMs = null)
        }
        lines.clear()
        for ((id, state) in byId) lines[id] = state
        registered = lineIds.isNotEmpty()
    }

    fun onActivationState(lineId: UUID, active: Boolean) = mutate(lineId) { it.active = active }

    fun onBindingState(lineId: UUID, bindingActive: Boolean) =
        mutate(lineId) { it.bindingActive = bindingActive }

    fun onContinuityCheck(lineId: UUID, pending: Boolean) = mutate(lineId) { it.continuityPending = pending }

    /** A changed card is sticky until the owner re-approves a new binding:
     * un-clearing it locally would invent authority. */
    fun onCardChanged(lineId: UUID) = mutate(lineId) { it.cardChanged = true }

    fun onBindingReapproved(lineId: UUID) = mutate(lineId) {
        it.cardChanged = false
        it.bindingActive = true
    }

    /** An authenticated heartbeat acknowledgment is the freshness source. A
     * non-monotonic timestamp is ignored rather than rolling freshness back. */
    fun onAuthenticatedObservation(lineId: UUID, atMs: Long) = mutate(lineId) {
        if (it.lastObservedMs == null || atMs >= it.lastObservedMs!!) it.lastObservedMs = atMs
    }

    /** Produces the observation for one line at `nowMs`. `offlineThresholdMs`
     * is the owner-configured per-line threshold from the server; the store
     * never picks its own. */
    fun observe(lineId: UUID, nowMs: Long, offlineThresholdMs: Long): LineReadinessObservation {
        require(offlineThresholdMs >= 0)
        val state = lines[lineId]
            ?: throw IllegalArgumentException("line is not registered")
        val since = state.lastObservedMs?.let { (nowMs - it).coerceAtLeast(0) }
        val kind = when {
            !state.active -> LineReadinessKind.INACTIVE
            state.cardChanged -> LineReadinessKind.CARD_CHANGED
            !state.bindingActive -> LineReadinessKind.BINDING_NOT_ACTIVE
            state.continuityPending -> LineReadinessKind.CONTINUITY_PENDING
            since == null || since >= offlineThresholdMs -> LineReadinessKind.OFFLINE_PAST_THRESHOLD
            else -> LineReadinessKind.READY
        }
        return LineReadinessObservation(lineId, kind,
            if (kind == LineReadinessKind.OFFLINE_PAST_THRESHOLD && since == null) null else since, nowMs)
    }

    /** All registered lines' observations, roster order, one per line. */
    fun snapshot(nowMs: Long, offlineThresholdMs: Long): List<LineReadinessObservation> =
        lines.keys.map { observe(it, nowMs, offlineThresholdMs) }

    val isRegistered get() = registered

    private fun mutate(lineId: UUID, block: (State) -> Unit) {
        val state = lines[lineId] ?: throw IllegalArgumentException("line is not registered")
        block(state)
    }
}
