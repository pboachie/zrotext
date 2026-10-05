// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** One deliberate authenticated receive. This port cannot submit, claim or send SMS. */
internal fun interface ConversationMessageReceiver {
    fun receive(message: String, complete: (Boolean) -> Unit)
}

/** UI authority is sampled from the installed connection, never from the supplied message ID. */
internal class ConversationMessageReceiveController(
    private val current: () -> Current?,
    private val elapsedMillis: () -> Long
) : AutoCloseable {
    internal class Current(
        val connection: Any,
        val accountId: String,
        val deviceId: String,
        val snapshot: ConversationPresentationSnapshot,
        val observedAt: Long,
        val receiver: ConversationMessageReceiver
    ) {
        override fun toString() = "ConversationReceiveAuthority(redacted)"
    }
    internal enum class Outcome { IDLE, RECEIVING, VERIFIED, REFUSED, UNKNOWN, CANCELLED }
    private class Pending(val authority: Current, val deadline: Long, val generation: Long)
    private val gate = Any()
    private var pending: Pending? = null
    private var closed = false
    private var generation = 0L
    private var result = Outcome.IDLE
    val outcome: Outcome get() = synchronized(gate) { result }

    private fun live(value: Current, now: Long): Boolean {
        val snapshot = value.snapshot
        return snapshot.phase == ConversationPresentationPhase.CONFIRMED_ACTIVE && snapshot.canStop &&
            snapshot.intervalId != null && snapshot.lineId != null && snapshot.lineGeneration != null &&
            now >= value.observedAt && now - value.observedAt < snapshot.remainingMs
    }
    private fun same(original: Current, next: Current): Boolean =
        original.connection === next.connection && original.accountId == next.accountId &&
            original.deviceId == next.deviceId && original.snapshot.version == next.snapshot.version &&
            original.snapshot.intervalId == next.snapshot.intervalId &&
            original.snapshot.lineId == next.snapshot.lineId &&
            original.snapshot.lineGeneration == next.snapshot.lineGeneration

    /** No retry or radio fallback. Underlying receive performs the actual live crypto/receipt checks. */
    fun receive(message: String): Boolean {
        val request = synchronized(gate) {
            if (closed || pending != null) return false
            val observedGeneration = generation
            val validId = message.length == 36 && runCatching {
                val id = UUID.fromString(message)
                id != UUID(0, 0) && id.toString() == message
            }.getOrDefault(false)
            val authority = runCatching(current).getOrNull()
            val now = runCatching(elapsedMillis).getOrNull()
            if (closed || generation != observedGeneration || pending != null) return false
            if (!validId || authority == null || now == null || !live(authority, now)) {
                result = Outcome.REFUSED
                return false
            }
            val deadline = runCatching { Math.addExact(authority.observedAt, authority.snapshot.remainingMs) }.getOrNull()
            if (deadline == null) { result = Outcome.REFUSED; return false }
            Pending(authority, deadline, observedGeneration).also { pending = it; result = Outcome.RECEIVING }
        }
        try {
            val authority = runCatching(current).getOrNull()
            val now = elapsedMillis()
            if (authority == null || !same(request.authority, authority) || !live(authority, now) || now >= request.deadline) {
                finish(request, false)
                return false
            }
            synchronized(gate) { if (closed || generation != request.generation || pending !== request) return false }
            request.authority.receiver.receive(message) { accepted -> finish(request, accepted) }
        } catch (_: Exception) { finish(request, false) }
        return true
    }

    private fun finish(request: Pending, accepted: Boolean) = synchronized(gate) {
        if (closed || pending !== request) return@synchronized
        val authority = runCatching(current).getOrNull()
        val now = runCatching(elapsedMillis).getOrNull()
        if (closed || generation != request.generation || pending !== request) return@synchronized
        pending = null
        result = if (authority == null || now == null || !same(request.authority, authority) ||
            !live(authority, now) || now >= request.deadline) Outcome.CANCELLED
        else if (accepted) Outcome.VERIFIED else Outcome.UNKNOWN
    }

    /** Navigation/Stop invalidates UI completion; it does not undo an already committed receipt. */
    fun cancel() = synchronized(gate) { generation++; pending = null; result = Outcome.CANCELLED }
    override fun close() = synchronized(gate) { closed = true; generation++; pending = null; result = Outcome.CANCELLED }
    override fun toString() = "ConversationMessageReceiveController(redacted)"
}
