// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.Executor

/** Worker-only domain adapter. sample must revalidate authority/lease, not replay an active cache.
 * approve consumes the exact current review and completes acceptance/install through recovery policy.
 * decline preserves pairing and never implicitly grants content consent.
 */
internal interface ConversationPresentationDomain {
    fun sample(): ConversationPresentationSnapshot
    fun approve(review: ConversationPhoneReview, stillCurrent: () -> Boolean)
    fun decline(review: ConversationPhoneReview)
    /** Synchronous memory-only shared admission closure; must succeed before stop is queued. */
    fun disableAdmission()
    fun stop(intervalId: String): ConversationPresentationSnapshot
    fun stop(intervalId: String, reason: ConversationStopReason): ConversationPresentationSnapshot = stop(intervalId)
    fun stopForLifecycle(reason: ConversationStopReason): ConversationPresentationSnapshot {
        disableAdmission()
        return ConversationPresentationSnapshot(1, ConversationPresentationPhase.FAILURE,
            close = ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,
            failure = ConversationPresentationFailure.AUTHORITY_UNAVAILABLE, stopReason = reason)
    }
}

/** Unmounted runtime. Worker MUST be a serial executor; delivery MUST dispatch to the UI executor.
 * No Room/network operation runs on the caller. Every mutation uses the exact observed version.
 */
internal class ConversationPresentationRuntime(
    private val worker: Executor, private val delivery: Executor, private val domain: ConversationPresentationDomain
) : ConversationPresentationPort {
    private val listeners = linkedSetOf<(ConversationPresentationSnapshot) -> Unit>()
    private val notifications = java.util.concurrent.ConcurrentLinkedQueue<Pair<(ConversationPresentationSnapshot) -> Unit, ConversationPresentationSnapshot>>()
    private var last = ConversationPresentationSnapshot(1, ConversationPresentationPhase.UNAVAILABLE)
    private var stopping = false
    override fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable {
        val value = synchronized(this) { listeners.add(listener); last }
        deliver(listener, value)
        return AutoCloseable { synchronized(this) { listeners.remove(listener) } }
    }
    private fun deliver(listener: (ConversationPresentationSnapshot) -> Unit, value: ConversationPresentationSnapshot) {
        // Notification rejection must never interrupt the durable worker queue.
        runCatching { delivery.execute {
            val allowed = synchronized(this) {
                listener in listeners && value.version == last.version && !(stopping && value.canStop)
            }
            if (allowed) runCatching { listener(value) }
        } }
    }
    @Synchronized private fun publish(value: ConversationPresentationSnapshot) {
        last = value.copy(version = Math.addExact(last.version, 1))
        listeners.toList().forEach { notifications.add(it to last) }
    }
    private fun flush() { while (true) { val next = notifications.poll() ?: return; deliver(next.first,next.second) } }
    private fun failed(closing: Boolean = synchronized(this) { stopping }, reason: ConversationStopReason? = null) {
        domain.disableAdmission()
        synchronized(this) {
            publish(ConversationPresentationSnapshot(1, ConversationPresentationPhase.FAILURE,
                last.intervalId,last.lineId,last.lineGeneration,
                canStop = !closing && !stopping && last.close != ConversationCloseOutcome.DISABLED_CLOSURE_FAILED && last.intervalId != null,
                close = if (closing) ConversationCloseOutcome.DISABLED_CLOSURE_FAILED else last.close?.takeIf { it == ConversationCloseOutcome.DISABLED_CLOSURE_FAILED },
                failure = ConversationPresentationFailure.AUTHORITY_UNAVAILABLE, stopReason = reason ?: last.stopReason))
        }
    }
    private fun enqueue(closing: Boolean = false, reason: ConversationStopReason? = null, action: Runnable) {
        try { worker.execute(action) } catch (_: Exception) { submissionFailed(closing, reason) }
    }
    /** Memory-only failure publication is safe even when no worker can accept a closure.
     * A failed unrelated submission must not release another pending closure's cancellation latch.
     */
    fun submissionFailed(closing: Boolean = false, reason: ConversationStopReason? = null) {
        failed(closing || synchronized(this) { stopping }, reason)
        if (closing) synchronized(this) { stopping = false }
        flush()
    }
    override fun refresh() { enqueue {
        try {
            val version = synchronized(this) { if (stopping) return@enqueue; last.version }
            val sampled = domain.sample()
            synchronized(this) { if (!stopping && last.version == version) publish(sampled) }
        } catch (_: Exception) { failed() } finally { flush() }
    } }
    private fun reviewAction(requestId: String, version: Long, approve: Boolean) { enqueue {
        try {
            val expected = synchronized(this) {
                if (stopping || last.version != version || last.review?.requestId != requestId) return@enqueue
                checkNotNull(last.review)
            }
            val current = domain.sample()
            val decisionVersion = synchronized(this) {
                if (stopping || last.version != version) return@enqueue
                if (current.review?.copy(remainingMs = expected.remainingMs) != expected) { publish(current); return@enqueue }
                publish(ConversationPresentationSnapshot(1, ConversationPresentationPhase.PREPARING,
                    expected.intervalId, expected.lineId, expected.lineGeneration, canStop = true))
                last.version
            }
            flush() // Expose cancellable Preparing before the acceptance/install wait.
            val currentDecision = { synchronized(this) { !stopping && last.version == decisionVersion } }
            // Domain must check this under the shared admission gate at installation commit.
            if (approve) domain.approve(expected, currentDecision) else domain.decline(expected)
            val sampled = domain.sample()
            synchronized(this) { if (currentDecision()) publish(sampled) }
        } catch (_: Exception) { if (synchronized(this) { !stopping }) failed() } finally { flush() }
    } }
    override fun approvePhoneReview(requestId: String, observedVersion: Long) = reviewAction(requestId, observedVersion, true)
    override fun declinePhoneReview(requestId: String, observedVersion: Long) = reviewAction(requestId, observedVersion, false)
    override fun requestStop(intervalId: String, observedVersion: Long) = requestStop(intervalId, observedVersion, ConversationStopReason.USER_STOP)
    /** Same cancellation/gate fence as user Stop; no presentation port change. */
    fun lifecycleStop(reason: ConversationStopReason) {
        synchronized(this) {
            if (stopping) return
            stopping = true // Lifecycle cancellation has no stale UI-version precondition.
            publish(ConversationPresentationSnapshot(1, ConversationPresentationPhase.PAUSING,
                last.intervalId, last.lineId, last.lineGeneration,
                close = ConversationCloseOutcome.IN_PROGRESS, stopReason = reason))
        }
        domain.disableAdmission()
        flush()
        enqueue(closing = true, reason = reason) {
            try { publish(domain.stopForLifecycle(reason)) } catch (_: Exception) { failed() }
            finally { synchronized(this) { stopping = false }; flush() }
        }
    }
    private fun requestStop(intervalId: String, observedVersion: Long, reason: ConversationStopReason) {
        synchronized(this) {
            if (stopping || last.version != observedVersion || last.intervalId != intervalId || !last.canStop) return
            stopping = true // Cancel install before waiting for the shared admission monitor.
        }
        domain.disableAdmission() // No runtime monitor: installation may check its decision under admission.
        synchronized(this) {
            publish(ConversationPresentationSnapshot(1, ConversationPresentationPhase.PAUSING,
                intervalId, last.lineId, last.lineGeneration, close = ConversationCloseOutcome.IN_PROGRESS,
                stopReason = reason))
        }
        flush()
        enqueue(closing = true, reason = reason) {
            try { publish(domain.stop(intervalId, reason)) } catch (_: Exception) { failed() }
            finally { synchronized(this) { stopping = false }; flush() }
        }
    }
}
