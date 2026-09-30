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
        delivery.execute {
            val allowed = synchronized(this) {
                listener in listeners && value.version == last.version && !(stopping && value.canStop)
            }
            if (allowed) runCatching { listener(value) }
        }
    }
    @Synchronized private fun publish(value: ConversationPresentationSnapshot) {
        last = value.copy(version = Math.addExact(last.version, 1))
        listeners.toList().forEach { notifications.add(it to last) }
    }
    private fun flush() { while (true) { val next = notifications.poll() ?: return; deliver(next.first,next.second) } }
    private fun failed() {
        domain.disableAdmission()
        synchronized(this) {
            publish(ConversationPresentationSnapshot(1, ConversationPresentationPhase.FAILURE,
                last.intervalId,last.lineId,last.lineGeneration,
                canStop = !stopping && last.intervalId != null,
                close = if (stopping) ConversationCloseOutcome.DISABLED_CLOSURE_FAILED else null,
                failure = ConversationPresentationFailure.AUTHORITY_UNAVAILABLE))
        }
    }
    override fun refresh() { worker.execute {
        try {
            val version = synchronized(this) { if (stopping) return@execute; last.version }
            val sampled = domain.sample()
            synchronized(this) { if (!stopping && last.version == version) publish(sampled) }
        } catch (_: Exception) { failed() } finally { flush() }
    } }
    private fun reviewAction(requestId: String, version: Long, approve: Boolean) { worker.execute {
        try {
            val expected = synchronized(this) {
                if (stopping || last.version != version || last.review?.requestId != requestId) return@execute
                checkNotNull(last.review)
            }
            val current = domain.sample()
            val decisionVersion = synchronized(this) {
                if (stopping || last.version != version) return@execute
                if (current.review?.copy(remainingMs = expected.remainingMs) != expected) { publish(current); return@execute }
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
    override fun requestStop(intervalId: String, observedVersion: Long) {
        synchronized(this) {
            if (stopping || last.version != observedVersion || last.intervalId != intervalId || !last.canStop) return
            stopping = true // Cancel install before waiting for the shared admission monitor.
        }
        domain.disableAdmission() // No runtime monitor: installation may check its decision under admission.
        synchronized(this) {
            publish(ConversationPresentationSnapshot(1, ConversationPresentationPhase.PAUSING,
                intervalId, last.lineId, last.lineGeneration, close = ConversationCloseOutcome.IN_PROGRESS,
                stopReason = ConversationStopReason.USER_STOP))
        }
        flush()
        worker.execute {
            try { publish(domain.stop(intervalId)) } catch (_: Exception) { failed() }
            finally { synchronized(this) { stopping = false }; flush() }
        }
    }
}
