// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** One deliberate, current presentation decision; never persisted or restored on restart. */
internal class ConversationPhoneDecision(
    private val session: ConversationPhoneSession,
    private val scope: ConversationCaptureScope,
    private val review: ConversationPhoneReview,
    observedVersion: Long,
    private val elapsedMillis: () -> Long,
    private val currentSession: () -> ConversationPhoneSession?
) : AutoCloseable {
    private val started = elapsedMillis()
    private var last = started
    private var approved = false
    private var consumed = false
    private var closed = false
    private var version: Long? = null
    private var latestVersion = 0L
    private var observing = false
    private var observation: AutoCloseable? = null
    init {
        require(started >= 0 && observedVersion == 0L) { "Decision starts unarmed" }
        require(scope.accountId == session.account.toString() && scope.deviceId == session.device.toString())
        require(review.intervalId == scope.intervalId && review.lineId == scope.lineId &&
            review.lineGeneration == scope.bindingGeneration && review.peer == scope.peer &&
            review.disclosureDigest == scope.disclosureDigest)
    }
    /** Subscribe to the actual domain; callers cannot arm a decision with a predicted counter. */
    fun observePresentation(presentation: ConversationPresentationPort) {
        synchronized(this) { current(); check(!observing); observing = true }
        val handle = try { presentation.observe(::observed) }
        catch (error: Exception) { close(); throw error }
        val discard = synchronized(this) {
            if (closed) true else { observation = handle; false }
        }
        if (discard) handle.close()
    }
    @Synchronized private fun observed(snapshot: ConversationPresentationSnapshot) {
        if (closed || consumed) return
        try { current() } catch (_: Exception) { closed = true; approved = false; version = null; return }
        if (snapshot.version < latestVersion) { closed = true; approved = false; version = null; return }
        latestVersion = snapshot.version
        // The existing domain publishes its next, cancellable Preparing state before consuming
        // the approved decision. Its own stillCurrent check independently fences installation.
        if (approved && snapshot.phase == ConversationPresentationPhase.PREPARING &&
            snapshot.version == checkNotNull(version) + 1 && snapshot.intervalId == scope.intervalId &&
            snapshot.lineId == scope.lineId && snapshot.lineGeneration == scope.bindingGeneration) return
        if (snapshot.phase != ConversationPresentationPhase.AWAITING_PHONE_REVIEW) {
            approved = false; version = null
            return
        }
        val displayed = snapshot.review
        if (displayed == null || displayed.remainingMs > review.remainingMs ||
            displayed.copy(remainingMs = review.remainingMs) != review) {
            closed = true; approved = false; version = null; return
        }
        if (version != snapshot.version) approved = false
        version = snapshot.version
    }
    private fun current() {
        check(!closed && !consumed)
        if (runCatching { currentSession() }.getOrNull() != session) {
            closed = true
            error("Phone decision unavailable")
        }
        val now = try { elapsedMillis() } catch (error: Exception) { closed = true; throw error }
        if (now < last || now < started || now - started >= review.remainingMs) {
            closed = true
            error("Phone decision unavailable")
        }
        last = now
    }
    /** The presentation host calls this only for its actual affirmative request/version action. */
    @Synchronized fun approve(requestId: String, version: Long) {
        current()
        check(requestId == review.requestId && version == this.version && !approved)
        approved = true
    }
    @Synchronized fun consume(expected: ConversationCaptureScope) {
        current()
        check(approved && expected == scope)
        consumed = true
    }
    override fun close() {
        val handle = synchronized(this) {
            closed = true; approved = false; version = null
            observation.also { observation = null }
        }
        handle?.close()
    }
    override fun toString() = "ConversationPhoneDecision(redacted)"
}
