// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Value identity copied from independently authenticated SealedDispatchExecutor.Session. */
internal data class ConversationPhoneSession(
    val account: UUID, val device: UUID, val session: UUID,
    val connectionEpoch: Long, val deploymentEpoch: Long, val originHash: String
) {
    init {
        require(listOf(account, device, session).all { it != UUID(0, 0) })
        require(connectionEpoch > 0 && deploymentEpoch > 0 && originHash.matches(Regex("[0-9a-f]{64}")))
    }
    override fun toString() = "ConversationPhoneSession(redacted)"
    companion object {
        fun from(value: SealedDispatchExecutor.Session) = ConversationPhoneSession(value.accountId, value.deviceId,
            value.sessionId, value.connectionEpoch, value.deploymentEpoch, value.originHash)
    }
}
/**
 * Proposed authenticated socket time-reply adapter. No wall clock, persistence, service hookup or
 * default source. Only the owner of the authenticated socket may install a reply, after matching
 * its channel/session and request nonce. Current wire protocol does not yet emit such a reply.
 * Upper-bound UTC accounts for the full bounded RTT, so clock uncertainty expires grants early.
 */
internal class ConversationTrustedClock(
    private val elapsedMillis: () -> Long, private val currentSession: () -> ConversationPhoneSession?
) {
    data class Request(val challenge: UUID, val session: ConversationPhoneSession) {
        override fun toString() = "ConversationTimeRequest(redacted)"
    }
    private data class Pending(val request: Request, val started: Long)
    private data class Anchor(val session: ConversationPhoneSession, val lowerUtc: Long, val upperUtc: Long, val received: Long)
    private var pending: Pending? = null
    private var anchor: Anchor? = null
    private var lastElapsed = -1L
    private var lastUtc = 0L
    private var failed = false
    private fun elapsed(): Long {
        check(!failed)
        val now = try { elapsedMillis() } catch (error: Exception) { invalidate(); failed = true; throw error }
        if (now < 0 || now < lastElapsed) { invalidate(); failed = true; error("Monotonic time unavailable") }
        lastElapsed = now
        return now
    }
    private fun session(): ConversationPhoneSession = try { checkNotNull(currentSession()).also {
        if (anchor?.session?.let { prior -> prior != it } == true) invalidate()
    } } catch (error: Exception) { invalidate(); throw error }
    @Synchronized fun beginRequest(): Request {
        val now = elapsed(); val live = session()
        val request = Request(UUID.randomUUID(), live)
        pending = Pending(request, now)
        return request
    }
    /** Input UTC is authenticated channel data, never a local wall clock or arbitrary frame claim. */
    @Synchronized fun installAuthenticatedReply(challenge: UUID, replyingSession: ConversationPhoneSession, serverSentUtcMs: Long) {
        val waiting = checkNotNull(pending)
        pending = null // A rejection consumes this request; never replay it later.
        try {
            val now = elapsed()
            require(waiting.request.challenge == challenge && waiting.request.session == replyingSession && session() == replyingSession)
            val rtt = now - waiting.started
            require(rtt in 0..MAX_RTT_MS && serverSentUtcMs > 0 && serverSentUtcMs <= Long.MAX_VALUE - rtt - MAX_AGE_MS)
            val upper = serverSentUtcMs + rtt
            val prior = anchor
            val floor = if (prior == null) lastUtc else maxOf(lastUtc, Math.addExact(prior.upperUtc, now - prior.received))
            // A shorter RTT may lower the new uncertainty bound even though
            // authenticated server UTC advances. Keep the old conservative
            // upper bound, but reject a sample below the elapsed lower bound.
            val lower = if (prior == null) serverSentUtcMs else
                maxOf(serverSentUtcMs, Math.addExact(prior.lowerUtc, now - prior.received))
            require(upper >= lower) { "Authenticated UTC regressed" }
            val conservative = maxOf(upper, floor)
            anchor = Anchor(replyingSession, lower, conservative, now)
            lastUtc = conservative
        } catch (error: Exception) { invalidate(); throw error }
    }
    @Synchronized fun nowMs(): Long? { return try {
        val now = elapsed(); val live = session(); val value = anchor ?: return null
        check(value.session == live && now - value.received < MAX_AGE_MS)
        val utc = value.upperUtc + now - value.received
        check(utc >= lastUtc); lastUtc = utc; utc
    } catch (_: Exception) { invalidate(); null } }
    @Synchronized fun invalidate() { pending = null; anchor = null }
    companion object { const val MAX_RTT_MS = 2000L; const val MAX_AGE_MS = 30000L }
}
