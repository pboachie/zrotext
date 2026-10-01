// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Implement inside the existing authenticated socket owner only. No raw-frame/public HTTP fallback.
 * Replies carry channel-established identity, never an identity read from an untrusted payload.
 * Server implementation must commit closure before acknowledging; a socket write is not an ACK.
 */
internal interface ConversationAuthenticatedChannel {
    fun time(request: ConversationTrustedClock.Request): ConversationTimeReply
    fun close(request: ConversationClosureRequest): ConversationClosureReply
    fun reconcile(request: ConversationClosureRequest, originalStatement: ByteArray): ConversationClosureReply =
        error("Authenticated closure reconciliation unavailable")
}
internal data class ConversationTimeReply(val session: ConversationPhoneSession, val challenge: UUID, val sentUtcMs: Long)
internal data class ConversationClosureRequest(val session: ConversationPhoneSession, val challenge: UUID, val scope: ConversationCaptureScope) {
    override fun toString() = "ConversationClosureRequest(redacted)"
}
internal data class ConversationClosureReply(val session: ConversationPhoneSession, val challenge: UUID,
    val scope: ConversationCaptureScope, val durablyClosed: Boolean) {
    override fun toString() = "ConversationClosureReply(redacted)"
}

/** Dormant authenticated transport adapter. Mandatory channel has no production implementation yet. */
internal class ConversationAuthorityTransport(
    private val channel: ConversationAuthenticatedChannel, private val clock: ConversationTrustedClock,
    private val currentSession: () -> ConversationPhoneSession?, private val elapsedMillis: () -> Long
) {
    @Synchronized fun refreshTime() {
        try {
            val request = clock.beginRequest()
            val reply = channel.time(request)
            check(currentSession() == request.session)
            clock.installAuthenticatedReply(reply.challenge, reply.session, reply.sentUtcMs)
        } catch (error: Exception) { clock.invalidate(); throw error }
    }
    @Synchronized fun close(scope: ConversationCaptureScope) = exchangeClose(scope, null)
    /** Explicit closed-only query, never a retry of approval, capture or SMS execution. */
    @Synchronized fun reconcile(scope: ConversationCaptureScope, originalStatement: ByteArray) =
        exchangeClose(scope, originalStatement.copyOf())
    private fun exchangeClose(scope: ConversationCaptureScope, originalStatement: ByteArray?) {
        val session = checkNotNull(currentSession())
        check(session.account.toString() == scope.accountId && session.device.toString() == scope.deviceId)
        val start = elapsedMillis(); check(start >= 0 && start <= Long.MAX_VALUE - 5000)
        val request = ConversationClosureRequest(session, UUID.randomUUID(), scope)
        val reply = if (originalStatement == null) channel.close(request) else {
            check(ConversationActivationCodec.decode(originalStatement).scope == scope)
            channel.reconcile(request, originalStatement)
        }
        val end = elapsedMillis()
        check(end >= start && end - start <= 5000 && currentSession() == session)
        check(reply.session == session && reply.challenge == request.challenge && reply.scope == scope && reply.durablyClosed)
        // No replay queue: a lost/late response remains closure failure, requiring deliberate reconciliation.
    }
}
