// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/** Trusted adapter must verify current manifest, both signatures and decrypted body digest. */
internal interface ConversationSendVerifier { fun verify(evidence: ByteArray): VerifiedConversationSend }
internal data class VerifiedConversationSend(val scope: ConversationCaptureScope, val message: String,
                                           val expiresAt: Long, val body: String) {
    init {
        require(UUID.fromString(message).toString() == message && UUID.fromString(message) != UUID(0, 0))
        require(expiresAt > 0 && body.isNotEmpty() && !body.startsWith('\uFEFF') && !body.contains('\u0000'))
        val encoder = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        require(encoder.encode(java.nio.CharBuffer.wrap(body)).remaining() <= 32768)
    }
    override fun toString() = "VerifiedConversationSend(redacted)"
}
internal enum class ConversationSubmission { SUBMITTED, UNKNOWN }
internal interface ConversationSendTransport {
    /** One synchronous submission boundary; no retry or carrier-success inference. */
    fun submit(message: String, attempt: String, scope: ConversationCaptureScope, body: String): ConversationSubmission
}

/**
 * Library only. Adapters are mandatory; no transport, key provisioning or builder default exists.
 * trustedNowMillis follows SealedDispatchExecutor's trusted-time contract: authenticated server
 * time advanced by a monotonic clock, unavailable until refreshed after restart. Device wall time
 * alone is forbidden. No received/claimed row may supply its own authority or trusted time.
 */
internal class ConversationConfirmedSend(
    private val journal: ConversationSendDao, private val admission: ConversationCaptureAdmission,
    private val verifier: ConversationSendVerifier, private val protection: ConversationJournalProtection,
    private val trustedNowMillis: () -> Long?, private val transport: ConversationSendTransport
) {
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun aad(message: String, interval: String, digest: String) = "zrotext-conversation-send-v1:$message:$interval:$digest"
    private var latestTrustedTime = 0L
    private var clockFailed = false
    private fun fresh(value: VerifiedConversationSend) {
        check(!clockFailed) { "Trusted clock requires recovery" }
        val now = try { trustedNowMillis() } catch (error: Exception) { clockFailed = true; throw error }
        if (now == null || now <= 0 || now < latestTrustedTime) {
            clockFailed = true
            error("Trusted clock unavailable or regressed")
        }
        latestTrustedTime = now
        check(now < value.expiresAt && value.expiresAt - now <= 30000) { "Confirmed intent expired" }
    }
    @Synchronized fun receiveConfirmed(evidence: ByteArray, expectedMessage: String? = null) {
        require(evidence.size in 1..80000)
        val copy = evidence.copyOf(); val verified = verifier.verify(copy.copyOf()); val hash = digest(copy)
        check(expectedMessage == null || verified.message == expectedMessage) { "Confirmed message changed" }
        admission.withCurrentScope(verified.scope) { checkAdmission ->
            fresh(verified)
            val protected = protection.seal(Base64.getEncoder().encodeToString(copy), aad(verified.message, verified.scope.intervalId, hash))
            fresh(verified)
            checkAdmission()
            journal.receive(ConversationSendReceipt(verified.message, verified.scope.intervalId, hash, verified.expiresAt,
                protected.ciphertext.copyOf(), protected.nonce.copyOf()))
            checkAdmission()
            fresh(verified)
        }
    }
    /** Explicit caller action only. No restart worker invokes this method. */
    @Synchronized fun submitConfirmed(message: String): ConversationSubmission {
        val row = checkNotNull(journal.receipt(message))
        check(row.state == "confirmed") { "Claimed attempts require reconciliation, never replay" }
        val raw = Base64.getDecoder().decode(protection.open(InboundVault.Sealed(checkNotNull(row.protectedPayload), checkNotNull(row.nonce)), aad(message, row.interval, row.evidenceDigest)))
        check(raw.size in 1..80000 && digest(raw) == row.evidenceDigest) { "Protected intent changed" }
        val verified = verifier.verify(raw.copyOf())
        check(verified.message == row.message && verified.scope.intervalId == row.interval && verified.expiresAt == row.deadline)
        return admission.withCurrentScope(verified.scope) { checkAdmission ->
            fresh(verified)
            val attempt = UUID.randomUUID().toString()
            // This transaction commits BEFORE the irreversible transport callback.
            journal.claim(message, attempt)
            // Any crash/failure from this point leaves a permanent claimed fence.
            check(verifier.verify(raw.copyOf()) == verified) { "Current signed intent changed" }
            fresh(verified)
            checkAdmission()
            fresh(verified)
            val result = try { transport.submit(message, attempt, verified.scope, verified.body) }
                catch (_: Exception) { ConversationSubmission.UNKNOWN }
            journal.recordOutcome(message, attempt, if (result == ConversationSubmission.SUBMITTED) "submitted" else "unknown")
            result
        }
    }
    @Synchronized fun close(interval: String) {
        // Stop the receiver/execution gate before any send-journal persistence.
        admission.close(interval)
        journal.close(interval)
    }
}
