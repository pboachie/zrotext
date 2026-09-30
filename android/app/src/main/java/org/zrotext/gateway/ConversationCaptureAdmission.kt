// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Implement only with the approved authority / authenticated server adapter. No default exists. */
internal interface ConversationActivationVerifier {
    fun verifiedPreparation(evidence: ByteArray): ConversationCaptureScope

    /** Verify exact scope, challenge and server-installed state; return remaining admission millis. */
    fun verifiedActiveLease(scope: ConversationCaptureScope, challenge: String, evidence: ByteArray): Long
}

internal interface ConversationJournalProtection {
    fun seal(value: String, aad: String): InboundVault.Sealed
    fun open(value: InboundVault.Sealed, aad: String): String
}

/** Reuses the existing vault and aliases; construction does not provision credentials or keys. */
internal object ConversationExistingVault : ConversationJournalProtection {
    override fun seal(value: String, aad: String) = InboundVault.seal(value, aad)
    override fun open(value: InboundVault.Sealed, aad: String) = InboundVault.open(value, aad)
}

internal data class ConversationRecoveryRequest(val intervalId: String, val challenge: String) {
    override fun toString() = "ConversationRecoveryRequest(redacted)"
}

internal enum class ConversationObservation { CAPTURED, DISCARDED, DUPLICATE }

/**
 * Dormant, synchronized phone contract. All adapters are mandatory; no network or SMS API is used.
 * The caller must invoke observe exactly at first PDU receipt, never on a retry / backlog drain.
 * checkCurrent must reject permission loss, pause, line/reader/root change and expired device lease.
 */
internal class ConversationCaptureAdmission(
    private val journal: ConversationCaptureDao,
    private val verifier: ConversationActivationVerifier,
    private val protection: ConversationJournalProtection,
    private val elapsedMillis: () -> Long,
    private val checkCurrent: (ConversationCaptureScope) -> Unit
) {
    private data class Recovery(val scope: ConversationCaptureScope, val challenge: String, val start: Long)
    private data class Lease(val scope: ConversationCaptureScope, val deadline: Long)
    private data class Accepted(val request: Recovery, val duration: Long)
    private var recovery: Recovery? = null
    private var lease: Lease? = null
    private var accepted: Accepted? = null
    private var lastElapsed: Long? = null

    /** Phone affirmation is separate from pairing / permissions. Prepared cannot capture. */
    @Synchronized fun prepare(evidence: ByteArray, phoneApproved: Boolean) {
        failClosed {
            require(phoneApproved) { "Phone content transfer was not approved" }
            require(evidence.size in 1..16384) { "Preparation evidence size" }
            val scope = verifier.verifiedPreparation(evidence.copyOf())
            checkCurrent(scope)
            clock()
            val existing = journal.installation()
            val value = if (existing != null && existing.state != "closed") {
                check(readScope(existing) == scope) { "Prepared scope changed" }
                existing
            } else {
                val sealed = protection.seal(scope.encode(), scopeAad(scope.intervalId, scope.receiptId))
                ConversationInstallation(intervalId = scope.intervalId, receiptId = scope.receiptId,
                    transcriptDigest = scope.transcriptDigest, protectedScope = sealed.ciphertext,
                    nonce = sealed.nonce)
            }
            journal.prepare(value) { checkCurrent(scope); clock() }
            // An idempotent prepare never extends an existing admission lease.
        }
    }

    /** A new instance has no lease even when durable state says installed. */
    @Synchronized fun beginRecovery(): ConversationRecoveryRequest {
        lease = null
        recovery = null
        accepted = null
        val row = checkNotNull(journal.installation()) { "No prepared installation" }
        check(row.state in setOf("prepared", "installed")) { "Installation is closed" }
        val scope = readScope(row)
        checkCurrent(scope)
        val value = Recovery(scope, UUID.randomUUID().toString(), clock())
        recovery = value
        return ConversationRecoveryRequest(scope.intervalId, value.challenge)
    }

    /** Lost responses use recovery of the same durable identity, not another consent interval. */
    @Synchronized fun completeRecovery(challenge: String, evidence: ByteArray) {
        require(evidence.size in 1..16384) { "Active evidence size" }
        val replay = accepted
        if (recovery == null && replay != null && challenge == replay.request.challenge) {
            check(verifier.verifiedActiveLease(replay.request.scope, challenge, evidence.copyOf()) == replay.duration)
            check(currentLease()?.scope == replay.request.scope) { "Admission expired or closed" }
            return // Exact authenticated duplicate, without extending the original deadline.
        }
        lease = null
        val request = checkNotNull(recovery) { "Recovery was not requested" }
        recovery = null // A failed / replayed response cannot reuse a challenge.
        check(challenge == request.challenge) { "Recovery challenge changed" }
        val duration = verifier.verifiedActiveLease(request.scope, challenge, evidence.copyOf())
        require(duration in 1..MAX_ADMISSION_MS) { "Admission lease bound" }
        check(request.start <= Long.MAX_VALUE - duration)
        val next = Lease(request.scope, request.start + duration)
        journal.installed(request.scope.intervalId) {
            checkCurrent(request.scope)
            check(clock() < next.deadline) { "Active response arrived after expiry" }
            check(readScope(checkNotNull(journal.installation())) == request.scope) { "Installation changed" }
        }
        lease = next
        accepted = Accepted(request, duration)
    }

    /** Invoke synchronously before acknowledging pause / cancellation / withdrawal to presentation. */
    @Synchronized fun close(intervalId: String) {
        lease = null
        recovery = null
        accepted = null
        require(UUID.fromString(intervalId).toString() == intervalId && UUID.fromString(intervalId) != UUID(0, 0))
        journal.close(intervalId)
    }

    @Synchronized fun captureEligible(): Boolean = currentLease() != null

    /** Dormant adapters share the exact receiver/Pause monitor and scope fence. */
    @Synchronized fun <T> withCurrentScope(expected: ConversationCaptureScope, action: (() -> Unit) -> T): T = failClosed {
        val check = { check(checkNotNull(currentLease()).scope == expected) { "Conversation scope unavailable" } }
        check()
        action(check)
    }

    /**
     * receiptToken is the existing vault's domain-separated HMAC of the original PDU identity.
     * It must be independent of interval / retries. No plaintext PDU hash or peer is stored in Room.
     */
    @Synchronized fun observe(receiptToken: String, firstObservedAtMs: Long, peer: String,
                              lineId: String, generation: Long, body: String): ConversationObservation {
        require(Regex("[0-9a-f]{64}").matches(receiptToken)) { "Receipt token shape" }
        val validBody = firstObservedAtMs > 0 && body.toByteArray(Charsets.UTF_8).size <= 8192
        val recordedAt = firstObservedAtMs.coerceAtLeast(0)
        val observedElapsed = try { clock() } catch (_: Exception) { null }
        // Snapshot eligibility at API entry too: waiting for SQLite cannot make old content eligible.
        val atReceipt = if (observedElapsed == null || !validBody) null else currentLease()?.takeIf {
            it.scope.peer == peer && it.scope.lineId == lineId && it.scope.bindingGeneration == generation
        }
        var built: ConversationReceipt? = null
        val result = try {
            if (!journal.reserveReceipt(receiptToken, recordedAt)) return ConversationObservation.DUPLICATE
            journal.finishReceipt(receiptToken, { lease = null; recovery = null }) { capacity ->
            val admitted = atReceipt != null && capacity && currentLease() == atReceipt
            val previous = built
            if (previous != null) {
                check((previous.protectedCapture != null) == admitted) { "Admission closed during capture" }
                previous
            } else {
                val value = if (admitted) {
                    val scope = checkNotNull(atReceipt).scope
                    val captureId = UUID.randomUUID().toString()
                    val content = ConversationCapturedBody(scope, captureId, firstObservedAtMs, checkNotNull(observedElapsed), body)
                    val protected = protection.seal(content.encode(), captureAad(receiptToken, captureId))
                    ConversationReceipt(receiptToken, recordedAt, captureId, scope.intervalId,
                        protected.ciphertext, protected.nonce)
                } else ConversationReceipt(receiptToken, recordedAt)
                built = value
                value
            }
        } } catch (error: Exception) {
            lease = null
            recovery = null
            throw error // Storage unavailable: receiver must stop receipt dispatch until safe recovery.
        }
        return if (result.protectedCapture != null) ConversationObservation.CAPTURED else ConversationObservation.DISCARDED
    }

    /** Queue retries retain original scope and receipt time; renewal never reseals old content. */
    @Synchronized fun retry(receiptToken: String): ConversationCapturedBody? = failClosed {
        val active = currentLease() ?: return@failClosed null
        val row = journal.receipt(receiptToken) ?: return@failClosed null
        if (row.intervalId != active.scope.intervalId || row.protectedCapture == null || row.nonce == null) return@failClosed null
        val value = try { ConversationCapturedBody.decode(protection.open(
            InboundVault.Sealed(row.protectedCapture, row.nonce), captureAad(row.token, checkNotNull(row.captureId))))
            .also {
                check(it.scope == active.scope && it.captureId == row.captureId &&
                    it.firstObservedAtMs == row.firstObservedAtMs) { "Protected capture identity changed" }
            }
        } catch (error: Exception) { lease = null; recovery = null; throw error }
        check(currentLease() == active) { "Admission closed during retry" }
        value
    }

    private inline fun <T> failClosed(block: () -> T): T = try { block() } catch (error: Exception) {
        lease = null
        recovery = null
        accepted = null
        throw error
    }

    private fun currentLease(): Lease? {
        val active = lease ?: return null
        return try {
            check(clock() < active.deadline)
            checkCurrent(active.scope)
            val row = checkNotNull(journal.installation())
            check(row.state == "installed" && row.intervalId == active.scope.intervalId &&
                row.transcriptDigest == active.scope.transcriptDigest)
            check(clock() < active.deadline)
            checkCurrent(active.scope)
            active
        } catch (_: Exception) { lease = null; null }
    }

    private fun clock(): Long {
        val now = elapsedMillis()
        check(now >= 0 && (lastElapsed == null || now >= checkNotNull(lastElapsed))) {
            lease = null
            recovery = null
            "Monotonic clock changed; authenticated recovery required"
        }
        lastElapsed = now
        return now
    }

    private fun readScope(row: ConversationInstallation): ConversationCaptureScope {
        val scope = ConversationCaptureScope.decode(protection.open(
            InboundVault.Sealed(row.protectedScope, row.nonce), scopeAad(row.intervalId, row.receiptId)))
        check(scope.intervalId == row.intervalId && scope.receiptId == row.receiptId &&
            scope.transcriptDigest == row.transcriptDigest) { "Protected installation identity changed" }
        return scope
    }

    private fun scopeAad(interval: String, receipt: String) = "zrotext-conversation-scope-v1:$interval:$receipt"
    private fun captureAad(token: String, capture: String) = "zrotext-conversation-capture-v1:$token:$capture"

    companion object { const val MAX_ADMISSION_MS = 60_000L }
}
