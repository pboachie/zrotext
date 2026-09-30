// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Connects the dormant port to the actual protected journal/recovery and lifecycle hooks.
 * Proposal and all methods except disableAdmission are worker-only. No receiver/service mounts it.
 * exchange must verify canonical server acceptance and phone installation, using existing authority.
 */
internal class ConversationJournalPresentationDomain(
    private val admission: ConversationCaptureAdmission, private val recovery: ConversationFreshReviewRecovery,
    private val hooks: ConversationLifecycleHooks, private val verifier: ConversationActivationVerifier,
    private val elapsedMillis: () -> Long,
    private val exchange: (ConversationRecoveryRequest) -> ByteArray
) : ConversationPresentationDomain {
    private data class Pending(val review: ConversationPhoneReview, val scope: ConversationCaptureScope,
        val evidence: ByteArray, val deadline: Long)
    private var pending: Pending? = null
    private var scope: ConversationCaptureScope? = null
    private var terminal: ConversationPresentationSnapshot? = null
    private var lastElapsed = -1L
    private fun now(): Long = elapsedMillis().also { check(it >= 0 && it >= lastElapsed); lastElapsed = it }
    fun propose(review: ConversationPhoneReview, evidence: ByteArray) {
        check(scope == null || terminal?.close == ConversationCloseOutcome.DURABLY_CLOSED)
        admission.disableForLifecycle()
        pending = null; terminal = null
        val owned = evidence.copyOf(); require(owned.size in 1..16384)
        val verified = verifier.verifiedPreparation(owned.copyOf())
        require(review.intervalId == verified.intervalId && review.lineId == verified.lineId &&
            review.lineGeneration == verified.bindingGeneration && review.peer == verified.peer &&
            review.disclosureDigest == verified.disclosureDigest)
        val started = now(); check(started <= Long.MAX_VALUE - review.remainingMs)
        pending = Pending(review,verified,owned,started + review.remainingMs)
        scope = verified
    }
    override fun sample(): ConversationPresentationSnapshot {
        val elapsed = now()
        pending?.let { value ->
            val budget = value.deadline - elapsed
            if (budget <= 0) { pending = null; scope = null; value.evidence.fill(0)
                return ConversationPresentationSnapshot(1,ConversationPresentationPhase.EXPIRED) }
            check(verifier.verifiedPreparation(value.evidence.copyOf()) == value.scope)
            return ConversationPresentationSnapshot(1,ConversationPresentationPhase.AWAITING_PHONE_REVIEW,
                review = value.review.copy(remainingMs = budget))
        }
        terminal?.let { return it }
        val selected = scope ?: return ConversationPresentationSnapshot(1,ConversationPresentationPhase.OFF)
        val budget = admission.remainingMs(selected)
        return if (budget > 0) ConversationPresentationSnapshot(1,ConversationPresentationPhase.CONFIRMED_ACTIVE,
            selected.intervalId,selected.lineId,selected.bindingGeneration,budget,true)
        else ConversationPresentationSnapshot(1,ConversationPresentationPhase.EXPIRED,
            selected.intervalId,selected.lineId,selected.bindingGeneration,canStop=true)
    }
    override fun approve(review: ConversationPhoneReview, stillCurrent: () -> Boolean) {
        val value = checkNotNull(pending)
        pending = null // Consume once before storage or transport; failure never retries approval.
        try {
            check(value.review.copy(remainingMs = review.remainingMs) == review && now() < value.deadline && stillCurrent())
            recovery.approveFreshReview(value.evidence.copyOf())
            val request = recovery.beginRecovery()
            val activeEvidence = exchange(request)
            try {
                synchronized(admission) {
                    try {
                        check(now() < value.deadline && stillCurrent())
                        recovery.completeRecovery(request.challenge,activeEvidence.copyOf())
                        check(now() < value.deadline && stillCurrent()) { "Decision expired or cancelled" }
                    } catch (error: Exception) {
                        admission.disableForLifecycle() // Including throwing clock/decision, before releasing gate.
                        throw error
                    }
                }
            } finally { activeEvidence.fill(0) }
        } catch (error: Exception) { admission.disableForLifecycle(); throw error }
        finally { value.evidence.fill(0) }
    }
    override fun decline(review: ConversationPhoneReview) {
        val value = checkNotNull(pending)
        check(value.review.copy(remainingMs = review.remainingMs) == review)
        pending = null; value.evidence.fill(0); scope = null
        admission.disableForLifecycle()
        terminal = ConversationPresentationSnapshot(1,ConversationPresentationPhase.OFF)
    }
    override fun disableAdmission() = admission.disableForLifecycle()
    override fun stop(intervalId: String): ConversationPresentationSnapshot {
        val selected = checkNotNull(scope); check(selected.intervalId == intervalId)
        pending?.evidence?.fill(0); pending = null
        return hooks.stop(selected,ConversationStopReason.USER_STOP).also { terminal = it }
    }
}
