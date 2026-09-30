// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/**
 * Future worker recovery port. Cold-loaded and locally stopped intervals cannot resume.
 * Only a NEW verified interval plus a consumed affirmative UI decision can prepare/recover.
 * The mandatory decision consumer binds the exact observed request/version/disclosure/selection.
 * No default decision consumer, automatic worker, network transport or builder exists.
 */
internal class ConversationFreshReviewRecovery(
    private val journal: ConversationCaptureDao, private val admission: ConversationCaptureAdmission,
    private val verifier: ConversationActivationVerifier,
    private val consumePhoneDecision: (ConversationCaptureScope) -> Unit
) {
    init { admission.disableForLifecycle() } // Before the first storage read, including constructor failure.
    private val blocked = mutableSetOf<String>().apply { journal.installation()?.intervalId?.let(::add) }
    private var approved: ConversationCaptureScope? = null
    private var pending: ConversationRecoveryRequest? = null
    @Synchronized fun approveFreshReview(evidence: ByteArray) {
        val owned = evidence.copyOf(); require(owned.size in 1..16384)
        approved = null; pending = null
        val scope = verifier.verifiedPreparation(owned.copyOf())
        check(scope.intervalId !in blocked && blocked.size < 1024) { "Fresh interval required" }
        consumePhoneDecision(scope)
        admission.disableForLifecycle()
        check(verifier.verifiedPreparation(owned.copyOf()) == scope)
        // Old installation is durably fenced before any new local preparation.
        journal.installation()?.let { old -> if (old.intervalId != scope.intervalId) admission.close(old.intervalId) }
        admission.prepare(owned, true)
        approved = scope
    }
    @Synchronized fun beginRecovery(): ConversationRecoveryRequest {
        val scope = checkNotNull(approved) { "Fresh phone approval required" }
        check(scope.intervalId !in blocked)
        return admission.beginRecovery().also { check(it.intervalId == scope.intervalId); pending = it }
    }
    @Synchronized fun completeRecovery(challenge: String, evidence: ByteArray) {
        val scope = checkNotNull(approved); val request = checkNotNull(pending)
        pending = null
        check(scope.intervalId !in blocked && request.intervalId == scope.intervalId && request.challenge == challenge)
        admission.completeRecovery(challenge, evidence.copyOf())
    }
    @Synchronized fun block(intervalId: String) {
        admission.disableForLifecycle(); approved = null; pending = null
        check(blocked.size < 1024 || intervalId in blocked)
        blocked.add(intervalId)
    }
}
