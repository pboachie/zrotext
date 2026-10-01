// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

internal object ConversationInputFixture {
    val account = UUID.randomUUID()
    val device = UUID.randomUUID()
    val session = ConversationPhoneSession(account, device, UUID.randomUUID(), 1, 1, "11".repeat(32))
    val disclosure = Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray())
    val scope = ConversationCaptureScope(account.toString(), device.toString(), UUID.randomUUID().toString(),
        1, "+12", UUID.randomUUID().toString(), UUID.randomUUID().toString(), UUID.randomUUID().toString(),
        disclosure, "22".repeat(32), 1, 1, "33".repeat(32), "44".repeat(32))
    val review = ConversationPhoneReview(UUID.randomUUID().toString(), scope.intervalId, scope.lineId,
        scope.bindingGeneration, scope.peer, ConversationActivationCodec.DISCLOSURE,
        "conversation-content-v1", disclosure, 10000)
    fun refuse(action: () -> Unit) {
        try { action(); fail("Expected unavailable authority") } catch (_: IllegalStateException) { }
    }
}

internal class ConversationDecisionPresentation : ConversationPresentationPort {
    private var listener: ((ConversationPresentationSnapshot) -> Unit)? = null
    override fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable {
        this.listener = listener
        listener(ConversationPresentationSnapshot(1, ConversationPresentationPhase.OFF))
        return AutoCloseable { this.listener = null }
    }
    fun publish(value: ConversationPresentationSnapshot) { listener?.invoke(value) }
    fun review(version: Long = 7, review: ConversationPhoneReview = ConversationInputFixture.review) =
        publish(ConversationPresentationSnapshot(version, ConversationPresentationPhase.AWAITING_PHONE_REVIEW, review = review))
    override fun refresh() = Unit
    override fun approvePhoneReview(requestId: String, observedVersion: Long) = Unit
    override fun declinePhoneReview(requestId: String, observedVersion: Long) = Unit
    override fun requestStop(intervalId: String, observedVersion: Long) = Unit
}

class ConversationPhoneDecisionTest {
    private val f = ConversationInputFixture
    private var now = 100L
    private var live: ConversationPhoneSession? = f.session
    private fun decision() = ConversationPhoneDecision(f.session, f.scope, f.review, 0, { now }, { live })
    private fun armedDecision(): ConversationPhoneDecision = decision().also {
        val presentation = ConversationDecisionPresentation()
        it.observePresentation(presentation); presentation.review()
    }

    @Test fun creationNeverApprovesAndExplicitExactDecisionConsumesOnce() {
        val decision = decision()
        f.refuse { decision.consume(f.scope) }
        f.refuse { decision.approve(f.review.requestId, 7) }
        val presentation = ConversationDecisionPresentation()
        decision.observePresentation(presentation); presentation.review()
        f.refuse { decision.approve(UUID.randomUUID().toString(), 7) }
        f.refuse { decision.approve(f.review.requestId, 6) }
        decision.approve(f.review.requestId, 7)
        f.refuse { decision.consume(f.scope.copy(peer = "+13")) }
        decision.consume(f.scope)
        f.refuse { decision.consume(f.scope) }
        f.refuse { decision.approve(f.review.requestId, 7) }
    }
    @Test fun ExpiryRegressionOrSessionChangeCannotConsumeApproval() {
        val expired = armedDecision(); expired.approve(f.review.requestId, 7)
        now += 10000; f.refuse { expired.consume(f.scope) }
        val regressed = armedDecision(); regressed.approve(f.review.requestId, 7)
        now--; f.refuse { regressed.consume(f.scope) }
        now++
        val changed = armedDecision(); changed.approve(f.review.requestId, 7)
        live = f.session.copy(connectionEpoch = 2); f.refuse { changed.consume(f.scope) }
        live = f.session; f.refuse { changed.consume(f.scope) }
    }
    @Test fun closeInvalidatesApprovedDecisionAndIsIdempotent() {
        val decision = armedDecision(); decision.approve(f.review.requestId, 7)
        decision.close(); decision.close()
        f.refuse { decision.consume(f.scope) }
    }
    @Test fun mismatchedReviewCannotCreateDecision() {
        try {
            ConversationPhoneDecision(f.session, f.scope, f.review.copy(peer = "+13"), 0, { now }, { live })
            fail("Expected review binding refusal")
        } catch (_: IllegalArgumentException) { }
    }
    @Test fun actualReviewRefreshInvalidatesStaleApprovalAndPreparingPreservesExactConsumedDecision() {
        val decision = decision(); val presentation = ConversationDecisionPresentation()
        decision.observePresentation(presentation)
        f.refuse { decision.approve(f.review.requestId, 7) }
        presentation.review(); decision.approve(f.review.requestId, 7)
        presentation.review(8, f.review.copy(remainingMs = 9000))
        f.refuse { decision.consume(f.scope) }
        f.refuse { decision.approve(f.review.requestId, 7) }
        decision.approve(f.review.requestId, 8)
        presentation.publish(ConversationPresentationSnapshot(9, ConversationPresentationPhase.PREPARING,
            f.scope.intervalId, f.scope.lineId, f.scope.bindingGeneration, canStop = true))
        decision.consume(f.scope)
    }
    @Test fun replacedReviewAndPredictedCounterCannotArmDecision() {
        try { ConversationPhoneDecision(f.session, f.scope, f.review, 7, { now }, { live }); fail("Predicted counter accepted") }
        catch (_: IllegalArgumentException) { }
        val decision = decision(); val presentation = ConversationDecisionPresentation()
        decision.observePresentation(presentation)
        presentation.review(review = f.review.copy(peer = "+13"))
        f.refuse { decision.approve(f.review.requestId, 7) }
        presentation.review(8)
        f.refuse { decision.approve(f.review.requestId, 8) }
    }
    @Test fun realPresentationRuntimeConsumesOnlyAfterActualReviewAndPreparingTransition() {
        val decision = decision()
        var consumed = false
        val domain = object : ConversationPresentationDomain {
            override fun sample() = ConversationPresentationSnapshot(1,
                ConversationPresentationPhase.AWAITING_PHONE_REVIEW, review = f.review.copy(remainingMs = 9000))
            override fun approve(review: ConversationPhoneReview, stillCurrent: () -> Boolean) {
                check(stillCurrent()); decision.consume(f.scope); consumed = true
            }
            override fun decline(review: ConversationPhoneReview) = Unit
            override fun disableAdmission() = Unit
            override fun stop(intervalId: String) = ConversationPresentationSnapshot(1, ConversationPresentationPhase.OFF)
        }
        val direct = java.util.concurrent.Executor { it.run() }
        val runtime = ConversationPresentationRuntime(direct, direct, domain)
        decision.observePresentation(runtime)
        f.refuse { decision.approve(f.review.requestId, 2) }
        runtime.refresh()
        decision.approve(f.review.requestId, 2)
        runtime.approvePhoneReview(f.review.requestId, 2)
        assertTrue(consumed)
        f.refuse { decision.consume(f.scope) }
    }
}
