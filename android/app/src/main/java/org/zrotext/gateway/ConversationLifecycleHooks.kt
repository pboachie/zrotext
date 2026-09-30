// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/**
 * Shared future runtime worker hook, not a service/presentation implementation. A new process
 * requires fresh phone review; it never automatically recovers an installed row. All legacy,
 * authenticated, receiver and notification routes must use this same instance before mounting.
 */
internal class ConversationLifecycleHooks(
    private val admission: ConversationCaptureAdmission, private val sends: ConversationSendDao,
    private val clock: ConversationTrustedClock, private val recovery: ConversationFreshReviewRecovery,
    // Mandatory authenticated adapter verifies the exact scope's durable server closure ACK.
    private val closeServerInterval: (ConversationCaptureScope) -> Unit
) {
    private var version = 1L
    private var last = ConversationPresentationSnapshot(version, ConversationPresentationPhase.UNAVAILABLE)
    @Synchronized fun snapshot() = last
    @Synchronized fun stop(scope: ConversationCaptureScope, reason: ConversationStopReason): ConversationPresentationSnapshot {
        // This linearization is on the runtime worker, never the Compose/UI thread.
        admission.disableForLifecycle()
        clock.invalidate()
        last = ConversationPresentationSnapshot(++version, ConversationPresentationPhase.PAUSING,
            scope.intervalId, scope.lineId, scope.bindingGeneration, close = ConversationCloseOutcome.IN_PROGRESS, stopReason = reason)
        val local = runCatching {
            recovery.block(scope.intervalId)
            admission.close(scope.intervalId)
            sends.close(scope.intervalId)
        }
        // Attempt remote withdrawal even when local persistence failed; no automatic recovery.
        val remote = runCatching { closeServerInterval(scope) }
        last = if (local.isSuccess && remote.isSuccess) {
            ConversationPresentationSnapshot(++version, ConversationPresentationPhase.DURABLY_CLOSED,
                scope.intervalId, scope.lineId, scope.bindingGeneration, close = ConversationCloseOutcome.DURABLY_CLOSED, stopReason = reason)
        } else {
            ConversationPresentationSnapshot(++version, ConversationPresentationPhase.FAILURE,
                scope.intervalId, scope.lineId, scope.bindingGeneration,
                close = ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,
                failure = if (local.isFailure) ConversationPresentationFailure.STORAGE_UNAVAILABLE else ConversationPresentationFailure.AUTHORITY_UNAVAILABLE,
                stopReason = reason)
        }
        return last
    }
}
