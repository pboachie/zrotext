// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Process-only installation. No preference, intent extra, bootstrap key or automatic cold-start recovery. */
internal class ConversationRuntimeMount {
    data class ObservedLine(val line: String, val generation: Long)
    private class Mounted(val runtime: ConversationAuthenticatedRuntime,
                          val observedLine: (Int) -> ObservedLine?,
                          val loss: () -> ConversationStopReason?, val captured: (String) -> Unit)
    class Receipt internal constructor(internal val owner: Any,
                                      internal val boundary: ConversationCaptureAdmission.ReceiptBoundary) {
        override fun toString() = "MountedConversationReceipt(redacted)"
    }
    @Volatile private var mounted: Mounted? = null
    @Synchronized fun install(runtime: ConversationAuthenticatedRuntime, observedLine: (Int) -> ObservedLine?,
                               loss: () -> ConversationStopReason?, enabled: Boolean = false,
                               captured: (String) -> Unit = {}): Boolean {
        if (!enabled || mounted != null) return false
        mounted = Mounted(runtime, observedLine, loss, captured)
        return true // Installation is not phone approval or capture eligibility.
    }
    fun firstReceipt(): Receipt? = mounted?.let { Receipt(it, it.runtime.firstReceiptBoundary()) }
    /** Worker-only decoded first receipt; the subscription is observed on this actual broadcast. */
    @Synchronized fun receive(receipt: Receipt?, subscription: Int?, token: String, peer: String,
                              body: String): ConversationObservation {
        val value = mounted ?: return ConversationObservation.DISCARDED
        if (receipt == null || receipt.owner !== value) return ConversationObservation.DISCARDED
        val failure = try { value.loss() } catch (_: Exception) { ConversationStopReason.PHONE_SESSION_LOST }
        if (failure != null) { pause(failure); return ConversationObservation.DISCARDED }
        val line = try { subscription?.let(value.observedLine) } catch (_: Exception) {
            pause(ConversationStopReason.LINE_CHANGED)
            return ConversationObservation.DISCARDED
        } ?: return value.runtime.observeAtBoundary(receipt.boundary, token, peer, "", 0, body)
        val observation=value.runtime.observeAtBoundary(receipt.boundary, token, peer, line.line, line.generation, body)
        if(observation==ConversationObservation.CAPTURED) {
            try {value.captured(token)} catch(_:Exception) {pause(ConversationStopReason.WORKER_SHUTDOWN)}
        }
        return observation
    }
    /** Includes token/vault/storage preparation before receive can reserve a durable receipt. */
    fun prepareAndReceive(action: () -> Unit) {
        try { action() } catch (error: Exception) {
            pause(ConversationStopReason.WORKER_SHUTDOWN)
            throw error
        }
    }
    @Synchronized fun pause(reason: ConversationStopReason) {
        val old = mounted
        mounted = null // New receipt and stale queued work are fenced before async durable closure.
        old?.runtime?.lifecycleLost(reason)
    }
    /** A stale session cannot close a later owner's process mount. */
    @Synchronized fun pauseOwned(runtime: ConversationAuthenticatedRuntime, reason: ConversationStopReason) {
        if (mounted?.runtime === runtime) pause(reason)
        else runtime.lifecycleLost(reason)
    }
}
/** Shared by both ordinary service Pause paths and the ordinary first-PDU receiver. Default uninstalled. */
internal object ConversationProcessMount { val runtime = ConversationRuntimeMount() }
