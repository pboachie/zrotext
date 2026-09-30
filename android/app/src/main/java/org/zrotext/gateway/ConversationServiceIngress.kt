// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Dormant service/decoded-receipt seam. Disabled by default, never creates a receiver or SMS sender.
 * The service owner supplies independently sampled authority, not values from a broadcast.
 * Pause is terminal for this instance: a new process/session needs a fresh runtime and phone review.
 * Calls run on the receipt worker; durable closure outcomes remain on the presentation port.
 */
internal class ConversationServiceIngress(
    private val runtime: ConversationAuthenticatedRuntime,
    private val currentLoss: () -> ConversationStopReason?,
    enabled: Boolean = false
) {
    private var closed = !enabled

    @Synchronized fun observeFirstReceipt(token: String, peer: String, line: String,
                                         generation: Long, body: String): ConversationObservation {
        if (closed) return ConversationObservation.DISCARDED
        val loss = try { currentLoss() } catch (_: Exception) { ConversationStopReason.PHONE_SESSION_LOST }
        if (loss != null) {
            pause(loss)
            return ConversationObservation.DISCARDED
        }
        // Runtime independently rechecks the exact scope/session/clock/consent under its admission gate.
        return runtime.observeFirstReceipt(token, peer, line, generation, body)
    }

    /** Synchronous eligibility fence; successful return does not claim durable closure succeeded. */
    @Synchronized fun pause(reason: ConversationStopReason) {
        closed = true
        runtime.lifecycleLost(reason)
    }
}
