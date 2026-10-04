// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Future presentation port only. No current activity/service constructs or mounts it. */
internal interface ConversationPresentationPort {
    fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable
    fun refresh()
    fun approvePhoneReview(requestId: String, observedVersion: Long)
    fun declinePhoneReview(requestId: String, observedVersion: Long)
    fun requestStop(intervalId: String, observedVersion: Long)
}
internal enum class ConversationStopReason {
    USER_STOP, WITHDRAWAL, PERMISSION_LOST, SIM_CHANGED, LINE_CHANGED, OWNER_SESSION_LOST,
    PHONE_SESSION_LOST, ROOT_CHANGED, READER_CHANGED, LEASE_EXPIRED, WORKER_SHUTDOWN
}
internal enum class ConversationPresentationPhase {
    UNAVAILABLE, OFF, AWAITING_PHONE_REVIEW, PREPARING, RECOVERING,
    CONFIRMED_ACTIVE, PAUSING, DURABLY_CLOSED, EXPIRED, FAILURE
}
internal enum class ConversationCloseOutcome { IN_PROGRESS, DURABLY_CLOSED, DISABLED_CLOSURE_FAILED }
internal enum class ConversationPresentationFailure { AUTHORITY_UNAVAILABLE, STORAGE_UNAVAILABLE, STALE_REVIEW, UNSUPPORTED }
/** Present only inside a deliberate phone confirmation pane; never save or routinely announce peer. */
internal data class ConversationPhoneReview(
    val requestId: String, val intervalId: String, val lineId: String, val lineGeneration: Long,
    val peer: String, val disclosure: String, val disclosureRevision: String, val disclosureDigest: String,
    val remainingMs: Long,
    val integrationSelection: ConversationReaderSelection = ConversationReaderSelection(emptyList())
) {
    init {
        listOf(requestId, intervalId, lineId).forEach { require(UUID.fromString(it).toString() == it && UUID.fromString(it) != UUID(0, 0)) }
        require(lineGeneration > 0 && remainingMs in 1..60000 && Regex("\\+[1-9][0-9]{1,14}").matches(peer))
        require(disclosure == (if(integrationSelection.values.isEmpty()) ConversationActivationCodec.DISCLOSURE else ConversationActivationCodec.READER_DISCLOSURE) && disclosureRevision == "conversation-content-v1")
        require(disclosureDigest == Draft02OutboundPreparation.hash(disclosure.toByteArray(Charsets.UTF_8)))
    }
    override fun toString() = "ConversationPhoneReview(redacted)"
}
/** Domain-owned immutable observation. Version fences actions; remainingMs is a fresh lease budget. */
internal data class ConversationPresentationSnapshot(
    val version: Long, val phase: ConversationPresentationPhase,
    val intervalId: String? = null, val lineId: String? = null, val lineGeneration: Long? = null,
    val remainingMs: Long = 0, val canStop: Boolean = false,
    val review: ConversationPhoneReview? = null, val close: ConversationCloseOutcome? = null,
    val failure: ConversationPresentationFailure? = null, val stopReason: ConversationStopReason? = null
) {
    init {
        require(version > 0 && remainingMs in 0..60000)
        listOfNotNull(intervalId, lineId).forEach { require(UUID.fromString(it).toString() == it && UUID.fromString(it) != UUID(0, 0)) }
        require(lineGeneration == null || lineGeneration > 0)
        require((phase == ConversationPresentationPhase.AWAITING_PHONE_REVIEW) == (review != null))
        require(phase != ConversationPresentationPhase.CONFIRMED_ACTIVE ||
            intervalId != null && lineId != null && lineGeneration != null && remainingMs > 0 && canStop)
        require((close == ConversationCloseOutcome.DURABLY_CLOSED) == (phase == ConversationPresentationPhase.DURABLY_CLOSED))
        require(close != ConversationCloseOutcome.DISABLED_CLOSURE_FAILED || phase == ConversationPresentationPhase.FAILURE && !canStop)
    }
    override fun toString() = "ConversationPresentationSnapshot($phase)"
}
