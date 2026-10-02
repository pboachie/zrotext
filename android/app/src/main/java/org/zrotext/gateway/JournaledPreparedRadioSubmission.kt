// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Shared durable intent/ACK boundary. A metadata context alone never permits plaintext consumption. */
internal class JournaledPreparedRadioSubmission(
    private val dao: SmsAttemptDao, private val wire: ConversationRadioIntentWire,
    private val platform: (LocalLineBinding) -> ConversationRadioPlatform,
    private val enabled: Boolean = false,
) {
    fun submit(context: JournaledRadioContext, prepared: Draft02OutboundPreparation.Prepared,
               requireCurrent: () -> Long): ConversationSubmission {
        if (!enabled) return ConversationSubmission.UNKNOWN
        val eventId = UUID.randomUUID().toString()
        val phone = ConversationPhoneSession.from(context.session)
        val ownership = ConversationRadioIntentOwnership.register(phone, eventId, context.message, context.attempt)
        var reserved = false
        fun now() = requireCurrent().also { check(it > 0 && it < context.deadlineMs) }
        return try {
            val before = now()
            dao.reserveAlpha(context.attempt, context.message, context.local.binding.subscriptionId,
                prepared.segmentCount, eventId, before,
                identity = EvidenceIdentity(context.accountId, context.deviceId, context.session.originHash))
            reserved = true
            val event = checkNotNull(dao.getAlphaEvent(eventId))
            val permitted = wire.submitIntent(phone, event)
            val after = now()
            if (!dao.acknowledgeAlphaIntent(eventId, permitted, after)) ConversationSubmission.UNKNOWN
            else platform(context.local.binding).submitJournaled(context, prepared, eventId, dao, requireCurrent)
        } catch (_: Exception) {
            if (reserved) runCatching { dao.setState(context.attempt, AttemptState.UNKNOWN, requireCurrent()) }
            ConversationSubmission.UNKNOWN
        } finally { ownership.close() }
    }
    override fun toString() = "JournaledPreparedRadioSubmission(redacted)"
}
