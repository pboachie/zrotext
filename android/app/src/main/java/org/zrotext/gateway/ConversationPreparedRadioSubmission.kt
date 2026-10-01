// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Metadata ACK wait occurs outside admission; guarded holder consumption is synchronous and final.
 * Constructor defaults disabled. Missing custody/channel/current authority never obtains a fallback.
 */
internal class ConversationPreparedRadioSubmission(
    private val dao:SmsAttemptDao, private val wire:ConversationRadioIntentWire,
    private val requireCurrent:(ConversationPreparedSubmissionContext)->Long,
    private val platform:(LocalLineBinding)->ConversationRadioPlatform,
    private val enabled:Boolean=false
):ConversationPreparedSubmission {
    override fun submit(context:ConversationPreparedSubmissionContext,
                        prepared:Draft02OutboundPreparation.Prepared):ConversationSubmission {
        if(!enabled)return ConversationSubmission.UNKNOWN
        val eventId=UUID.randomUUID().toString()
        val phone=ConversationPhoneSession.from(context.session)
        val ownership=ConversationRadioIntentOwnership.register(phone,eventId,context.message,context.attempt)
        var reserved=false
        fun now():Long=requireCurrent(context).also {check(it>0 && it<context.deadlineMs)}
        return try {
            val before=now()
            dao.reserveAlpha(context.attempt,context.message,context.local.binding.subscriptionId,
                prepared.segmentCount,eventId,before,identity=EvidenceIdentity(context.scope.accountId,
                    context.scope.deviceId,context.session.originHash))
            reserved=true
            val event=checkNotNull(dao.getAlphaEvent(eventId))
            val permitted=wire.submitIntent(phone,event) // No admission/sender monitor held.
            val after=now()
            if(!dao.acknowledgeAlphaIntent(eventId,permitted,after))ConversationSubmission.UNKNOWN
            else platform(context.local.binding).submit(context,prepared,eventId,dao,requireCurrent)
        } catch(_:Exception) {
            if(reserved)runCatching {dao.setState(context.attempt,AttemptState.UNKNOWN,requireCurrent(context))}
            ConversationSubmission.UNKNOWN
        } finally {ownership.close()}
    }
    override fun toString()="ConversationPreparedRadioSubmission(redacted)"
}
