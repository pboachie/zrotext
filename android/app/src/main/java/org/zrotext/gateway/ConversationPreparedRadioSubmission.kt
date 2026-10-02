// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

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
        return JournaledPreparedRadioSubmission(dao, wire, platform, enabled)
            .submit(context, prepared) { requireCurrent(context) }
    }
    override fun toString()="ConversationPreparedRadioSubmission(redacted)"
}
