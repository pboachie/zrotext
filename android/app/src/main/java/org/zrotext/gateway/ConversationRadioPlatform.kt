// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Build
import android.telephony.SmsManager

/** Default-disabled selected-line platform boundary. No plaintext persistence or radio retry.
 * Only an already guarded prepared holder may enter; a writer ACK and one-use Room CAS remain
 * mandatory. Android String APIs make transient copies, which cannot be reliably zeroized.
 */
/** Internal fixture seam replaces only Android APIs; all ACK/guard/CAS logic stays in the consumer. */
internal interface ConversationRadioDriver {
    fun requireSelected()
    fun divide(body:String):ArrayList<String>
    fun close()
    fun prepare(attempt:String,parts:ArrayList<String>)
    fun send(peer:String,attempt:String,parts:ArrayList<String>)
}
internal class ConversationRadioPlatform internal constructor(
    private val binding:LocalLineBinding, private val driver:ConversationRadioDriver,
    private val suppression:ConversationExistingSuppressionTokens, private val enabled:Boolean=false
) {
    constructor(context:Context,binding:LocalLineBinding,enabled:Boolean=false):this(
        binding,AndroidDriver(checkNotNull(context.applicationContext),binding),
        ConversationExistingSuppressionTokens(),enabled)
    constructor(context:Context,binding:LocalLineBinding,suppression:ConversationExistingSuppressionTokens,
                enabled:Boolean=false):this(binding,AndroidDriver(checkNotNull(context.applicationContext),binding),suppression,enabled)
    private fun selected() {check(enabled);driver.requireSelected()}
    private class AndroidDriver(private val application:Context,private val binding:LocalLineBinding):ConversationRadioDriver {
        override fun requireSelected() {
            check(SmsAttemptAdapter.hasSelectedSim(application,binding.subscriptionId))
            check(SimCardContinuity.matches(binding.cardId?.let {
                ActivatedSimCard(binding.subscriptionId,it)
            },SimCardContinuity.observe(application)))
        }
        @Suppress("DEPRECATION") private fun manager():SmsManager {
            requireSelected()
            return if(Build.VERSION.SDK_INT>=31) application.getSystemService(SmsManager::class.java)
                .createForSubscriptionId(binding.subscriptionId)
            else SmsManager.getSmsManagerForSubscriptionId(binding.subscriptionId)
        }
        override fun divide(body:String)=manager().divideMessage(body)
        private var preparedAttempt:String?=null
        private var preparedParts:ArrayList<String>?=null
        private var radio:SmsManager?=null
        private var sent:ArrayList<android.app.PendingIntent>?=null
        private var delivered:ArrayList<android.app.PendingIntent>?=null
        override fun prepare(attempt:String,parts:ArrayList<String>) {
            check(preparedAttempt==null)
            radio=manager()
            sent=ArrayList(parts.indices.map {
                SmsAttemptAdapter.callbackIntent(application,attempt,it,SmsCallbackReceiver.ACTION_SENT)
            })
            delivered=ArrayList(parts.indices.map {
                SmsAttemptAdapter.callbackIntent(application,attempt,it,SmsCallbackReceiver.ACTION_DELIVERED)
            })
            preparedAttempt=attempt;preparedParts=parts
        }
        override fun close() {preparedAttempt=null;preparedParts=null;radio=null;sent=null;delivered=null}
        override fun send(peer:String,attempt:String,parts:ArrayList<String>) {
            check(preparedAttempt==attempt && preparedParts===parts)
            preparedAttempt=null;preparedParts=null
            val selectedRadio=checkNotNull(radio);val sentCallbacks=checkNotNull(sent);val deliveredCallbacks=checkNotNull(delivered)
            radio=null;sent=null;delivered=null
            if(parts.size==1)selectedRadio.sendTextMessage(peer,null,parts.single(),sentCallbacks.single(),deliveredCallbacks.single())
            else selectedRadio.sendMultipartTextMessage(peer,null,parts,sentCallbacks,deliveredCallbacks)
        }
    }
    fun submit(context:ConversationPreparedSubmissionContext, prepared:Draft02OutboundPreparation.Prepared,
               eventId:String, dao:SmsAttemptDao, requireCurrent:(ConversationPreparedSubmissionContext)->Long):ConversationSubmission {
        if(!enabled)return ConversationSubmission.UNKNOWN
        var started=false
        var invoked=false
        var lastNow=0L
        fun fresh():Long {
            val now=requireCurrent(context)
            check(now>0 && now>=lastNow && now<context.deadlineMs)
            lastNow=now
            val grant=context.grant
            check(context.deadlineMs<=grant.expiresAtMs && grant.expiresAtMs<=context.originalDeadlineMs &&
                grant.attemptId.toString()==context.attempt && grant.messageId.toString()==context.message &&
                grant.accountId.toString()==context.scope.accountId && grant.deviceId.toString()==context.scope.deviceId &&
                grant.lineId.toString()==binding.lineId && grant.bindingGeneration==binding.generation &&
                context.local.binding==binding && context.scope.peer.matches(Regex("\\+[1-9][0-9]{1,14}")))
            selected()
            suppression.requireAvailable()
            // Selected-card and Keystore providers may block. Time is sampled after them.
            val completed=requireCurrent(context)
            check(completed>=now && completed>=lastNow && completed<context.deadlineMs)
            lastNow=completed
            return completed
        }
        return try {
            fresh()
            val event=checkNotNull(dao.getAlphaEvent(eventId))
            val attempt=checkNotNull(dao.getAttempt(context.attempt))
            check(event.evidence=="durable_submit_intent" && event.acknowledgedAtMs!=null &&
                event.quarantinedAtMs==null && event.messageId==context.message && event.attemptId==context.attempt &&
                event.accountId==context.scope.accountId && event.deviceId==context.scope.deviceId &&
                event.originHash==context.session.originHash && attempt.state==AttemptState.SUBMITTING &&
                attempt.messageId==context.message && attempt.accountId==context.scope.accountId &&
                attempt.deviceId==context.scope.deviceId && attempt.originHash==context.session.originHash &&
                attempt.subscriptionId==binding.subscriptionId && attempt.segmentCount==prepared.segmentCount)
            prepared.consume { chars ->
                fresh()
                val parts=driver.divide(String(chars))
                check(parts.size in 1..context.grant.segmentCount && parts.size==prepared.segmentCount)
                driver.prepare(context.attempt,parts)
                val now=fresh() // Manager/division/callback providers can wait.
                check(dao.consumeRadioStart(context.attempt,context.message,binding.subscriptionId,parts.size,now)==1)
                started=true
                // Best effort while alive; startup reconciliation retains unknown work after death.
                val startedElapsed=android.os.SystemClock.elapsedRealtime()
                JournalRuntime.timeouts.schedule({ JournalRuntime.io.execute {
                    runCatching {
                        val elapsed=android.os.SystemClock.elapsedRealtime()-startedElapsed
                        check(elapsed>=0)
                        dao.markStalledSubmission(context.attempt,Math.addExact(now,elapsed))
                        JournalWriteSignal.alphaEventRecorded()
                    }
                } },2,java.util.concurrent.TimeUnit.MINUTES)
                synchronized(LocalSuppressionGate.lock) {
                    val token=suppression.sender(context.scope.peer)
                    check(!dao.isRecipientSuppressed(token))
                    fresh() // The durable CAS and suppression lookup may wait.
                    invoked=true // A throw after invocation can represent a partial carrier action.
                    driver.send(context.scope.peer,context.attempt,parts)
                }
            }
            ConversationSubmission.SUBMITTED
        } catch(_:Exception) {
            if(started)runCatching {
                if(!invoked)dao.markPreflightNoRadio(context.attempt,lastNow)
                else dao.setState(context.attempt,AttemptState.UNKNOWN,lastNow)
            }
            ConversationSubmission.UNKNOWN
        } finally {runCatching {driver.close()}}
    }
    override fun toString()="ConversationRadioPlatform(redacted)"
}
