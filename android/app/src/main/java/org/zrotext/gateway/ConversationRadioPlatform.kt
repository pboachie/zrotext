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
    private val suppression:ConversationExistingSuppressionTokens, private val enabled:Boolean=false,
    private val healthCurrent: () -> Unit = InboundProtectionHealth::requireNotRevoked
) {
    constructor(context:Context,binding:LocalLineBinding,enabled:Boolean=false):this(
        binding,AndroidDriver(checkNotNull(context.applicationContext),binding),
        ConversationExistingSuppressionTokens(context),enabled)
    constructor(context:Context,binding:LocalLineBinding,suppression:ConversationExistingSuppressionTokens,
                enabled:Boolean=false):this(binding,AndroidDriver(checkNotNull(context.applicationContext),binding),suppression,enabled)
    private val installedProfile = binding.installedProfile()
    private val installedSelectionV2 = binding.installedSelectionV2()
    private fun liveProfile() = when {
        binding.protocolVersion == 2 -> installedSelectionV2?.isCurrent() == true &&
            installedSelectionV2.record.purpose == "sealed" && binding.installedSelectionV2() === installedSelectionV2
        binding.protocolVersion != 1 -> false
        else -> binding.continuityKind == "physical" && binding.liveContinuity() ||
            binding.continuityKind == "esim" && installedProfile?.isCurrent() == true &&
                binding.installedProfile() === installedProfile
    }
    private fun selected() {healthCurrent(); check(enabled && liveProfile());driver.requireSelected(); healthCurrent()}
    private class AndroidDriver(private val application:Context,private val binding:LocalLineBinding):ConversationRadioDriver {
        private val installedSelectionV2 = binding.installedSelectionV2()
        private val installedProfile = binding.installedProfile()
        private val healthEpoch = InboundProtectionHealth.snapshot()
        private var health: InboundProtectionEpochs.Lease? = null
        override fun requireSelected() {
            health = InboundProtection.lease(application, healthEpoch)
            check(SmsAttemptAdapter.hasSelectedSim(application,binding.subscriptionId))
            check(SimCardContinuity.matches(binding.activatedSim(),SimCardContinuity.observe(application)))
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
            check(binding.liveContinuity()) // Memory-only after the consumer's final authority/time sample.
            check(if (binding.protocolVersion == 2) installedSelectionV2?.isCurrent() == true &&
                binding.installedSelectionV2() === installedSelectionV2
                else binding.continuityKind != "esim" || installedProfile?.isCurrent() == true &&
                    binding.installedProfile() === installedProfile)
            check(preparedAttempt==attempt && preparedParts===parts)
            preparedAttempt=null;preparedParts=null
            val selectedRadio=checkNotNull(radio);val sentCallbacks=checkNotNull(sent);val deliveredCallbacks=checkNotNull(delivered)
            radio=null;sent=null;delivered=null
            checkNotNull(health).requireCurrent() // No provider or storage call after this.
            if(parts.size==1)selectedRadio.sendTextMessage(peer,null,parts.single(),sentCallbacks.single(),deliveredCallbacks.single())
            else selectedRadio.sendMultipartTextMessage(peer,null,parts,sentCallbacks,deliveredCallbacks)
        }
    }
    fun submit(context:ConversationPreparedSubmissionContext, prepared:Draft02OutboundPreparation.Prepared,
               eventId:String, dao:SmsAttemptDao, requireCurrent:(ConversationPreparedSubmissionContext)->Long):ConversationSubmission =
        submitJournaled(context, prepared, eventId, dao) { requireCurrent(context) }

    /** The ordinary sealed stream uses the same ACK, selected-card, suppression and one-use CAS path. */
    internal fun submitJournaled(context:JournaledRadioScope, prepared:Draft02OutboundPreparation.Prepared,
               eventId:String, dao:SmsAttemptDao, requireCurrent:()->Long):ConversationSubmission {
        if(!enabled)return ConversationSubmission.UNKNOWN
        var started=false
        var invoked=false
        var lastNow=0L
        fun fresh():Long {
            val now=requireCurrent()
            check(now>0 && now>=lastNow && now<context.deadlineMs)
            lastNow=now
            context.requireGrantBinding(binding)
            check(context.peer.matches(Regex("\\+[1-9][0-9]{1,14}")))
            selected()
            suppression.requireAvailable()
            // Selected-card and Keystore providers may block. Time is sampled after them.
            val completed=requireCurrent()
            check(completed>=now && completed>=lastNow && completed<context.deadlineMs)
            lastNow=completed
            check(liveProfile()) // No framework/disk wait after the final current-authority clock sample.
            return completed
        }
        return try {
            fresh()
            val event=checkNotNull(dao.getAlphaEvent(eventId))
            val attempt=checkNotNull(dao.getAttempt(context.attempt))
            check(event.evidence=="durable_submit_intent" && event.acknowledgedAtMs!=null &&
                event.quarantinedAtMs==null && event.messageId==context.message && event.attemptId==context.attempt &&
                event.accountId==context.accountId && event.deviceId==context.deviceId &&
                event.originHash==context.session.originHash && attempt.state==AttemptState.SUBMITTING &&
                attempt.messageId==context.message && attempt.accountId==context.accountId &&
                attempt.deviceId==context.deviceId && attempt.originHash==context.session.originHash &&
                attempt.subscriptionId==binding.subscriptionId && attempt.segmentCount==prepared.segmentCount)
            prepared.consume { chars ->
                fresh()
                val parts=driver.divide(String(chars))
                check(parts.size in 1..context.segmentCeiling && parts.size==prepared.segmentCount)
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
                    val token=suppression.sender(context.peer)
                    check(!dao.isRecipientSuppressed(token))
                    fresh() // The durable CAS and suppression lookup may wait.
                    healthCurrent()
                    invoked=true // A throw after invocation can represent a partial carrier action.
                    driver.send(context.peer,context.attempt,parts)
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

    /** Distinct03 path: an actual typed writer/ACK factory supplies the final one-use
     * entry. No AlphaRadioEvent, legacy state update or consumeRadioStart is consulted. */
    internal fun submitTyped(context: Profile03RadioContext, prepared: Draft02OutboundPreparation.Prepared,
        requireCurrent: () -> Long, isSuppressed: (String) -> Boolean,
        reserveEntry: () -> TypedPlatformStart): ConversationSubmission {
        if (!enabled) return ConversationSubmission.UNKNOWN
        var lastNow = 0L
        fun fresh() {
            val before = requireCurrent()
            check(before > 0 && before >= lastNow && before < context.deadlineMs)
            context.requireGrantBinding(binding)
            check(context.peer.matches(Regex("\\+[1-9][0-9]{1,14}")))
            selected(); suppression.requireAvailable()
            val completed = requireCurrent() // Framework, provider and suppression may wait.
            check(completed >= before && completed >= lastNow && completed < context.deadlineMs && liveProfile())
            lastNow = completed
        }
        return try {
            fresh()
            prepared.consume { chars ->
                fresh()
                val parts = driver.divide(String(chars))
                check(parts.size in 1..context.segmentCeiling && parts.size == prepared.segmentCount)
                driver.prepare(context.attempt, parts)
                fresh()
                val entry = reserveEntry() // SAME writer competes with permanent no-entry closure.
                synchronized(LocalSuppressionGate.lock) {
                    val token = suppression.sender(context.peer)
                    check(!isSuppressed(token))
                    fresh(); healthCurrent()
                    entry.consume() // RAM only; after this the cached driver makes its one call.
                    driver.send(context.peer, context.attempt, parts)
                }
            }
            ConversationSubmission.SUBMITTED
        } catch (_: Exception) { ConversationSubmission.UNKNOWN }
        finally { runCatching { driver.close() } }
    }
    override fun toString()="ConversationRadioPlatform(redacted)"
}
