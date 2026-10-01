// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock
import android.telephony.SubscriptionManager
import java.security.KeyStore
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicReference

/**
 * Dormant provider of device-local inputs. The host supplies its existing authenticated session,
 * existing line journal and mandatory transport. A transport must use the separately authenticated
 * sealed execution grant boundary; a confirmed body alone is never a radio authorization.
 * Construction neither opens databases nor creates keys. The host disables admission before close.
 */
internal class ConversationAndroidConnectionInputs(
    context: Context,
    private val lines: SmsAttemptDao,
    payloadAlias: String,
    private val delivery: Executor,
    private val currentSession: () -> ConversationPhoneSession?,
    private val dispatch: ConversationSendTransport
) {
    private val application = checkNotNull(context.applicationContext)
    private val payloadKeys = DevicePayloadKeyStore(application, payloadAlias.also { require(it.isNotBlank()) })
    private val signingKeys = DeviceSigningKeyStore(application)

    /**
     * Explicit user action on a worker; failed setup publishes no input handle. observedVersion
     * must be zero: attach Owned.decision to the actual presentation before the affirmative action.
     */
    fun openForUserAction(session: ConversationPhoneSession, scope: ConversationCaptureScope,
                         review: ConversationPhoneReview, observedVersion: Long,
                         bindings: ConversationConnectionBindings): Owned {
        return openForUserAction(session, scope, review, observedVersion) { bindings }
    }

    internal fun openForUserAction(session: ConversationPhoneSession, scope: ConversationCaptureScope,
                                  review: ConversationPhoneReview, observedVersion: Long,
                                  bindings: () -> ConversationConnectionBindings): Owned {
        check(currentSession() == session)
        val decision = ConversationPhoneDecision(session, scope, review, observedVersion,
            SystemClock::elapsedRealtime, currentSession)
        val journals = ConversationJournalStores(application)
        val storage = Draft02AndroidTrustStorage(application)
        val owned = Owned(session, scope, decision, journals, storage)
        try {
            owned.requireLocal(scope)
            val public = payloadKeys.existingPublic()
            check(public.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT))
            val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            check(keys.getKey(DeviceSigningKeyStore.DEFAULT_ALIAS, null) != null &&
                keys.getCertificate(DeviceSigningKeyStore.DEFAULT_ALIAS) != null)
            val protection = ConversationExistingJournalProtection()
            protection.requireAvailable()
            val handles = journals.openForUserAction()
            owned.requireLocal(scope)
            owned.preparedInputs = ConversationConnectionInputs(handles.capture, handles.sends,
                protection, Draft02TrustStore(storage), payloadKeys, signingKeys,
                delivery, { expected, _ -> owned.requireLocal(expected); bindings() },
                { expected, _ -> owned.requireLocal(expected); handles.requireOpen() },
                { expected -> owned.requireLocal(expected); decision.consume(expected); owned.requireLocal(expected) },
                { subscription -> owned.observedLine(subscription) }, { owned.loss() }, dispatch, owned::close)
            return owned
        } catch (error: Exception) { runCatching { owned.close() }; throw error }
    }

    internal inner class Owned internal constructor(
        private val session: ConversationPhoneSession,
        private val scope: ConversationCaptureScope,
        val decision: ConversationPhoneDecision,
        private val journals: ConversationJournalStores,
        private val storage: Draft02AndroidTrustStorage
    ) : AutoCloseable {
        @Volatile private var closed = false
        private val lost = AtomicReference<ConversationStopReason?>(null)
        internal lateinit var preparedInputs: ConversationConnectionInputs
        val inputs: ConversationConnectionInputs get() { requireLocal(scope); return preparedInputs }
        private fun binding(): LocalLineBinding? = try { lines.currentLineBinding() } catch (_: Exception) { null }
        internal fun loss(): ConversationStopReason? {
            lost.get()?.let { return it }
            val reason = try {
                if (closed || currentSession() != session) ConversationStopReason.PHONE_SESSION_LOST
                else {
                    val permissions = listOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS,
                        Manifest.permission.READ_PHONE_STATE)
                    if (permissions.any { application.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED })
                        ConversationStopReason.PERMISSION_LOST
                    else {
                        val line = binding()
                        val selected = application.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                            .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
                        localLoss(scope, line, selected, SimCardContinuity.observe(application))
                    }
                }
            } catch (_: Exception) { ConversationStopReason.LINE_CHANGED }
            if (reason != null) lost.compareAndSet(null, reason)
            return lost.get()
        }
        internal fun requireLocal(expected: ConversationCaptureScope) {
            check(expected == scope && loss() == null) { "Conversation local authority unavailable" }
        }
        internal fun observedLine(subscription: Int): ConversationRuntimeMount.ObservedLine? =
            if (loss() != null || binding()?.subscriptionId != subscription) null
            else ConversationRuntimeMount.ObservedLine(scope.lineId, scope.bindingGeneration)
        /** Admission must already be disabled; no callbacks are invoked under storage locks. */
        override fun close() {
            closed = true
            lost.set(ConversationStopReason.PHONE_SESSION_LOST)
            try { decision.close() }
            finally { try { journals.close() } finally { storage.close() } }
        }
        override fun toString() = "ConversationOwnedInputs(redacted)"
    }
    companion object {
        internal fun localLoss(scope: ConversationCaptureScope, line: LocalLineBinding?,
                               selected: Int, cards: List<ActiveSimCard>?): ConversationStopReason? {
            if (line == null || line.accountId != scope.accountId || line.deviceId != scope.deviceId ||
                line.lineId != scope.lineId || line.generation != scope.bindingGeneration)
                return ConversationStopReason.LINE_CHANGED
            val card = line.cardId ?: return ConversationStopReason.SIM_CHANGED
            return if (selected != line.subscriptionId ||
                !SimCardContinuity.matches(ActivatedSimCard(line.subscriptionId, card), cards))
                ConversationStopReason.SIM_CHANGED else null
        }
    }
}
