// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import java.security.MessageDigest

/** Explicit owner-provisioned trust port. The relay frame cannot select a peer or supply a trust root.
 * Provisioning/root withdrawal remains the owner's responsibility; missing authority refuses.
 */
internal class SealedExecutionInputs(context: Context, val db: SmsJournalDatabase,
    val keyStore: DevicePayloadKeyStore,
    private val ownerScope: (SealedExecutionGrantValidator.Fields) -> Scope?,
    private val ownerCurrent: () -> Boolean,
) {
    class Scope(val authority: Draft02ManifestAuthority, val request: Draft02ManifestAuthority.Request)
    private val application = checkNotNull(context.applicationContext)
    val suppression = ConversationExistingSuppressionTokens()
    fun current() = runCatching { ownerCurrent() }.getOrDefault(false)
    fun cards() = SimCardContinuity.observe(application)
    private fun selected() = application.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
        .getInt("subscription_id", android.telephony.SubscriptionManager.INVALID_SUBSCRIPTION_ID)
    fun readiness(session: SealedDispatchExecutor.Session): Pair<LocalLineBinding, DevicePayloadPublic>? = runCatching {
        check(current())
        for (permission in listOf(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_PHONE_STATE)) {
            check(ContextCompat.checkSelfPermission(application, permission) == PackageManager.PERMISSION_GRANTED)
        }
        val binding = checkNotNull(db.attempts().currentLineBinding())
        check(binding.accountId == session.accountId.toString() && binding.deviceId == session.deviceId.toString() &&
            binding.subscriptionId == selected())
        check(SimCardContinuity.matches(binding.cardId?.let { ActivatedSimCard(binding.subscriptionId, it) }, cards()))
        val key = keyStore.existingPublic()
        check(key.security == PayloadKeySecurity.STRONGBOX || key.security == PayloadKeySecurity.TRUSTED_ENVIRONMENT)
        suppression.requireAvailable(); check(current())
        binding to key
    }.getOrNull()
    fun observe(fields: SealedExecutionGrantValidator.Fields, session: SealedDispatchExecutor.Session,
                now: Long, completedNow: () -> Long): Pair<SealedDispatchExecutor.Local, Scope>? = runCatching {
        check(current() && now > 0)
        val (binding, key) = checkNotNull(readiness(session))
        check(binding.lineId == fields.lineId.toString() && binding.generation == fields.bindingGeneration)
        check(MessageDigest.isEqual(key.keyId, fields.readerKeyId))
        val scope = checkNotNull(ownerScope(SealedEnvelopeFetch.snapshot(fields)))
        suppression.requireAvailable()
        val completed = completedNow()
        check(completed >= now && completed < fields.expiresAtMs && fields.expiresAtMs - completed <= 35_000)
        val context = scope.authority.context(scope.request, completed)
        fun uuid(bytes: ByteArray) = Draft02OutboundPreparation.uuid(bytes)
        check(uuid(context.accountId) == session.accountId.toString() && uuid(context.deviceId) == session.deviceId.toString() &&
            uuid(context.lineId) == binding.lineId && uuid(context.messageId) == fields.messageId.toString() &&
            context.direction == Draft02ManifestAuthority.Direction.OUTBOUND)
        val local = SealedDispatchExecutor.Local(binding, key.keyId, context.generation, context.version,
            Draft02OutboundPreparation.hex(context.manifestDigest), Draft02OutboundPreparation.hash(context.peer))
        check(current())
        local to scope
    }.getOrNull()
    fun preparation(grant: Draft02OutboundPreparation.Grant, fields: SealedExecutionGrantValidator.Fields,
                    session: SealedDispatchExecutor.Session, now: () -> Long): Draft02OutboundPreparation.Current? =
        observe(fields, session, now(), now)?.let { (_, scope) ->
            val selection = selected()
            val cards = cards()
            val completed = now()
            check(current())
            Draft02OutboundPreparation.Current(grant, scope.authority, scope.request, completed, selection, cards)
        }
    fun suppressed(peer: ByteArray) = runCatching {
        db.attempts().isRecipientSuppressed(suppression.sender(peer.toString(Charsets.US_ASCII)))
    }.getOrDefault(true)
    fun platform(binding: LocalLineBinding) = ConversationRadioPlatform(application, binding, suppression, enabled = true)
    override fun toString() = "SealedExecutionInputs(redacted)"
}

/** Process-only candidate installation; no intent/preference/bootstrap/cold-start activation. */
internal object SealedExecutionMount {
    class Lease internal constructor(val inputs: SealedExecutionInputs) {
        @Volatile private var closed = false
        fun current() = !closed && inputs.current()
        internal fun close() { closed = true }
        override fun toString() = "SealedExecutionLease(redacted)"
    }
    @Volatile private var installed: Lease? = null
    @Synchronized fun install(inputs: SealedExecutionInputs, enabled: Boolean = false): Boolean {
        if (!enabled || installed != null) return false
        installed = Lease(inputs); return true
    }
    fun capture(): Lease? = installed?.takeIf { it.current() }
    @Synchronized fun pause() { installed?.close(); installed = null }
}
