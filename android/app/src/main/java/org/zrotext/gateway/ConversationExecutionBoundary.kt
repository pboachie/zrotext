// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Independently sampled local/session truth; a dispatch frame cannot supply these values. */
internal data class ConversationExecutionAuthority(
    val scope: ConversationCaptureScope, val phoneSession: ConversationPhoneSession,
    val ownerSessionLive: Boolean, val contentConsentLive: Boolean,
    val sendPermission: Boolean, val receivePermission: Boolean, val selectedLineCurrent: Boolean
) {
    override fun toString() = "ConversationExecutionAuthority(redacted)"
}
/**
 * Future-feature adapter around the existing grant/hardware/preparation executor. No builder,
 * radio transport, software key fallback or current service invokes this boundary.
 * The mandatory current-preparation adapter must independently reverify current manifest and
 * selected card continuity. Confirmation proof and durable submit journal remain distinct gates.
 */
internal class ConversationExecutionBoundary(
    private val admission: ConversationCaptureAdmission, private val clock: ConversationTrustedClock,
    private val authority: () -> ConversationExecutionAuthority?,
    private val db: SmsJournalDatabase, private val keys: DevicePayloadKeyStore,
    private val currentPreparation: (Draft02OutboundPreparation.Grant) -> Draft02OutboundPreparation.Current?
) {
    private fun checkLive(scope: ConversationCaptureScope, session: ConversationPhoneSession): Long {
        val live = checkNotNull(authority())
        check(live.scope == scope && live.phoneSession == session && live.ownerSessionLive && live.contentConsentLive &&
            live.sendPermission && live.receivePermission && live.selectedLineCurrent)
        check(scope.accountId == session.account.toString() && scope.deviceId == session.device.toString())
        return checkNotNull(clock.nowMs())
    }
    /** Ownership seam around an already hardware-prepared holder; never constructs/decrypts plaintext. */
    internal fun guardedPrepared(scope: ConversationCaptureScope, phone: ConversationPhoneSession,
                                 prepared: Draft02OutboundPreparation.Prepared): Draft02OutboundPreparation.Prepared =
        GuardedPrepared(scope, phone, prepared)
    private inner class GuardedPrepared(private val scope: ConversationCaptureScope,
                                        private val phone: ConversationPhoneSession,
                                        private val prepared: Draft02OutboundPreparation.Prepared) : Draft02OutboundPreparation.Prepared {
            private val fence = consumptionFence(scope, phone, prepared::close)
            override val segmentCount get() = prepared.segmentCount
            override fun consume(consumer: (CharArray) -> Unit) = fence.consume(prepared::consume, consumer)
            override fun close() = fence.close()
        }
    /** Pure ownership/monitor seam, never an execution grant or plaintext preparation provider. */
    internal fun consumptionFence(scope: ConversationCaptureScope, phone: ConversationPhoneSession,
                                  discard: () -> Unit) = ConversationConsumptionFence(admission, { checkLive(scope, phone); Unit }, scope, discard)
    fun prepare(scope: ConversationCaptureScope, grant: SealedExecutionGrantValidator.Fields,
                envelope: ByteArray, session: SealedDispatchExecutor.Session,
                local: SealedDispatchExecutor.Local): SealedDispatchExecutor.Outcome {
        val owned = envelope.copyOf()
        val fields = grant.copy(envelopeDigest = grant.envelopeDigest.copyOf(), readerKeyId = grant.readerKeyId.copyOf(), unsignedDigest = grant.unsignedDigest.copyOf())
        val phone = ConversationPhoneSession.from(session)
        return try {
            admission.withCurrentScope(scope) { guard ->
                val now = checkLive(scope, phone)
                check(local.manifestGeneration == scope.trustGeneration && local.manifestVersion >= scope.activationVersion &&
                    (local.manifestVersion != scope.activationVersion || local.manifestDigest == scope.activationDigest))
                check(fields.accountId.toString() == scope.accountId && fields.deviceId.toString() == scope.deviceId &&
                    fields.lineId.toString() == scope.lineId && fields.bindingGeneration == scope.bindingGeneration &&
                    now < fields.expiresAtMs)
                val outcome = SealedDispatchExecutor.execute(fields, owned, session, local, db, keys,
                    { runCatching { guard(); checkLive(scope, phone) }.getOrNull() }) { candidate ->
                    guard(); checkLive(scope, phone)
                    val value = currentPreparation(candidate)
                    guard(); val currentNow = checkLive(scope, phone)
                    value?.let {
                        check(it.grant == candidate && it.request.direction == Draft02ManifestAuthority.Direction.OUTBOUND)
                        check(Draft02OutboundPreparation.uuid(it.request.account()) == scope.accountId &&
                            Draft02OutboundPreparation.uuid(it.request.device()) == scope.deviceId &&
                            Draft02OutboundPreparation.uuid(it.request.line()) == scope.lineId &&
                            it.request.peer().toString(Charsets.US_ASCII) == scope.peer)
                        val archive = it.request.readers().single { reader -> reader.role == 2 }
                        check(Draft02OutboundPreparation.hex(archive.keyId) == scope.readerKeyId)
                        Draft02OutboundPreparation.Current(it.grant, it.authority, it.request, currentNow,
                            it.selectedSubscriptionId, it.cards())
                    }
                }
                try { guard(); checkLive(scope, phone) }
                catch (error: Exception) { (outcome as? SealedDispatchExecutor.Ready)?.prepared?.close(); throw error }
                if (outcome is SealedDispatchExecutor.Ready) SealedDispatchExecutor.Ready(guardedPrepared(scope, phone, outcome.prepared)) else outcome
            }
        } catch (_: Exception) { SealedDispatchExecutor.Unavailable }
        finally { owned.fill(0) }
    }
}

/** Separately testable lifetime fence; production passes ONLY an existing hardware-prepared holder. */
internal class ConversationConsumptionFence(
    private val admission: ConversationCaptureAdmission, private val checkAuthority: () -> Unit,
    private val scope: ConversationCaptureScope, private val discard: () -> Unit
) : AutoCloseable {
    private var consumed = false
    @Synchronized fun consume(consumePrepared: ((CharArray) -> Unit) -> Unit, consumer: (CharArray) -> Unit) {
        check(!consumed); consumed = true
        try {
            admission.withCurrentScope(scope) { guard ->
                guard(); checkAuthority()
                consumePrepared { chars -> guard(); checkAuthority(); consumer(chars) }
            }
        } catch (error: Exception) { discard(); throw error }
    }
    @Synchronized override fun close() { consumed = true; discard() }
}
