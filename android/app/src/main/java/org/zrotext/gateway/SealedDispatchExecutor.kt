// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID

/**
 * Grant-bound sealed decrypt executor (roadmap #539). Dormant: no stream handler or
 * service calls it, because no hub emits the PROPOSED `sealed_execution_grant` frame
 * and this client never negotiates it.
 *
 * Order of fences, each fail-closed and none reachable without the previous one:
 * 1. the envelope is bounded by the sealed-v1 profile-02 outbound parser before the
 *    grant is consulted (a malformed envelope never consumes a grant);
 * 2. [SealedExecutionGrantValidator] binds the grant to the authenticated account and
 *    device, the active line and binding generation, the envelope's claimed message,
 *    the device-payload reader role and this device's own Keystore key ID, the session
 *    and deployment epochs, the exact envelope bytes and a bounded trusted-time expiry;
 * 3. only then is the existing [Draft02OutboundPreparation.prepare] entered. It
 *    authenticates the envelope against the grant's message, journals the attempt in
 *    `sealed_preparations` before the Keystore HPKE open, zeroizes every key and
 *    plaintext buffer it owns, and aborts the journal row on any later failure;
 * 4. a prepared text needing more segments than the grant authorizes is closed
 *    (zeroized) and its journal row aborted.
 *
 * A refusal never decrypts, writes no journal row (fences 1 and 2) and is never
 * retried here; the caller reports it (see [SealedExecutionGrantFrame.refusal]).
 * No envelope byte, digest, key or plaintext is logged or stored by this object.
 */
internal object SealedDispatchExecutor {
    /** The authenticated stream session: identity the socket proved, never frame-supplied. */
    class Session(
        val accountId: UUID,
        val deviceId: UUID,
        val connectionEpoch: Long,
        val deploymentEpoch: Long,
        val sessionId: UUID,
        val originHash: String,
    ) {
        override fun toString() = "SealedDispatchSession(redacted)"
    }

    /** Device-local truth the hub cannot supply. */
    class Local(
        val binding: LocalLineBinding,
        pinnedReaderKeyId: ByteArray,
        val manifestGeneration: Long,
        val manifestVersion: Long,
        val manifestDigest: String,
        val recipientDigest: String,
    ) {
        private val readerKey = pinnedReaderKeyId.copyOf()
        val pinnedReaderKeyId: ByteArray get() = readerKey.copyOf()
        override fun toString() = "SealedDispatchLocal(redacted)"
    }

    sealed interface Outcome
    data class Refused(val reason: SealedExecutionGrantValidator.Verdict.Refused) : Outcome
    data object Unavailable : Outcome
    data object Unsupported : Outcome
    data object Rejected : Outcome

    /** Owns the one-use zeroizing text holder; the caller must consume or close it. */
    class Ready(val prepared: Draft02OutboundPreparation.Prepared) : Outcome {
        override fun toString() = "SealedDispatchReady(redacted)"
    }

    fun execute(
        grant: SealedExecutionGrantValidator.Fields,
        envelope: ByteArray,
        session: Session,
        local: Local,
        db: SmsJournalDatabase,
        keyStore: DevicePayloadKeyStore,
        trustedNowMs: () -> Long?,
        current: (Draft02OutboundPreparation.Grant) -> Draft02OutboundPreparation.Current?,
    ): Outcome {
        val owned = envelope.copyOf()
        try {
            val claims = try {
                claims(Draft02OutboundEnvelope.routingClaims(owned))
            } catch (_: Exception) {
                return Refused(SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_MALFORMED)
            }
            val now = trustedNowMs() ?: return Unavailable
            val verdict = SealedExecutionGrantValidator.validate(
                grant, owned, claims, session.accountId, session.deviceId,
                UUID.fromString(local.binding.lineId), session.connectionEpoch, session.deploymentEpoch,
                local.binding.generation, local.pinnedReaderKeyId, now,
            )
            if (verdict is SealedExecutionGrantValidator.Verdict.Refused) return Refused(verdict)
            val candidate = try {
                candidate(grant, session, local)
            } catch (_: Exception) {
                return Rejected
            }
            return when (val result = Draft02OutboundPreparation.prepare(owned, candidate, db, keyStore) {
                current(candidate)
            }) {
                is Draft02OutboundPreparation.Prepared -> settle(result.segmentCount, grant.segmentCount, {
                    result.close()
                    db.sealedPreparations().abort(candidate.accountId, candidate.messageId, candidate.attemptId)
                }) { Ready(result) }
                Draft02OutboundPreparation.Unavailable -> Unavailable
                Draft02OutboundPreparation.Unsupported -> Unsupported
                Draft02OutboundPreparation.Rejected -> Rejected
            }
        } finally {
            owned.fill(0)
        }
    }

    /**
     * Post-decrypt grant fence: more segments than the grant authorizes closes the
     * zeroizing holder and aborts the journal row before any submit intent exists.
     */
    internal fun settle(prepared: Int, authorized: Int, discard: () -> Unit, ready: () -> Outcome): Outcome {
        if (prepared > authorized) {
            discard()
            return Refused(SealedExecutionGrantValidator.Verdict.Refused.SEGMENT_COUNT_EXCEEDS_GRANT)
        }
        return ready()
    }

    /** The existing candidate-preparation contract, assembled from the validated wire grant and local truth. */
    internal fun candidate(grant: SealedExecutionGrantValidator.Fields, session: Session, local: Local) =
        Draft02OutboundPreparation.Grant(
            accountId = grant.accountId.toString(),
            messageId = grant.messageId.toString(),
            attemptId = grant.attemptId.toString(),
            deviceId = grant.deviceId.toString(),
            lineId = grant.lineId.toString(),
            bindingGeneration = grant.bindingGeneration,
            attemptGeneration = grant.attemptGeneration,
            connectionEpoch = grant.connectionEpoch,
            deploymentEpoch = grant.deploymentEpoch,
            sessionId = session.sessionId.toString(),
            originHash = session.originHash,
            unsignedDigest = Draft02OutboundPreparation.hex(grant.unsignedDigest),
            manifestGeneration = local.manifestGeneration,
            manifestVersion = local.manifestVersion,
            manifestDigest = local.manifestDigest,
            recipientDigest = local.recipientDigest,
            expiresAtMs = grant.expiresAtMs,
            subscriptionId = local.binding.subscriptionId,
            // A pre-v11 binding without a card ID stays local-only, as everywhere else.
            cardId = checkNotNull(local.binding.cardId) { "Line binding has no card continuity" },
        )

    private fun claims(routing: Draft02OutboundEnvelope.Companion.RoutingClaims) =
        SealedExecutionGrantValidator.EnvelopeClaims(
            uuid(routing.accountId), uuid(routing.messageId), uuid(routing.deviceId),
            uuid(routing.lineId), routing.deviceReaderKeyId,
        )

    private fun uuid(bytes: ByteArray): UUID = ByteBuffer.wrap(bytes).let { UUID(it.long, it.long) }
}
