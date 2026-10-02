// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.zrotext.gateway.SealedExecutionGrantValidator.Verdict.Refused as GrantRefusal

/**
 * Grant-driven caller that wires sealed execution to trusted session time and
 * journaled submission (roadmap #628).
 *
 * Disabled on ordinary startup: the default build never offers sealed dispatch
 * ([DeviceStatusPublisher.OFFER] carries no sealed token). An explicitly installed
 * owner-provisioned process lease lets [SealedExecutionConnection] construct this
 * lane after authenticated v2 time/session sampling. Unnegotiated grants remain
 * unparsed. The lane enforces the post-negotiation
 * behavior before any enabling slice exists: given one grant frame from the
 * authenticated session it fetches only the grant-bound envelope by digest,
 * refuses without vouched trusted time, runs the existing executor fences
 * under the current root/line/device authority, and only then applies the
 * pre-submit fences and the one-use journaled submission.
 *
 * Trusted time comes from [SealedSessionClock]: the lane refuses before any
 * fetch or decrypt when the clock does not vouch for this session's
 * connection epoch, and the executor sees `null` time (its own refusal) when
 * the anchor has reset (reboot) or aged out. There is no fallback wall time.
 *
 * The durable one-use intent is the `sealed_preparations` journal row the
 * executor's preparation writes before the Keystore HPKE open; every retained
 * row is a permanent replay fence, so a crash anywhere after that commit can
 * never re-enter preparation for the same message. The pre-submit fences
 * below recheck, after decryption and before the submit seam, exactly the
 * conditions the issue names: vouched time and expiry, session cancellation,
 * SIM/card continuity, local suppression and the granted segment cap. A fence
 * refusal closes the zeroizing holder, aborts the journal row (the row stays
 * as the fence) and never touches the submit seam.
 *
 * The submit seam is the radio boundary, passed the prepared text as a one-use
 * `consumeText` closure plus its segment count (the same primitive shape as
 * [SealedDispatchExecutor.settle], because the JVM has no Android Keystore
 * and tests must drive this stage without one). Production wiring would run
 * every radio read and at most one SmsManager call inside `consumeText`; no
 * [SealedExecutionConnection] uses the shared durable intent/ACK/radio path; tests
 * inject a no-radio fake. A
 * return is not a delivery acknowledgment, a throwing seam is an ambiguous
 * outcome that stays [Submission.UNKNOWN], and nothing here ever retries:
 * [SealedExecutionGrantFrame.refusal] reporting and later grant decisions
 * belong to the caller. The lane itself closes the holder on every path
 * after handing it over; zeroizing is idempotent.
 *
 * Single-threaded contract: one lane per authenticated session, invoked on
 * the journal thread, like the alpha submit path. No envelope byte, digest,
 * key, peer or plaintext is logged or retained by this object.
 */
internal class SealedDispatchLane(
    /** The authenticated stream session the grant must bind to; never frame-supplied. */
    private val session: SealedDispatchExecutor.Session,
    /** Trusted time anchored to this session's connection epoch. */
    private val clock: SealedSessionClock,
    /** Fetches exactly this device-signed grant's envelope over the authenticated API; null = unavailable. */
    private val fetchEnvelope: (grant: SealedExecutionGrantValidator.Fields) -> ByteArray?,
    /** Current device-local truth; null (no binding, no pinned key, no authority) is a refusal. */
    private val localTruth: () -> SealedDispatchExecutor.Local?,
    private val db: SmsJournalDatabase,
    private val keyStore: DevicePayloadKeyStore,
    /** Monotonic elapsed clock, `SystemClock::elapsedRealtime` in production. */
    private val elapsedRealtime: () -> Long,
    /** Current root/manifest authority, subscription and active cards, re-obtained on every call. */
    private val current: (Draft02OutboundPreparation.Grant) -> Draft02OutboundPreparation.Current?,
    /** Local STOP/withdrawal lookup for the recipient peer; failing closed equals suppressed. */
    private val isRecipientSuppressed: (peer: ByteArray) -> Boolean,
    /** Active SIM cards for the continuity recheck; null or a changed card fails the fence. */
    private val activeCards: () -> List<ActiveSimCard>?,
    /** Live session currency (a reconnect mid-flight cancels the submission). */
    private val isSessionCurrent: () -> Boolean,
    /**
     * The one radio boundary. Must run all radio work inside `consumeText`
     * (one use) and report; never retries and never stores the text.
     */
    private val submit: (
        fields: SealedExecutionGrantValidator.Fields,
        segments: Int,
        consumeText: ((CharArray) -> Unit) -> Unit,
    ) -> Submission,
) {
    /** The submit seam's report; neither value is a delivery acknowledgment. */
    enum class Submission { SUBMITTED, UNKNOWN }

    /**
     * Post-decrypt local fences. Each means: prepared text closed, journal
     * row aborted, no radio, no retry, no re-entry for the same message.
     */
    enum class Fence { SESSION_TIME, EXPIRY, SESSION_CANCELLED, SIM_CARD_CONTINUITY, LOCAL_SUPPRESSION, SEGMENT_CAP }

    sealed interface Outcome {
        /** A pre-decrypt refusal with its fixed reportable reason code. */
        data class Refused(val reason: SealedExecutionGrantValidator.Verdict.Refused) : Outcome

        /** Trusted time, the fetch, local truth or custody was unavailable; no decrypt, no journal row. */
        data object Unavailable : Outcome

        /** The envelope or device state is unsupported for sealed execution. */
        data object Unsupported : Outcome

        /** The preparation refused the grant (including the journal replay fence). */
        data object Rejected : Outcome

        /** A pre-submit fence refused after decryption; plaintext was closed and the row aborted. */
        data class FenceRefused(val fence: Fence) : Outcome

        /** The submit seam ran; ambiguity stays [Submission.UNKNOWN] and never auto-resends. */
        data class Submitted(val result: Submission) : Outcome
    }

    @Volatile
    private var tornDown = false

    /**
     * Dispatches one grant frame. A structurally malformed frame throws from
     * the strict parser, which the stream caller treats as a protocol
     * rejection of the whole frame (the documented contract); nothing has been
     * fetched, decrypted or journaled at that point.
     */
    fun onGrant(frame: JSONObject): Outcome {
        if (tornDown) return Outcome.Unavailable
        val fields = SealedExecutionGrantFrame.parse(frame)
        // A clock from another epoch never vouches for this session's grants:
        // refuse before any fetch, so a stale lane cannot pull envelopes.
        if (!clock.isCurrentSession(session.connectionEpoch)) return Outcome.Unavailable
        val now = runCatching { clock.nowMs(elapsedRealtime()) }.getOrNull() ?: return Outcome.Unavailable
        if (now >= fields.expiresAtMs) return Outcome.Refused(SealedExecutionGrantValidator.Verdict.Refused.EXPIRED)
        val local = localTruth() ?: return Outcome.Unavailable
        headerRefusal(fields, local, now)?.let { return Outcome.Refused(it) }
        // Fetch only the grant-bound envelope; the executor still binds the
        // grant to the SHA-256 of exactly these bytes (digest mismatch refuses).
        val envelope = fetchEnvelope(SealedEnvelopeFetch.snapshot(fields)) ?: return Outcome.Unavailable
        return when (val outcome = SealedDispatchExecutor.execute(
            fields, envelope, session, local, db, keyStore,
            { clock.nowMs(elapsedRealtime()) },
            current,
        )) {
            is SealedDispatchExecutor.Ready -> submitUnderFences(
                fields, local,
                outcome.prepared.segmentCount,
                { consumer -> outcome.prepared.consume(consumer) },
                { outcome.prepared.close() },
            )
            is SealedDispatchExecutor.Refused -> Outcome.Refused(outcome.reason)
            SealedDispatchExecutor.Unavailable -> Outcome.Unavailable
            SealedDispatchExecutor.Unsupported -> Outcome.Unsupported
            SealedDispatchExecutor.Rejected -> Outcome.Rejected
        }
    }

    /**
     * Pre-submit fences and the one-use journaled submission, over the
     * prepared text's primitive seams. Internal so the JVM no-radio tests can
     * drive the post-decrypt stage directly (the JVM has no Android Keystore,
     * so a real bound grant stops at the custody fence inside
     * [Draft02OutboundPreparation.prepare] and never yields a holder).
     */
    internal fun submitUnderFences(
        fields: SealedExecutionGrantValidator.Fields,
        local: SealedDispatchExecutor.Local,
        segments: Int,
        consumeText: ((CharArray) -> Unit) -> Unit,
        closeText: () -> Unit,
    ): Outcome {
        fun refused(fence: Fence): Outcome {
            closeText()
            runCatching {
                db.sealedPreparations().abort(
                    fields.accountId.toString(), fields.messageId.toString(), fields.attemptId.toString(),
                )
            }
            return Outcome.FenceRefused(fence)
        }
        // Own the prepared holder across every fence callback, including failures.
        try {
            // Fixed order, each fail-closed, none skippable:
            val now = runCatching { clock.nowMs(elapsedRealtime()) }.getOrNull()
                ?: return refused(Fence.SESSION_TIME)
            if (now >= fields.expiresAtMs) return refused(Fence.EXPIRY)
            if (!runCatching { isSessionCurrent() }.getOrDefault(false)) return refused(Fence.SESSION_CANCELLED)
            val cards = runCatching { activeCards() }.getOrNull()
            if (!SimCardContinuity.matches(
                    local.binding.cardId?.let { ActivatedSimCard(local.binding.subscriptionId, it) },
                    cards,
                )
            ) return refused(Fence.SIM_CARD_CONTINUITY)
            // Bind the lookup to the preparation's immutable recipient digest;
            // changing current authority cannot select another peer for STOP.
            val peer = currentPeer(fields, local) ?: return refused(Fence.LOCAL_SUPPRESSION)
            if (runCatching { isRecipientSuppressed(peer) }.getOrDefault(true)) return refused(Fence.LOCAL_SUPPRESSION)
            if (segments > fields.segmentCount) return refused(Fence.SEGMENT_CAP)
            return try {
                Outcome.Submitted(submit(fields, segments, consumeText))
            } catch (_: Exception) {
                // A throw may follow a partial radio action: ambiguous, and the
                // journal row must stay as the permanent replay fence.
                Outcome.Submitted(Submission.UNKNOWN)
            }
        } finally {
            closeText() // Idempotent: consumed, refused and throwing callbacks all relinquish custody.
        }
    }

    /** Permanent lane teardown: further grants are unavailable, never executed. */
    fun teardown() {
        tornDown = true
    }

    /** Refuse known foreign identities before using the enrollment signing key for retrieval. */
    private fun headerRefusal(fields: SealedExecutionGrantValidator.Fields,
        local: SealedDispatchExecutor.Local, now: Long): SealedExecutionGrantValidator.Verdict.Refused? {
        return when {
            fields.accountId != session.accountId -> GrantRefusal.ACCOUNT_MISMATCH
            fields.deviceId != session.deviceId -> GrantRefusal.DEVICE_MISMATCH
            fields.lineId.toString() != local.binding.lineId -> GrantRefusal.LINE_MISMATCH
            fields.connectionEpoch != session.connectionEpoch -> GrantRefusal.SESSION_MISMATCH
            fields.deploymentEpoch != session.deploymentEpoch -> GrantRefusal.DEPLOYMENT_MISMATCH
            fields.bindingGeneration != local.binding.generation -> GrantRefusal.BINDING_GENERATION_MISMATCH
            fields.readerRole != 1 -> GrantRefusal.READER_ROLE_MISMATCH
            !java.security.MessageDigest.isEqual(fields.readerKeyId, local.pinnedReaderKeyId) -> GrantRefusal.READER_KEY_MISMATCH
            fields.messageId == java.util.UUID(0, 0) || fields.attemptId == java.util.UUID(0, 0) -> GrantRefusal.MESSAGE_OR_ATTEMPT_MISMATCH
            fields.segmentCount !in 1..6 -> GrantRefusal.SEGMENT_COUNT_OUT_OF_RANGE
            fields.expiresAtMs - now > SealedExecutionGrantValidator.MAX_GRANT_FUTURE_MS -> GrantRefusal.IMPLAUSIBLE_EXPIRY
            else -> null
        }
    }

    /** The recipient peer under the current authority, or null when it cannot be established. */
    private fun currentPeer(
        fields: SealedExecutionGrantValidator.Fields,
        local: SealedDispatchExecutor.Local,
    ): ByteArray? = runCatching {
        current(SealedDispatchExecutor.candidate(fields, session, local))?.request?.peer()
            ?.takeIf { Draft02OutboundPreparation.hash(it) == local.recipientDigest }
    }.getOrNull()
}
