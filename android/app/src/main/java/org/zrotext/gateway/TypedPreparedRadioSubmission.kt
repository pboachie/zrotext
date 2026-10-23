// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** The sole implementation below is private and minted after actual typed ACK verification
 * and Room entry COMMIT, never from a public phase/Boolean or cold read. Sealed syntax itself
 * is not a same-file, hardware or authority boundary. */
internal sealed interface TypedPlatformStart { fun consume() }
private class CommittedTypedPlatformStart(private val ramCurrent: () -> Unit) : TypedPlatformStart {
    private val unused = AtomicBoolean(true)
    override fun consume() { check(unused.compareAndSet(true, false)); ramCurrent() }
}

/** Actual typed03 orchestration after maintained preparation. Every full authority/provider
 * check runs outside the Room writer; transactions get only the original RAM lifetime.
 * This path never inserts an AlphaRadioEvent or consumes a legacy radio-start Boolean. */
internal class TypedPreparedRadioSubmission(private val db: SmsJournalDatabase,
    private val transport: TypedSubmit03Transport, private val time: Profile03SessionTime,
    private val existingEnrollmentPoint: () -> ByteArray, private val connectionCurrent: () -> Unit,
    private val platform: (LocalLineBinding) -> ConversationRadioPlatform,
    private val closeBeforeEntry: (TypedSubmit03Record, () -> Unit) -> Unit) {
    fun submit(input: SealedDispatch03Frames.Grant, prepared: Draft02OutboundPreparation.Prepared,
        original: () -> Draft03OutboundPreparation.Current,
        verifySubmit: (TypedSubmit03Wire.Ack, TypedSubmit03Command) -> Draft03OutboundPreparation.Current): ConversationSubmission {
        val grant = SealedDispatch03Frames.grant(input.json())
        val identity = checkNotNull(time.snapshot()).first
        val session = identity.session
        val active = AtomicBoolean(true)
        var retained: TypedSubmit03Record? = null
        var entryCommitted = false
        var latest: Draft03OutboundPreparation.Current? = null
        var lastNow = 0L
        fun now(): Long {
            connectionCurrent()
            check(active.get() && time.snapshot()?.first?.session === session)
            return checkNotNull(time.nowMs()).also {
                check(active.get() && it > 0 && it >= lastNow && it < grant.expiresAtMs)
                lastNow = it
            }
        }
        fun ram() {
            now()
            val current = checkNotNull(latest)
            current.origins.requireSession(session)
            current.intervalRamCurrent()
            val physical = checkNotNull(current.physicalSelection)
            check(physical.isCurrent() && current.baseBinding.installedSelectionV2() === physical)
            connectionCurrent(); check(active.get())
        }
        fun checked(current: Draft03OutboundPreparation.Current): Draft03OutboundPreparation.Current {
            latest = current
            current.origins.requireSession(session)
            current.intent.requireGrant(grant)
            Profile03RadioContext(grant, session, current).requireGrantBinding(current.baseBinding)
            val at = now()
            current.election.requireCurrent(current.authority, current.selection, at)
            require(grant.expiresAtMs <= current.selection.permissionExpiresAtMs &&
                prepared.segmentCount in 1..current.intent.segmentCeiling && prepared.segmentCount <= grant.segmentCount)
            ram()
            return current
        }
        try {
            val initial = checked(original())
            val point = existingEnrollmentPoint().copyOf()
            // An existing-key wait cannot substitute a new original actor or carry stale time.
            val afterKey = checked(original())
            require(same(initial.intent.bytes(), afterKey.intent.bytes()) &&
                initial.installation == afterKey.installation && same(initial.signature(), afterKey.signature()))
            require(same(Profile03RetainedElection.signingId(point),
                Profile03ElectionEncoding.decode(afterKey.installation.coreB64url, 500).copyOfRange(288, 320)))
            val observed = now()
            val command = TypedSubmit03Command.create(grant.accountId.toString(), grant.deviceId.toString(),
                UUID.randomUUID().toString(), grant.messageId.toString(), grant.attemptId.toString(),
                TypedSubmit03Command.sha(SealedEnvelopeFetch03.transcript(grant)), identity.deviceSessionDigest(point),
                prepared.segmentCount, observed)
            val candidate = TypedSubmit03Record.candidateWithOrigin(command, point, session.originHash)
            val dao = db.typedSubmits03()
            if (!dao.reserveNewSubmit(candidate, ::ram)) return ConversationSubmission.UNKNOWN
            retained = candidate
            checked(original()) // Full post-COMMIT check outside the writer.
            val request = TypedSubmit03Request(candidate.attemptId, candidate.eventId, candidate.commandSha256,
                session.connectionEpoch, TypedSubmit03Record.base(TypedSubmit03Wire.request(command, grant, session)))
            val ticket = checkNotNull(dao.enterSubmit(candidate, request, ::ram))
            checked(original()) // Entry may have waited; no clock is gained from a history reply.
            val ack = transport.submit(ticket, grant, ::ram)
            if (!ack.submitOnce) return ConversationSubmission.UNKNOWN
            val acknowledged = checked(verifySubmit(ack, command))
            require(initial.installation == acknowledged.installation &&
                same(initial.intent.bytes(), acknowledged.intent.bytes()) && same(initial.signature(), acknowledged.signature()))
            check(dao.retainFirstAck(candidate, ack.bytes(), ::ram))
            val ackRow = checkNotNull(dao.get(candidate.attemptId))
            retained = ackRow
            require(ackRow.phase == "ack_authorized" && ackRow.commandSha256 == candidate.commandSha256)
            fun fresh(): Long { checked(verifySubmit(ack, command)); return now() }
            val context = Profile03RadioContext(grant, session, acknowledged)
            return platform(context.binding).submitTyped(context, prepared, ::fresh, db.attempts()::isRecipientSuppressed) {
                // Only RAM work runs under Room; final full/provider checks follow outside.
                val at = now()
                check(dao.retainPlatformEntry(ackRow, at, ::ram))
                entryCommitted = true
                CommittedTypedPlatformStart(::ram)
            }
        } catch (_: Exception) {
            return ConversationSubmission.UNKNOWN
        } finally {
            active.set(false)
            if (!entryCommitted) retained?.let { row ->
                // Withdraw synchronously before the asynchronous negative writer/clock path.
                runCatching { closeBeforeEntry(row) { active.set(false) } }
            }
        }
    }
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    override fun toString() = "TypedPreparedRadioSubmission(one-original-attempt)"
}
