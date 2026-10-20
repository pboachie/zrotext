// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Build
import android.telephony.SmsManager
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Profile03 journal-before-maintained-receiver composition. No profile/provider fallback. */
internal object Draft03OutboundPreparation {
    /** Trusted adapter input. Public cryptographic evidence does not authenticate its receipt or
     * current permission. The socket/HTTP adapter must obtain those from its live selected session.
     * The same Room record and independently installed v2 SIM lease are checked here on every use.
     */
    class Current(
        val election: Draft03PayloadElectionProof, val authority: Draft03ManifestAuthority,
        val selection: Draft03PayloadElectionProof.CurrentAuthority03,
        val installation: Profile03ElectionRecord, val baseBinding: LocalLineBinding,
        val intent: ReviewedIntent03, intentSignature: ByteArray, val acceptedMs: Long,
        val selectionEpoch: Long, val ownerUserId: UUID, val ownerSessionId: UUID,
        val intervalStartsMs: Long, val intervalExpiresMs: Long,
        val selectedSubscriptionId: Int, activeCards: List<ActiveSimCard>?,
        internal val physicalSelection: InstalledSelectedLineV2? = baseBinding.installedSelectionV2(),
        internal val intervalRamCurrent: () -> Unit,
    ) {
        private val signature = intentSignature.copyOf()
        private val cards = activeCards?.toList()
        fun signature() = signature.copyOf()
        internal fun cards() = cards?.toList()
        override fun toString() = "Profile03Current(redacted)"
    }
    sealed interface Result
    data object Unavailable : Result
    data object Unsupported : Result
    data object Rejected : Result
    class Ready(val prepared: Draft02OutboundPreparation.Prepared) : Result {
        override fun toString() = "Profile03Prepared(redacted)"
    }
    private class OwnedPrepared(private var chars: CharArray?, override val segmentCount: Int,
        private val recheck: () -> Unit) : Draft02OutboundPreparation.Prepared {
        @Synchronized override fun consume(consumer: (CharArray) -> Unit) {
            val owned = checkNotNull(chars)
            chars = null
            try { recheck(); consumer(owned) } finally { owned.fill('\u0000') }
        }
        @Synchronized override fun close() { chars?.fill('\u0000'); chars = null }
        override fun toString() = "Profile03OwnedText(redacted)"
    }

    fun prepare(input: ByteArray, received: SealedDispatch03Frames.Grant,
        session: SealedDispatchExecutor.Session, db: SmsJournalDatabase, keys: DevicePayloadKeyStore,
        trustedNow: () -> Long?, current: () -> Current?): Result {
        if (input.size !in 557..34_213) return Rejected
        val envelope = input.copyOf()
        val grant = SealedDispatch03Frames.grant(received.json()) // Own immutable exact scalar snapshots.
        if (Build.VERSION.SDK_INT < 31) { envelope.fill(0); return Unsupported }
        var reserved = false
        var handedOff = false
        var clear: CharArray? = null
        var verified: Draft03OutboundEnvelope? = null
        var initialIdentity: String? = null
        var initialPhysical: InstalledSelectedLineV2? = null
        var lastNow = 0L
        val dao = db.sealedPreparations()
        val record = SealedPreparationRecord(grant.accountId.toString(), grant.messageId.toString(),
            grant.attemptId.toString(), hex(grant.unsignedSha256),
            hash(SealedEnvelopeFetch03.transcript(grant) + uuid(session.sessionId) + session.originHash.toByteArray(Charsets.US_ASCII)))

        fun now(): Long = checkNotNull(trustedNow()).also {
            check(it > 0 && it >= lastNow && it < grant.expiresAtMs && grant.expiresAtMs - it <= 35_000)
            lastNow = it
        }
        fun selected(c: Current, line: LocalLineBinding?) {
            check(line != null && line == c.baseBinding && line.protocolVersion == 2 && line.v2Purpose == "sealed" &&
                line.accountId == session.accountId.toString() && line.deviceId == session.deviceId.toString() &&
                line.lineId == grant.lineId.toString() && line.generation == c.installation.oldGeneration &&
                line.subscriptionId == c.selectedSubscriptionId)
            val permit = checkNotNull(line.installedSelectionV2())
            check(permit === c.physicalSelection && permit.isCurrent() && permit.record.isInstalled() && permit.matches(line) &&
                SimCardContinuity.matches(line.activatedSim(), c.cards()))
        }
        fun fresh(): Current {
            now()
            val c = checkNotNull(current())
            c.intervalRamCurrent()
            val row = c.installation
            row.requireShape()
            check(row.state == "installed" && row.accountId == session.accountId.toString() &&
                row.deviceId == session.deviceId.toString() && row.lineId == grant.lineId.toString() &&
                row.originHash == session.originHash && row.newGeneration == grant.bindingGeneration &&
                row.readerKeyId == hex(grant.readerKeyId) && row.rootFingerprint == hex(grant.rootFingerprint))
            val accepted = c.election.acceptedRecord()
            check(row.acceptedEvidenceSha256 == acceptedIdentity(accepted) &&
                row.newBindingId == id(accepted.newBindingId) && row.oldBindingId == id(accepted.oldBindingId) &&
                row.oldGeneration == accepted.oldBindingGeneration && row.newGeneration == accepted.newBindingGeneration &&
                row.readerKeyId == hex(accepted.selectedReaderKeyId))
            check(hash(Profile03ElectionEncoding.decode(row.coreB64url, 500)) == hex(accepted.electionCoreSha256) &&
                hash(Profile03ElectionEncoding.decode(checkNotNull(row.deviceSignatureB64url), 64)) ==
                hex(c.election.deviceProofSha256()))
            check(grant.accountId == session.accountId && grant.deviceId == session.deviceId &&
                grant.connectionEpoch == session.connectionEpoch && grant.deploymentEpoch == session.deploymentEpoch)
            selected(c, c.baseBinding)
            check(initialPhysical == null || initialPhysical === c.physicalSelection)
            initialPhysical = checkNotNull(c.physicalSelection)
            // Reentrant Room transaction: when called by reserve/finish this shares their writer snapshot.
            db.profile03Elections().requireInstalled(row, grant.attemptId.toString()) { selected(c, it) }
            val instant = now() // Authority, Room and SIM/key providers above may wait.
            val comparison = c.election.requireCurrent(c.authority, c.selection, instant)
            check(grant.expiresAtMs <= c.selection.permissionExpiresAtMs &&
                grant.trustGeneration == c.selection.vaultGeneration && grant.manifestVersion == c.selection.manifestVersion &&
                same(grant.manifestDigest, c.selection.manifestDigest) && same(grant.electionDigest, c.selection.electionCommitment))
            c.intent.requireGrant(grant)
            check(c.intent.ownerUserId == c.ownerUserId && c.intent.ownerSessionId == c.ownerSessionId)
            val request = c.intent.verifyReceipt(c.signature(), c.authority, comparison, c.acceptedMs, instant,
                c.selectionEpoch, unhex(session.originHash), c.intervalStartsMs, c.intervalExpiresMs)
            verified?.parts(c.authority, request, instant)
            val identity = hash(row.acceptedEvidenceSha256.toByteArray(Charsets.US_ASCII) + c.intent.bytes() +
                c.signature() + ByteBuffer.allocate(8).putLong(c.acceptedMs).array())
            check(initialIdentity == null || initialIdentity == identity)
            initialIdentity = identity
            val completed = now()
            c.election.requireCurrent(c.authority, c.selection, completed)
            selected(c, c.baseBinding) // RAM-only permit; no platform call after the final clock.
            c.intervalRamCurrent()
            return c
        }
        fun line(binding: LocalLineBinding?) { val c = fresh(); selected(c, binding) }
        fun receiverGuard(c: Current, authorityDeadline: Long) {
            // Invoked while custody is held: no Room, network, key lookup or framework acquisition.
            // trustedNow is the authenticated session's monotonic RAM anchor, unavailable on loss.
            val instant = now()
            check(instant >= c.selection.comparedAtMs && instant < authorityDeadline)
            selected(c, c.baseBinding)
            c.intervalRamCurrent()
        }
        try {
            if (current() == null || trustedNow() == null) return Unavailable
            val first = fresh()
            val proof = Draft03OutboundEnvelope.verify(envelope, first.authority, first.intent.request()) { fresh(); lastNow }
            verified = proof
            check(same(proof.envelopeDigest, grant.envelopeSha256) && same(proof.unsignedDigest, grant.unsignedSha256))
            fresh()
            dao.reserve03(record, first.installation, ::line)
            reserved = true
            val beforeKey = fresh() // A writer wait cannot carry stale permission into the Keystore.
            val public = keys.existingPublic() // Never enrolls or replaces a missing/revoked recipient.
            check(public.security in setOf(PayloadKeySecurity.STRONGBOX, PayloadKeySecurity.TRUSTED_ENVIRONMENT) &&
                same(public.keyId, grant.readerKeyId))
            val checked = beforeKey.authority.context(beforeKey.intent.request(), lastNow, beforeKey.intent.expiresMs)
            check(same(beforeKey.authority.readerPoint(checked, Draft03ManifestAuthority.Reader(1, grant.readerKeyId), lastNow),
                public.point))
            val active = fresh()
            val parts = proof.parts(active.authority, active.intent.request(), lastNow)
            check(same(parts.keyId, public.keyId) && parts.wrap.size == 48)
            // Capture the cryptographically verified key/manifest bound before custody is held.
            // A long adapter lease can never extend it, and the guard performs no provider work.
            val activeContext = active.authority.context(active.intent.request(), lastNow, active.intent.expiresMs)
            val authorityDeadline = minOf(grant.expiresAtMs, activeContext.notAfterMs,
                activeContext.authorityExpiresAtMs, active.selection.permissionExpiresAtMs, active.intervalExpiresMs)
            // The sole production03 recipient. Never call Draft02 JCA HPKE or retry another provider.
            val cek = WolfHpkeKeystoreReceiver(keys).openCurrent(parts.keyId, parts.enc, parts.wrap, parts.info, parts.aad) {
                receiverGuard(active, authorityDeadline)
            }
            try {
                check(cek.size == 32)
                val after = fresh()
                clear = Draft03Body.open(proof, after.authority, after.intent.request(), lastNow, cek)
            } finally { cek.fill(0) }
            val body = checkNotNull(clear)
            val encoded = Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(body))
            val bodyBytes = ByteArray(encoded.remaining()).also(encoded::get)
            try { check(same(MessageDigest.getInstance("SHA-256").digest(bodyBytes), fresh().intent.bodySha256)) }
            finally { bodyBytes.fill(0); if (encoded.hasArray()) encoded.array().fill(0) }
            val live = fresh()
            val manager = SmsManager.getSmsManagerForSubscriptionId(live.selectedSubscriptionId)
            val count = Draft02OutboundPreparation.segmentCount(body, manager::divideMessage)
            check(count <= grant.segmentCount && count <= live.intent.segmentCeiling)
            dao.finish(record, count, ::line)
            line(db.attempts().currentLineBinding())
            fresh()
            val prepared = OwnedPrepared(body, count) { line(db.attempts().currentLineBinding()); fresh() }
            clear = null
            handedOff = true
            return Ready(prepared)
        } catch (_: UnsatisfiedLinkError) {
            return Unsupported
        } catch (_: Exception) {
            return Rejected
        } finally {
            clear?.fill('\u0000')
            envelope.fill(0)
            if (reserved && !handedOff) runCatching { dao.abort(record.accountId, record.messageId, record.attemptId) }
            // UNKNOWN, PREPARING, PREPARED and ABORTED rows all remain permanent no-reentry fences.
        }
    }

    /** Domain-separated exact accepted record identity, including allocation and original time. */
    internal fun acceptedIdentity(a: Draft03PayloadElectionProof.AcceptedRecord03): String = hash(
        "ZTSE/android/accepted-election/v1\u0000".toByteArray(Charsets.US_ASCII) +
            a.accountId + a.deviceId + a.lineId + a.rootFingerprint +
            ByteBuffer.allocate(8).putLong(a.vaultGeneration).array() + a.oldBindingId +
            ByteBuffer.allocate(8).putLong(a.oldBindingGeneration).array() + a.oldBindingProofDigest + a.newBindingId +
            ByteBuffer.allocate(8).putLong(a.newBindingGeneration).array() + a.selectedReaderKeyId +
            ByteBuffer.allocate(8).putLong(a.priorManifestVersion).array() + a.priorManifestDigest + a.priorSignedManifestSha256 +
            ByteBuffer.allocate(8).putLong(a.acceptedManifestVersion).array() + a.acceptedManifestDigest +
            a.acceptedSignedManifestSha256 + a.electionCoreSha256 + a.electionCommitment + a.electionBundleSha256 +
            ByteBuffer.allocate(8).putLong(a.acceptedAtMs).array())
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    private fun hash(bytes: ByteArray) = hex(MessageDigest.getInstance("SHA-256").digest(bytes))
    private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
    private fun unhex(value: String) = value.also { require(it.matches(Regex("[0-9a-f]{64}"))) }
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun uuid(value: UUID) = ReviewedIntent03.uuid(value)
    private fun id(bytes: ByteArray) = ByteBuffer.wrap(bytes).let { UUID(it.long, it.long).toString() }
}
