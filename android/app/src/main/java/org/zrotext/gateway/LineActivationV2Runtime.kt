// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

internal class SignedLineActivationV2(statement: ByteArray, signature: ByteArray, point: ByteArray) {
    private val bytes = statement.copyOf()
    private val der = signature.copyOf()
    private val publicPoint = point.copyOf()
    fun statement() = bytes.copyOf()
    fun signature() = der.copyOf()
    fun point() = publicPoint.copyOf()
    override fun toString() = "SignedLineActivationV2(redacted)"
}

/** Only the authenticated receipt consumer implements the publication permit. */
internal sealed interface LineActivationV2PublicationPermit {
    val lease: SelectedLineLeaseV2
    val record: LineActivationV2Record
    val refresh03: InstalledSelectionRefresh03? get() = null
    fun publicationCurrent(): Boolean
    fun installationCurrent(): Boolean
    fun publicationComplete()
}

/** Fixture seam for key-operation waits. The production constructor always uses the existing key. */
internal interface LineActivationV2RuntimeSigner {
    fun point(purpose: LineActivationV2Purpose): ByteArray
    fun sign(purpose: LineActivationV2Purpose, fields: LineActivationV2StatementFields,
        lease: SelectedLineLeaseV2, fingerprint: ByteArray, expiresAtMs: Long,
        now: () -> Long, current: () -> Boolean): SignedLineActivationV2
}
private class ExistingLineActivationV2Signer(private val keys: DeviceSigningKeyStore) : LineActivationV2RuntimeSigner {
    override fun point(purpose: LineActivationV2Purpose) = keys.existingLineActivationV2Point(purpose)
    override fun sign(purpose: LineActivationV2Purpose, fields: LineActivationV2StatementFields,
        lease: SelectedLineLeaseV2, fingerprint: ByteArray, expiresAtMs: Long, now: () -> Long,
        current: () -> Boolean) = keys.signLineActivationV2(purpose, fields, lease, fingerprint, expiresAtMs, now, current)
}

/** Only the authenticated service constructs this consumer; a decoder supplies no authority. */
internal class LineActivationV2Runtime(
    private val account: UUID, private val device: UUID, private val epoch: Long,
    private val originHash: String, private val owner: LineActivationV2SelectedLineOwner,
    private val signer: LineActivationV2RuntimeSigner, private val database: SmsJournalDatabase,
    private val sessionCurrent: () -> Boolean, private val nowMs: () -> Long = System::currentTimeMillis
) : AutoCloseable {
    constructor(account: UUID, device: UUID, epoch: Long, originHash: String,
        owner: LineActivationV2SelectedLineOwner, keys: DeviceSigningKeyStore, database: SmsJournalDatabase,
        current: () -> Boolean, now: () -> Long = System::currentTimeMillis) :
        this(account, device, epoch, originHash, owner, ExistingLineActivationV2Signer(keys), database, current, now)
    private class AcceptedPublication(
        override val lease: SelectedLineLeaseV2, override val record: LineActivationV2Record,
        publication: () -> Boolean, private val installation: () -> Boolean
    ) : LineActivationV2PublicationPermit {
        private var publication: (() -> Boolean)? = publication
        override fun publicationCurrent() = publication?.let { runCatching(it).getOrDefault(false) } == true
        override fun installationCurrent() = runCatching(installation).getOrDefault(false)
        override fun publicationComplete() { publication = null }
    }
    private class Pending(val challenge: LineActivationV2IncomingFrames.Challenge,
        val lease: SelectedLineLeaseV2, val signed: SignedLineActivationV2,
        val record: LineActivationV2Record, val acceptance: SealedLineActivationMount.V2Acceptance?,
        var lastNow: Long) {
        var receipt: LineActivationV2IncomingFrames.SealedActivated? = null
    }
    @Volatile private var closed = false
    private val closeLock = Any()
    private var observedNow = 0L
    private val pending = mutableMapOf<LineActivationV2Purpose, Pending>()
    private val receiptRetries = mutableMapOf<String, LineActivationV2Record>()
    private val dao get() = database.lineActivationsV2()
    init { require(account != UUID(0, 0) && device != UUID(0, 0) && epoch > 0 && originHash.matches(Regex("[0-9a-f]{64}"))) }
    private fun current() = !closed && runCatching(sessionCurrent).getOrDefault(false)
    fun isCurrent() = current()
    private fun checkedNow(): Long {
        val value = nowMs()
        check(value > 0 && value >= observedNow)
        observedNow = value // A refused expiry cannot be revived by a later clock rollback.
        return value
    }

    @Synchronized fun accept(input: LineActivationV2IncomingFrames.Frame): String? {
        if (!current()) return null
        return try {
            when (input) {
                is LineActivationV2IncomingFrames.Challenge -> challenge(input)
                is LineActivationV2IncomingFrames.ProofAck -> { proofAck(input); null }
                is LineActivationV2IncomingFrames.SmsActivated -> { activated(input); null }
                is LineActivationV2IncomingFrames.SealedActivated -> activated(input)
                is LineActivationV2IncomingFrames.SealedInstallAck -> { installAck(input); null }
                is LineActivationV2IncomingFrames.SealedInstalled -> throw IllegalArgumentException("Wrong line receipt direction")
            }
        } catch (_: Exception) { null } // Unknown writes/sends never publish an installation claim.
    }
    /** The service retains the exact pending/receipt context until the actual socket write. */
    @Synchronized fun acceptAndSend(input: LineActivationV2IncomingFrames.Frame,
        transportCurrent: () -> Boolean, send: (String) -> Boolean): Boolean? {
        val output = accept(input) ?: return null
        return try {
            check(transportCurrent())
            when (input) {
                is LineActivationV2IncomingFrames.Challenge -> {
                    val p = checkNotNull(pending[input.purpose])
                    check(same(p.challenge, input))
                    requireLive(p, false)
                }
                is LineActivationV2IncomingFrames.SealedActivated -> {
                    val p = pending[LineActivationV2Purpose.SEALED]
                    if (p != null && p.record.matches(input) && p.receipt === input) requireLive(p, true)
                    else {
                        val retry = checkNotNull(receiptRetries[input.challengeId.toString()])
                        check(retry.matches(input))
                        requireReceiptRetry(retry)
                    }
                }
                else -> error("No outbound frame for this line exchange")
            }
            // No caller/provider work occurs between the final lease/time fence and socket write.
            try { send(output) } catch (_: Exception) { false } // The service retires transport on uncertain write.
        } catch (_: Exception) { null }
    }
    private fun same(a: LineActivationV2IncomingFrames.Challenge, b: LineActivationV2IncomingFrames.Challenge) =
        a.purpose == b.purpose && a.challengeId == b.challengeId && a.accountId == b.accountId &&
            a.deviceId == b.deviceId && a.lineId == b.lineId && a.generation == b.generation &&
            a.expiresAtMs == b.expiresAtMs && a.nonce().contentEquals(b.nonce()) &&
            (a !is LineActivationV2IncomingFrames.SealedChallenge ||
                b is LineActivationV2IncomingFrames.SealedChallenge && a.connectionEpoch == b.connectionEpoch)

    private fun requireChallenge(c: LineActivationV2IncomingFrames.Challenge) {
        check(current() && c.accountId == account && c.deviceId == device &&
            c.expiresAtMs <= Long.MAX_VALUE - 900_000L &&
            (c !is LineActivationV2IncomingFrames.SealedChallenge || c.connectionEpoch == epoch))
        val now = checkedNow()
        check(now > 0 && c.expiresAtMs - now in 1..300_000L)
    }
    /** Memory/time only. Framework, signer and Room waits must precede this final check. */
    private fun requireLive(p: Pending, acknowledgement: Boolean) {
        check(current() && p.lease.isCurrent() && p.acceptance?.isCurrent() != false)
        val now = checkedNow()
        val end = p.challenge.expiresAtMs + if (acknowledgement) 900_000L else 0L
        check(now > 0 && now >= p.lastNow && now < end && p.challenge.expiresAtMs - now <= 300_000L &&
            current() && p.lease.isCurrent() && p.acceptance?.isCurrent() != false)
        p.lastNow = now
    }
    private fun recheck(p: Pending, acknowledgement: Boolean) {
        check(p.lease.recheck())
        val point = signer.point(p.challenge.purpose)
        check(MessageDigest.isEqual(point, p.signed.point()) &&
            SealedLineActivationTranscript.verify(point, p.signed.statement(), p.signed.signature()))
        check(p.lease.recheck())
        requireLive(p, acknowledgement)
    }
    private fun proofFrame(p: Pending) = LineActivationV2Frames.proof(LineActivationV2Frames.ProofDeclaration(
        p.challenge.purpose, epoch, p.challenge.challengeId, p.lease.observation(), p.signed.signature()))

    private fun challenge(c: LineActivationV2IncomingFrames.Challenge): String? {
        requireChallenge(c)
        pending[c.purpose]?.let { old ->
            if (old.challenge.challengeId == c.challengeId) {
                if (!same(old.challenge, c)) { pending.remove(c.purpose); dao.retire(old.record); return null }
                recheck(old, false)
                return proofFrame(old)
            }
            pending.remove(c.purpose)
            dao.retire(old.record)
        }
        val acceptance = if (c.purpose == LineActivationV2Purpose.SEALED)
            SealedLineActivationMount.captureV2() ?: return null else null
        if (acceptance != null && (acceptance.value.accountId != account || acceptance.value.deviceId != device ||
                acceptance.value.lineId != c.lineId || acceptance.value.generation != c.generation)) return null
        val lease = owner.capture() ?: return null
        if (acceptance != null && (acceptance.lease !== lease || !acceptance.isCurrent())) return null
        val point = signer.point(c.purpose)
        val fingerprint = SealedLineActivationTranscript.digest(point)
        if (acceptance != null && !MessageDigest.isEqual(fingerprint, acceptance.value.fingerprint())) return null
        requireChallenge(c)
        check(lease.recheck())
        val record = LineActivationV2Record(c.purpose.journalName(), c.challengeId.toString(), account.toString(),
            device.toString(), c.lineId.toString(), c.generation, c.expiresAtMs, epoch, originHash,
            Draft02OutboundPreparation.hex(fingerprint), LineActivationV2JournalEncoding.encode(lease.observation().bytes()))
        fun beforeSignature() {
            requireChallenge(c)
            check(lease.isCurrent() && acceptance?.isCurrent() != false)
        }
        if (!dao.reserve(record, ::beforeSignature)) return null
        beforeSignature()
        val fields = LineActivationV2StatementFields(account, c.lineId, device, c.generation, c.challengeId, c.nonce())
        val signed = signer.sign(c.purpose, fields, lease, fingerprint, c.expiresAtMs, ::checkedNow) {
            current() && acceptance?.isCurrent() != false
        }
        val complete = record.copy(state = "signed",
            signatureDerB64url = LineActivationV2JournalEncoding.encode(signed.signature()),
            statementSha256 = Draft02OutboundPreparation.hash(signed.statement()),
            signatureSha256 = Draft02OutboundPreparation.hash(signed.signature()),
            confirmationSha256 = Draft02OutboundPreparation.hex(LineActivationV2Statements.proofDigest(
                c.purpose, signed.statement(), signed.signature())))
        val prepared = Pending(c, lease, signed, complete, acceptance, checkedNow())
        requireLive(prepared, false)
        if (!dao.recordSigned(complete) { requireLive(prepared, false) }) return null
        recheck(prepared, false)
        pending[c.purpose] = prepared
        return proofFrame(prepared)
    }
    private fun proofAck(a: LineActivationV2IncomingFrames.ProofAck) {
        if (a is LineActivationV2IncomingFrames.SealedProofAck && a.connectionEpoch != epoch) return
        val p = pending[a.purpose]?.takeIf { it.challenge.challengeId == a.challengeId } ?: return
        if (!a.accepted) { pending.remove(a.purpose); dao.retire(p.record); return }
        requireLive(p, false)
        dao.proofRecorded(p.record) { requireLive(p, false) }
    }
    private fun activated(a: LineActivationV2IncomingFrames.Receipt): String? {
        if (a.accountId != account || a.deviceId != device ||
            a is LineActivationV2IncomingFrames.SealedActivated && a.connectionEpoch != epoch) return null
        val p = pending[a.purpose]?.takeIf { it.record.matches(a) }
        if (p == null) return retryReceipt(a)
        recheck(p, true)
        val binding = p.record.binding(p.lease.selected.subscriptionId, p.lastNow)
        if (!dao.recordFinal(p.record, binding) { requireLive(p, true) }) return null
        recheck(p, true)
        val stored = dao.find(p.record.purpose, p.record.challengeId) ?: return null
        check(stored.sameProof(p.record) && stored.matches(a) &&
            database.attempts().currentLineBinding()?.let(stored::matchesBinding) == true)
        requireLive(p, true)
        if (a is LineActivationV2IncomingFrames.SealedActivated) {
            p.receipt = a
            return LineActivationV2Frames.installed(a, epoch)
        }
        if (!dao.installed(p.record) { requireLive(p, true) }) return null
        val installed = dao.find(p.record.purpose, p.record.challengeId) ?: return null
        recheck(p, true)
        check(installed.sameProof(p.record) && installed.isInstalled() &&
            database.attempts().currentLineBinding()?.let(installed::matchesBinding) == true)
        requireLive(p, true)
        check(owner.publish(AcceptedPublication(p.lease, installed,
            { requireLive(p, true); true }, { current() })) != null)
        pending.remove(a.purpose) // Release the nonce-containing statement after final acceptance.
        return null
    }
    /** Durable provenance may retry a receipt; it never reconstructs a selected lease. */
    private fun retryReceipt(a: LineActivationV2IncomingFrames.Receipt): String? {
        if (a !is LineActivationV2IncomingFrames.SealedActivated) return null
        val record = dao.find("sealed", a.challengeId.toString()) ?: return null
        record.requireShape()
        if (!record.matches(a) || record.state !in setOf("final_recorded", "installed") || record.originHash != originHash ||
            database.attempts().currentLineBinding()?.let(record::matchesBinding) != true) return null
        requireReceiptRetry(record)
        receiptRetries[record.challengeId] = record
        return LineActivationV2Frames.installed(a, epoch)
    }
    private fun requireReceiptRetry(record: LineActivationV2Record) {
        check(current() && record.accountId == account.toString() && record.deviceId == device.toString())
        val point = signer.point(LineActivationV2Purpose.SEALED)
        check(Draft02OutboundPreparation.hash(point) == record.signerFingerprint)
        val now = checkedNow()
        check(now > 0 && now < record.expiresAtMs + 900_000L && record.expiresAtMs - now <= 300_000L && current() &&
            database.attempts().currentLineBinding()?.let(record::matchesBinding) == true)
        check(Draft02OutboundPreparation.hash(signer.point(LineActivationV2Purpose.SEALED)) == record.signerFingerprint)
        val completed = checkedNow()
        check(completed >= now && completed < record.expiresAtMs + 900_000L && current())
    }
    private fun installAck(a: LineActivationV2IncomingFrames.SealedInstallAck) {
        if (a.connectionEpoch != epoch) return
        val p = pending[LineActivationV2Purpose.SEALED]?.takeIf {
            it.challenge.challengeId == a.challengeId && it.receipt != null
        }
        if (p == null) {
            val record = receiptRetries[a.challengeId.toString()] ?: return
            if (!a.accepted) { receiptRetries.remove(record.challengeId); return }
            requireReceiptRetry(record)
            val earliest = checkedNow()
            fun receiptCurrent() {
                val completed = checkedNow()
                check(current() && completed >= earliest && completed > 0 &&
                    completed < record.expiresAtMs + 900_000L && record.expiresAtMs - completed <= 300_000L)
            }
            receiptCurrent()
            if (a.accepted && dao.installed(record, ::receiptCurrent)) {
                val installed = dao.find(record.purpose, record.challengeId) ?: return
                check(installed.sameProof(record) && installed.isInstalled())
                requireReceiptRetry(installed)
                receiptCurrent()
            }
            receiptRetries.remove(record.challengeId)
            return // Receipt disposition only; no live capability can be recovered here.
        }
        if (!a.accepted) { pending.remove(LineActivationV2Purpose.SEALED); dao.retire(p.record); return }
        recheck(p, true)
        if (!dao.installed(p.record) { requireLive(p, true) }) return
        val installed = dao.find(p.record.purpose, p.record.challengeId) ?: return
        recheck(p, true)
        check(installed.sameProof(p.record) && installed.isInstalled() &&
            database.attempts().currentLineBinding()?.let(installed::matchesBinding) == true)
        requireLive(p, true)
        val accepted = p.acceptance
        check(owner.publish(AcceptedPublication(p.lease, installed,
            { requireLive(p, true); true }, { current() && accepted?.isCurrent() == true })) != null)
        pending.remove(LineActivationV2Purpose.SEALED)
    }
    override fun close() {
        val first = synchronized(closeLock) {
            if (closed) false else { closed = true; true }
        } // Withdraw at entry, before an in-flight Room/Keystore call can finish.
        if (!first) return
        owner.stop()
        synchronized(this) { pending.clear(); receiptRetries.clear() }
    }
}
