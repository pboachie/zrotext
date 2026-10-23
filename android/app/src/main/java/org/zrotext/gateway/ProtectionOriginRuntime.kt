// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.SystemClock
import androidx.core.content.ContextCompat
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** Actual foreground first-origin flow. This runs on the dedicated setup worker, never the
 * UI, ingress, socket listener, Room writer or a protected-key executor. Every effect has a
 * durable burn before the external call. Backgrounding retains results but authorizes no
 * next operation. There is no reset, legacy adoption, quarantine clear or capture factory. */
internal class ProtectionOriginRuntime(private val context: Context) {
    class NeedsRecovery(message: String) : IllegalStateException(message)
    fun continueSetup(decision: ConversationInterval03Foreground.Decision, recoverProof: Boolean = false) {
        check(busy.compareAndSet(false, true)) { "Another setup action is settling" }
        try { run(decision, recoverProof) } finally { busy.set(false) }
    }
    private fun run(decision: ConversationInterval03Foreground.Decision, recoverProof: Boolean) {
        check(decision.isCurrent())
        val health = InboundProtectionHealth.snapshot()
        val host = ProtectionOriginConnections.current() ?: throw NeedsRecovery("Start the approved connection first")
        val db = SmsJournalDatabase.get(context); val setup = db.protectionSetup(); val dao = db.protectionOrigins()
        val keys = ProtectionOriginKeys(context)
        val current = {
            check(decision.isCurrent()); host.requireCurrent(); InboundProtectionHealth.checked(health)
            check(decision.isCurrent()); Unit
        }
        current(); InboundProtectionFaultJournal.requireReadable(context, false)
        check(dao.protection()?.blocked != true) { "Saved withdrawal needs recovery" }
        if (dao.installed() != null) {
            ProtectionOriginInstalled.key(context, current); current(); return
        }
        var command = setup.command()
        if (command == null) {
            // These are additional negative eligibility checks, never first-ever authority.
            // The actual server must independently commit the retained original pairing.
            check(ContextCompat.checkSelfPermission(context, Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) {
                "Existing SMS access requires original protection recovery"
            }
            keys.aliasesMatchRetained(emptyList())
            check(dao.providers().isEmpty() && !dao.hasAnyAttempt() && !dao.hasPriorLocalActivity() && dao.protection() == null)
            current()
            command = ProtectionSetupCommand(setupId = id(), openingId = id(), commandId = id(),
                accountId = host.identity.accountId, deviceId = host.identity.deviceId, originSha256 = host.identity.originHash,
                enrolledSigningKeyId = hex(ProtectionOriginProof.signingKeyId(host.point())), requestedMs = at())
            command = setup.reserveCommand(command, current)
        }
        var original = checkNotNull(command)
        host.requireOriginal(original); current()
        val opening: ProtectionOriginWire.Opening
        if (!original.openingSubmitted) {
            original = setup.openingWillBeSubmitted(original, current)
            val reply = host.request(original, ProtectionOriginWire.open(original, host.epoch), beforeSend = current) {
                it is ProtectionOriginWire.Opened
            }
            current(); opening = (reply.reply as ProtectionOriginWire.Opened).opening
        } else {
            val nonce = UUID.randomUUID()
            val reply = host.request(original, ProtectionOriginWire.status(original, host.epoch, nonce, null), beforeSend = current) {
                it is ProtectionOriginWire.Status && it.requestId == nonce && it.proofRequestId == null
            }
            current()
            val status = reply.reply as ProtectionOriginWire.Status
            if (status.state == "not_found") {
                // Retrying the SAME opening is idempotent; no new original command/nonce.
                opening = (host.request(original, ProtectionOriginWire.open(original, host.epoch), beforeSend = current) {
                    it is ProtectionOriginWire.Opened
                }.reply as ProtectionOriginWire.Opened).opening
            } else opening = checkNotNull(status.opening)
        }
        current()
        val packet = opening.bytes()
        original = setup.retainOpeningCandidate(original, original.openingId, encode(packet), hex(ProtectionOriginProof.sha(packet)), current)
        host.requireOriginal(original)
        ProtectionOriginProviderSteps(setup, keys, ::at).complete(original, opening, current)
        val prepared = ProtectionOriginPrepared.fromRetained(original, setup.providers(), opening)
        keys.requirePrepared(prepared, opening); current()
        val unresolved = dao.unresolved().also { check(it.size <= 2) }
        val leaves = unresolved.filter { row -> unresolved.none { it.previousProofRequestId == row.proofRequestId } }
        check(leaves.size == if (unresolved.isEmpty()) 0 else 1) { "Reconcile conflicting original proof history" }
        var attempt = leaves.singleOrNull()
        var clock: ProtectionOriginClock? = null
        val requested = attempt?.takeIf { it.requestEpoch != null }
        if (requested != null) {
            val observed = readStatus(host, original, requested, prepared, current)
            val status = observed.reply as ProtectionOriginWire.Status
            if (status.state == "accepted") {
                install(original, requested, prepared, opening, host, keys, status, current); return
            }
            status.challenge?.let { candidate ->
                attempt = dao.retainChallenge(checkNotNull(attempt), candidate, current)
            }
            if (!recoverProof) throw NeedsRecovery("Original proof is pending. Check status or explicitly recover the proof")
            if (attempt?.coreB64url == null) {
                val previous = checkNotNull(attempt)
                if (status.state != "not_found" || host.epoch <= checkNotNull(previous.requestEpoch))
                    throw NeedsRecovery("Reconnect the approved phone before recovering an unconfirmed proof request")
                val witness = observed.laterMissing(previous)
                attempt = dao.reserveAfterLaterMissing(prepared, previous, ProtectionOriginAttempt(id(), original.commandId,
                    encode(prepared.association.bytes()), encode(prepared.aesProbe()), at(),
                    absentPreviousProofRequestId = previous.proofRequestId), witness, current)
            } else {
                if (status.state == "superseded") throw NeedsRecovery("Reconcile the retained successor proof before continuing")
                val previous = checkNotNull(attempt)
                val core = decode(checkNotNull(previous.coreB64url), 393)
                val next = ProtectionOriginAttempt(id(), original.commandId, encode(prepared.association.bytes()),
                    encode(prepared.aesProbe()), at(), previousProofRequestId = previous.proofRequestId,
                    previousAttemptId = checkNotNull(previous.attemptId), previousCoreSha256 = hex(ProtectionOriginProof.sha(core)),
                    previousBundleSha256 = previous.bundleB64url?.let { hex(ProtectionOriginProof.sha(decode(it, 521))) })
                attempt = dao.reserve(prepared, next, current)
            }
        }
        if (attempt == null) attempt = dao.reserve(prepared, ProtectionOriginAttempt(id(), original.commandId,
            encode(prepared.association.bytes()), encode(prepared.aesProbe()), at()), current)
        var pending = checkNotNull(attempt)
        if (pending.requestEpoch == null) {
            val previous = pending.previousProofRequestId?.let { previousId ->
                val previous = checkNotNull(dao.attempt(previousId))
                ProtectionOriginWire.PreviousRequest(UUID.fromString(checkNotNull(previous.attemptId)),
                    ProtectionOriginProof.sha(decode(checkNotNull(previous.coreB64url), 393)),
                    previous.bundleB64url?.let { ProtectionOriginProof.sha(decode(it, 521)) })
            }
            val request = ProtectionOriginWire.proofOpen(original, host.epoch, UUID.fromString(pending.proofRequestId),
                prepared.association, prepared.aesProbe(), previous)
            check(dao.enterRequest(pending, host.epoch, request, current))
            pending = checkNotNull(dao.attempt(pending.proofRequestId))
            val proofId = UUID.fromString(pending.proofRequestId)
            val reply = host.request(original, request, prepared.association, beforeSend = current) {
                it is ProtectionOriginWire.ProofChallenge && it.challenge.proofRequestId == proofId
            }
            current()
            val challenge = (reply.reply as ProtectionOriginWire.ProofChallenge).challenge
            pending = dao.retainChallenge(pending, challenge, current)
            clock = ProtectionOriginClock.fromChallenge(challenge.core, reply.sentElapsedMs, reply.receivedElapsedMs)
        }
        val liveClock = clock ?: throw NeedsRecovery("This proof needs a new explicit recovery; historical replies do not renew time")
        val core = ProtectionOriginProof.Core.decode(decode(checkNotNull(pending.coreB64url), 393))
        val signingCurrent = { current(); liveClock.requireSigningTime(SystemClock.elapsedRealtime()); Unit }
        signingCurrent(); keys.requirePrepared(prepared, opening); signingCurrent()
        check(dao.enterSignature(pending, false, at(), current))
        pending = checkNotNull(dao.attempt(pending.proofRequestId))
        signingCurrent()
        val deviceResult = keys.signDevice(core)
        pending = dao.retainSignature(pending, false, deviceResult) { check(dao.setupCommand() == original) }
        signingCurrent()
        check(dao.enterSignature(pending, true, at(), current))
        pending = checkNotNull(dao.attempt(pending.proofRequestId))
        signingCurrent()
        val canaryResult = keys.signCanary(core, deviceResult)
        pending = dao.retainSignature(pending, true, canaryResult) { check(dao.setupCommand() == original) }
        val bundle = ProtectionOriginProof.Bundle.verify(core.bytes() + deviceResult + canaryResult, prepared.association, host.point())
        pending = dao.retainBundle(pending, bundle) { check(dao.setupCommand() == original) }
        signingCurrent()
        check(dao.enterProofSubmission(pending, current)); pending = checkNotNull(dao.attempt(pending.proofRequestId))
        signingCurrent()
        val proofId = UUID.fromString(pending.proofRequestId)
        host.request(original, ProtectionOriginWire.proof(original, host.epoch, proofId, bundle), prepared.association, beforeSend = current) {
            it is ProtectionOriginWire.Accepted && it.proofRequestId == proofId && it.attemptId == bundle.core.attemptId
        }.also { (it.reply as ProtectionOriginWire.Accepted).receipt.requireMatches(bundle) }
        current()
        // A fresh correlated status is mandatory even after a successful direct reply.
        val status = readStatus(host, original, pending, prepared, current).reply as ProtectionOriginWire.Status
        install(original, pending, prepared, opening, host, keys, status, current)
    }
    private fun readStatus(host: ProtectionOriginConnections.Host, command: ProtectionSetupCommand,
        attempt: ProtectionOriginAttempt, prepared: ProtectionOriginPrepared, current: () -> Unit): ProtectionOriginConnections.Received {
        current(); val nonce = UUID.randomUUID(); val proof = UUID.fromString(attempt.proofRequestId)
        val received = host.request(command, ProtectionOriginWire.status(command, host.epoch, nonce, proof), prepared.association, beforeSend = current) {
            it is ProtectionOriginWire.Status && it.requestId == nonce && it.proofRequestId == proof
        }
        current()
        (received.reply as ProtectionOriginWire.Status).also { status ->
            status.opening?.let { check(encode(it.bytes()) == command.openingCandidateB64url) }
        }
        return received.also { it.requireCurrent() }
    }
    private fun install(command: ProtectionSetupCommand, expected: ProtectionOriginAttempt,
        prepared: ProtectionOriginPrepared, opening: ProtectionOriginWire.Opening, host: ProtectionOriginConnections.Host,
        keys: ProtectionOriginKeys, status: ProtectionOriginWire.Status, current: () -> Unit) {
        current(); check(status.state == "accepted")
        val receipt = checkNotNull(status.receipt); val challenge = checkNotNull(status.challenge)
        check(challenge.proofRequestId.toString() == expected.proofRequestId &&
            encode(challenge.core.bytes()) == expected.coreB64url && encode(challenge.nonce()) == expected.nonceB64url)
        val exact = decode(checkNotNull(expected.bundleB64url), 521)
        val bundle = ProtectionOriginProof.Bundle.verify(exact, prepared.association, host.point())
        receipt.requireMatches(bundle); keys.requirePrepared(prepared, opening); current()
        val dao = SmsJournalDatabase.get(context).protectionOrigins()
        val accepted = dao.retainAccepted(expected, receipt, bundle, current)
        val prior = dao.installed()
        val row = prior ?: ProtectionOriginInstallation(commandId = command.commandId, proofRequestId = expected.proofRequestId,
            associationB64url = expected.associationB64url, aesProbeB64url = expected.aesProbeB64url,
            bundleB64url = encode(bundle.bytes()), receiptB64url = encode(ProtectionOriginJson.render(receipt.fields())),
            enrolledPointB64url = encode(host.point()), expectedTag = keys.continuityTag(), installedMs = at())
        current(); InboundProtectionFaultJournal.requireReadable(context, false); current()
        dao.install(prepared, accepted, row, current)
        ProtectionOriginInstalled.key(context, current); current()
    }
    companion object {
        private val busy = AtomicBoolean(false)
        private fun id() = UUID.randomUUID().toString()
        private fun at() = System.currentTimeMillis().coerceAtLeast(1)
        private fun encode(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
        private fun decode(value: String, width: Int) = SealedDispatch03Frames.decodeCanonical(value, width, width)
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
    }
}
