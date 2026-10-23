// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import java.util.UUID

/** Every proof command and signature burn is permanent. Nullable results mean UNKNOWN,
 * never authorization to repeat a signer. Monotonic time samples are deliberately NOT
 * reconstructed from these rows after process loss. */
@Entity(tableName = "protection_origin_attempts", indices = [Index(value = ["attemptId"], unique = true)])
data class ProtectionOriginAttempt(@PrimaryKey val proofRequestId: String, val commandId: String,
    val associationB64url: String, val aesProbeB64url: String, val createdMs: Long,
    val previousProofRequestId: String? = null, val previousAttemptId: String? = null,
    val previousCoreSha256: String? = null, val previousBundleSha256: String? = null,
    val requestEpoch: Long? = null, val requestB64url: String? = null, val attemptId: String? = null, val coreB64url: String? = null,
    val nonceB64url: String? = null, val deviceEnteredMs: Long? = null, val deviceSignatureB64url: String? = null,
    val canaryEnteredMs: Long? = null, val canarySignatureB64url: String? = null,
    val bundleB64url: String? = null, val proofSubmitted: Boolean = false, val acceptedMs: Long? = null,
    val closedMs: Long? = null, val supersededByProofRequestId: String? = null,
    val absentEpoch: Long? = null, val absentStatusB64url: String? = null,
    val absentPreviousProofRequestId: String? = null) {
    internal fun requireShape() {
        listOf(proofRequestId, commandId).forEach(Profile03ClosedUnaccepted::uuid)
        require(createdMs > 0 && (requestEpoch == null || requestEpoch > 0))
        require((requestEpoch == null) == (requestB64url == null))
        requestB64url?.let { SealedDispatch03Frames.decodeCanonical(it, 1, ProtectionOriginJson.MAX_BYTES) }
        canonical(associationB64url, 329); canonical(aesProbeB64url, 120)
        require(listOf(previousProofRequestId, previousAttemptId, previousCoreSha256).all { it == null } ||
            listOf(previousProofRequestId, previousAttemptId, previousCoreSha256).all { it != null })
        previousProofRequestId?.let(Profile03ClosedUnaccepted::uuid)
        previousAttemptId?.let(Profile03ClosedUnaccepted::uuid)
        previousCoreSha256?.let(::hash); previousBundleSha256?.let(::hash)
        require(previousBundleSha256 == null || previousAttemptId != null)
        require(listOf(attemptId, coreB64url, nonceB64url).all { it == null } ||
            listOf(attemptId, coreB64url, nonceB64url).all { it != null })
        attemptId?.let { Profile03ClosedUnaccepted.uuid(it); require(requestEpoch != null) }
        coreB64url?.let { canonical(it, 393) }; nonceB64url?.let { canonical(it, 32) }
        deviceEnteredMs?.let { require(it > 0 && coreB64url != null) }
        deviceSignatureB64url?.let { require(deviceEnteredMs != null); canonical(it, 64) }
        canaryEnteredMs?.let { require(it > 0 && deviceSignatureB64url != null) }
        canarySignatureB64url?.let { require(canaryEnteredMs != null); canonical(it, 64) }
        bundleB64url?.let {
            require(coreB64url != null && deviceSignatureB64url != null && canarySignatureB64url != null)
            require(canonical(it, 521).contentEquals(canonical(coreB64url, 393) +
                canonical(deviceSignatureB64url, 64) + canonical(canarySignatureB64url, 64)))
        }
        require(!proofSubmitted || bundleB64url != null)
        acceptedMs?.let { require(it > 0 && proofSubmitted && closedMs == null) }
        require((absentEpoch == null) == (absentStatusB64url == null))
        absentPreviousProofRequestId?.let(Profile03ClosedUnaccepted::uuid)
        absentEpoch?.let {
            require(it > checkNotNull(requestEpoch) && closedMs == null && coreB64url == null && deviceEnteredMs == null &&
                canaryEnteredMs == null && bundleB64url == null && previousProofRequestId == null && !proofSubmitted && acceptedMs == null)
            SealedDispatch03Frames.decodeCanonical(checkNotNull(absentStatusB64url), 1, ProtectionOriginJson.MAX_BYTES)
        }
        require((closedMs == null && absentEpoch == null) == (supersededByProofRequestId == null))
        supersededByProofRequestId?.let(Profile03ClosedUnaccepted::uuid)
        closedMs?.let { require(it > 0 && acceptedMs == null); Profile03ClosedUnaccepted.uuid(checkNotNull(supersededByProofRequestId)) }
    }
    override fun toString() = "ProtectionOriginAttempt(permanent-public-proof-history)"
    companion object {
        private fun canonical(value: String, width: Int) = SealedDispatch03Frames.decodeCanonical(value, width, width)
        private fun hash(value: String) { require(value.matches(Regex("[0-9a-f]{64}")) && value.any { it != '0' }) }
    }
}

/** This row is written only with the ready suppression record by the same Room transaction.
 * Its existence is not remote/current authority; every protected read must verify existing
 * original keys/probes and the independent negative-health state. */
@Entity(tableName = "protection_origin_installed")
data class ProtectionOriginInstallation(@PrimaryKey val slot: Int = 1, val commandId: String,
    val proofRequestId: String, val associationB64url: String, val aesProbeB64url: String,
    val bundleB64url: String, val receiptB64url: String, val enrolledPointB64url: String,
    val expectedTag: String, val installedMs: Long) {
    override fun toString() = "ProtectionOriginInstallation(original-public-association)"
}

/** Pure prepared candidate over exact existing journal rows. The actual foreground/host and
 * provider adapters independently verify the opening and custody outside the Room writer. */
internal class ProtectionOriginPrepared private constructor(val command: ProtectionSetupCommand,
    private val providers: List<ProtectionSetupProvider>, val association: ProtectionOriginProof.Association,
    private val aes: ByteArray) {
    fun aesProbe() = aes.copyOf()
    fun requireSame(dao: ProtectionOriginDao) {
        check(dao.setupCommand() == command && dao.providers().toSet() == providers.toSet())
    }
    companion object {
        fun fromRetained(command: ProtectionSetupCommand, rows: List<ProtectionSetupProvider>,
            opening: ProtectionOriginWire.Opening): ProtectionOriginPrepared {
            command.requireShape(); rows.forEach { it.requireShape(); check(it.commandId == command.commandId) }
            require(command.openingCandidateB64url != null && rows.size == 4 &&
                rows.map { it.kind }.toSet() == ProtectionSetupProvider.KINDS.toSet() &&
                rows.all { it.evidenceB64url != null })
            fun evidence(kind: String, width: Int) = SealedDispatch03Frames.decodeCanonical(
                checkNotNull(rows.single { it.kind == kind }.evidenceB64url), width, width)
            val aes = evidence("journal_aes", 60) + evidence("withdrawal_aes", 60)
            val association = ProtectionOriginProof.Association.create(command, opening.sourcePairingId,
                opening.nonce, evidence("suppression_hmac", 32), aes, evidence("canary", 65))
            return ProtectionOriginPrepared(command, rows.toList(), association, aes)
        }
    }
}

/** Same-writer durable phases only. No network, OS, signer/provider or foreground wait may
 * run inside these transactions. Callbacks are RAM-only. A passive history append cannot
 * authorize another signature, provider call, or local protection installation. */
@Dao
abstract class ProtectionOriginDao {
    @Query("SELECT * FROM protection_setup_command WHERE slot = 1") abstract fun setupCommand(): ProtectionSetupCommand?
    @Query("SELECT * FROM protection_setup_providers ORDER BY enteredMs,kind") abstract fun providers(): List<ProtectionSetupProvider>
    @Query("SELECT * FROM protection_origin_attempts WHERE proofRequestId = :id") abstract fun attempt(id: String): ProtectionOriginAttempt?
    @Query("SELECT * FROM protection_origin_attempts ORDER BY createdMs,proofRequestId") abstract fun attempts(): List<ProtectionOriginAttempt>
    @Query("SELECT * FROM protection_origin_attempts WHERE closedMs IS NULL AND absentEpoch IS NULL ORDER BY createdMs,proofRequestId LIMIT 3")
    abstract fun unresolved(): List<ProtectionOriginAttempt>
    @Query("SELECT EXISTS(SELECT 1 FROM protection_origin_attempts)") abstract fun hasAnyAttempt(): Boolean
    @Query("SELECT EXISTS(SELECT 1 FROM protection_origin_attempts WHERE coreB64url IS NOT NULL OR deviceEnteredMs IS NOT NULL OR canaryEnteredMs IS NOT NULL)")
    abstract fun hasAnyChallengeOrSignature(): Boolean
    @Query("SELECT EXISTS(SELECT 1 FROM sms_attempts UNION ALL SELECT 1 FROM inbound_events UNION ALL SELECT 1 FROM inbound_windows UNION ALL SELECT 1 FROM inbound_uploads UNION ALL SELECT 1 FROM local_recipient_suppressions UNION ALL SELECT 1 FROM local_line_binding UNION ALL SELECT 1 FROM local_inbound_withdrawals UNION ALL SELECT 1 FROM local_withdrawal_sequences UNION ALL SELECT 1 FROM sealed_preparations UNION ALL SELECT 1 FROM profile03_elections UNION ALL SELECT 1 FROM capture03_routes UNION ALL SELECT 1 FROM capture03_counters UNION ALL SELECT 1 FROM capture03_records UNION ALL SELECT 1 FROM capture03_modes UNION ALL SELECT 1 FROM typed_submit03 UNION ALL SELECT 1 FROM typed_submit03_requests UNION ALL SELECT 1 FROM typed_callback03 UNION ALL SELECT 1 FROM typed_history03_sources UNION ALL SELECT 1 FROM typed_history03_clocks)")
    abstract fun hasPriorLocalActivity(): Boolean
    @Query("SELECT EXISTS(SELECT 1 FROM protection_origin_attempts WHERE acceptedMs IS NOT NULL)")
    abstract fun hasAccepted(): Boolean
    @Query("SELECT * FROM protection_origin_installed WHERE slot = 1") abstract fun installed(): ProtectionOriginInstallation?
    @Query("SELECT * FROM inbound_protection_state WHERE slot = 1") abstract fun protection(): InboundProtectionRecord?
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertAttempt(row: ProtectionOriginAttempt)
    @Update protected abstract fun updateAttempt(row: ProtectionOriginAttempt): Int
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertInstalled(row: ProtectionOriginInstallation)
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertProtection(row: InboundProtectionRecord)

    @Transaction internal open fun reserve(prepared: ProtectionOriginPrepared, candidate: ProtectionOriginAttempt,
        current: () -> Unit): ProtectionOriginAttempt {
        current(); prepared.requireSame(this); candidate.requireShape()
        require(candidate.commandId == prepared.command.commandId && candidate.requestEpoch == null &&
            candidate.coreB64url == null && candidate.deviceEnteredMs == null && candidate.acceptedMs == null &&
            candidate.closedMs == null && candidate.absentEpoch == null && candidate.absentPreviousProofRequestId == null &&
            candidate.supersededByProofRequestId == null && candidate.associationB64url == encode(prepared.association.bytes()) &&
            candidate.aesProbeB64url == encode(prepared.aesProbe()))
        attempt(candidate.proofRequestId)?.let { check(it == candidate); current(); return it }
        val history = unresolved().onEach { it.requireShape(); check(it.commandId == candidate.commandId) }
        check(!hasAccepted() && installed() == null)
        if (history.isEmpty()) require(candidate.previousProofRequestId == null && !hasAnyAttempt())
        else {
            val previous = checkNotNull(attempt(checkNotNull(candidate.previousProofRequestId)))
            check(previous.closedMs == null && previous.acceptedMs == null && previous.coreB64url != null &&
                previous.attemptId == candidate.previousAttemptId &&
                hash(SealedDispatch03Frames.decodeCanonical(previous.coreB64url, 393, 393)) == candidate.previousCoreSha256 &&
                previous.bundleB64url?.let { hash(SealedDispatch03Frames.decodeCanonical(it, 521, 521)) } == candidate.previousBundleSha256)
            check(history.filter { it.closedMs == null }.all { it.proofRequestId == previous.proofRequestId })
            check(previous.associationB64url == candidate.associationB64url && previous.aesProbeB64url == candidate.aesProbeB64url)
        }
        insertAttempt(candidate); current(); return checkNotNull(attempt(candidate.proofRequestId))
    }

    /** Absence is not a fabricated server closure. Keep the original request/epoch and the
     * exact later-claim status separately, with no closed_ms or signature/result invention. */
    @Transaction internal open fun reserveAfterLaterMissing(prepared: ProtectionOriginPrepared, expected: ProtectionOriginAttempt,
        next: ProtectionOriginAttempt, witness: ProtectionOriginConnections.LaterMissing,
        current: () -> Unit): ProtectionOriginAttempt {
        current(); witness.requireFor(expected); prepared.requireSame(this); expected.requireShape(); next.requireShape()
        check(attempt(expected.proofRequestId) == expected && expected.supersededByProofRequestId == null &&
            !hasAnyChallengeOrSignature() && !hasAccepted() && installed() == null && unresolved() == listOf(expected))
        require(next.proofRequestId != expected.proofRequestId && next.commandId == expected.commandId &&
            next.associationB64url == expected.associationB64url && next.aesProbeB64url == expected.aesProbeB64url &&
            next.previousProofRequestId == null && next.absentPreviousProofRequestId == expected.proofRequestId &&
            next.requestEpoch == null && next.coreB64url == null && next.deviceEnteredMs == null && next.acceptedMs == null &&
            next.closedMs == null && next.absentEpoch == null && next.supersededByProofRequestId == null)
        val old = expected.copy(absentEpoch = witness.epoch(), absentStatusB64url = encode(witness.bytes()),
            supersededByProofRequestId = next.proofRequestId).also { it.requireShape() }
        check(updateAttempt(old) == 1); insertAttempt(next); witness.requireFor(expected); current()
        return checkNotNull(attempt(next.proofRequestId)).also { check(it == next) }
    }

    /** True ONLY for the first committed transport entry. Exact retries cannot mint a new
     * clock over a historical challenge. A cold submitted command goes to passive status. */
    @Transaction internal open fun enterRequest(expected: ProtectionOriginAttempt, actualEpoch: Long, originalRequest: ByteArray,
        current: () -> Unit): Boolean {
        current(); expected.requireShape(); require(actualEpoch > 0)
        require(originalRequest.size in 1..ProtectionOriginJson.MAX_BYTES)
        val old = checkNotNull(attempt(expected.proofRequestId)); check(old == expected && old.supersededByProofRequestId == null)
        if (old.requestEpoch != null) { current(); return false }
        check(updateAttempt(old.copy(requestEpoch = actualEpoch, requestB64url = encode(originalRequest.copyOf()))) == 1); current(); return true
    }

    @Transaction internal open fun retainChallenge(expected: ProtectionOriginAttempt, candidate: ProtectionOriginWire.Challenge,
        current: () -> Unit): ProtectionOriginAttempt {
        current(); expected.requireShape(); check(attempt(expected.proofRequestId) == expected && expected.requestEpoch != null)
        require(expected.supersededByProofRequestId == null && candidate.proofRequestId.toString() == expected.proofRequestId &&
            encode(candidate.core.association.bytes()) == expected.associationB64url)
        val next = expected.copy(attemptId = candidate.attemptId.toString(), coreB64url = encode(candidate.core.bytes()), nonceB64url = encode(candidate.nonce()))
        next.requireShape()
        if (expected.coreB64url != null) check(next == expected)
        else {
            val closure = candidate.predecessor
            if (expected.previousProofRequestId == null) check(closure == null)
            else {
                val c = checkNotNull(closure); val prior = checkNotNull(attempt(expected.previousProofRequestId))
                check(prior.acceptedMs == null && prior.closedMs == null && prior.coreB64url != null &&
                    c.proofRequestId.toString() == prior.proofRequestId && c.attemptId.toString() == prior.attemptId &&
                    hex(c.coreSha256()) == expected.previousCoreSha256 && c.bundleSha256()?.let(::hex) == expected.previousBundleSha256 &&
                    c.closedMs == candidate.core.issuedMs)
                check(updateAttempt(prior.copy(closedMs = c.closedMs, supersededByProofRequestId = expected.proofRequestId)) == 1)
            }
            check(updateAttempt(next) == 1)
        }
        current(); return checkNotNull(attempt(expected.proofRequestId))
    }

    @Transaction internal open fun enterSignature(expected: ProtectionOriginAttempt, canary: Boolean, at: Long,
        current: () -> Unit): Boolean {
        current(); expected.requireShape(); check(attempt(expected.proofRequestId) == expected)
        require(at > 0 && expected.coreB64url != null && expected.closedMs == null && expected.acceptedMs == null)
        val entered = if (canary) expected.canaryEnteredMs else expected.deviceEnteredMs
        if (entered != null) { current(); return false }
        if (canary) require(expected.deviceSignatureB64url != null)
        val next = if (canary) expected.copy(canaryEnteredMs = at) else expected.copy(deviceEnteredMs = at)
        next.requireShape(); check(updateAttempt(next) == 1); current(); return true
    }

    /** Actual returned signature bytes only, including after foreground withdrawal. This
     * append is history; it cannot unburn a signer or return an invocation/pin capability. */
    @Transaction internal open fun retainSignature(expected: ProtectionOriginAttempt, canary: Boolean, raw: ByteArray,
        originalOperationCurrent: () -> Unit): ProtectionOriginAttempt {
        originalOperationCurrent(); expected.requireShape(); require(raw.size == 64)
        val retained = checkNotNull(attempt(expected.proofRequestId))
        // A concurrent authenticated closure cannot erase the actual result of the old
        // already-burned operation. Retain that history without reopening the closed row.
        check(retained.copy(closedMs = expected.closedMs, supersededByProofRequestId = expected.supersededByProofRequestId) == expected)
        val prior = if (canary) retained.canarySignatureB64url else retained.deviceSignatureB64url
        val next = if (canary) retained.copy(canarySignatureB64url = encode(raw)) else retained.copy(deviceSignatureB64url = encode(raw))
        next.requireShape()
        if (prior != null) check(next == retained) else check(updateAttempt(next) == 1)
        originalOperationCurrent(); return checkNotNull(attempt(expected.proofRequestId))
    }

    @Transaction internal open fun retainBundle(expected: ProtectionOriginAttempt, verified: ProtectionOriginProof.Bundle,
        originalOperationCurrent: () -> Unit): ProtectionOriginAttempt {
        originalOperationCurrent(); expected.requireShape()
        val retained = checkNotNull(attempt(expected.proofRequestId))
        check(retained.copy(closedMs = expected.closedMs, supersededByProofRequestId = expected.supersededByProofRequestId) == expected)
        val next = retained.copy(bundleB64url = encode(verified.bytes())).also { it.requireShape() }
        require(next.coreB64url == encode(verified.core.bytes()))
        if (retained.bundleB64url != null) check(next == retained) else check(updateAttempt(next) == 1)
        originalOperationCurrent(); return checkNotNull(attempt(expected.proofRequestId))
    }

    @Transaction internal open fun enterProofSubmission(expected: ProtectionOriginAttempt, current: () -> Unit): Boolean {
        current(); expected.requireShape(); check(attempt(expected.proofRequestId) == expected && expected.closedMs == null && expected.bundleB64url != null)
        if (expected.proofSubmitted) { current(); return false }
        check(updateAttempt(expected.copy(proofSubmitted = true)) == 1); current(); return true
    }

    @Transaction internal open fun retainAccepted(expected: ProtectionOriginAttempt, receipt: ProtectionOriginWire.Receipt,
        verified: ProtectionOriginProof.Bundle, current: () -> Unit): ProtectionOriginAttempt {
        current(); expected.requireShape(); check(attempt(expected.proofRequestId) == expected && expected.closedMs == null && expected.proofSubmitted)
        require(expected.bundleB64url == encode(verified.bytes())); receipt.requireMatches(verified)
        val next = expected.copy(acceptedMs = receipt.acceptedMs).also { it.requireShape() }
        if (expected.acceptedMs != null) check(next == expected) else check(updateAttempt(next) == 1)
        current(); return checkNotNull(attempt(expected.proofRequestId))
    }

    /** Positive installation is the same writer as its expected suppression identity. The
     * caller has just checked the original proof, all existing providers and a fresh actual
     * accepted status outside Room. current is a RAM-only foreground/host/health guard. */
    @Transaction internal open fun install(prepared: ProtectionOriginPrepared, expected: ProtectionOriginAttempt,
        row: ProtectionOriginInstallation, current: () -> Unit): ProtectionOriginInstallation {
        current(); prepared.requireSame(this); expected.requireShape()
        check(attempt(expected.proofRequestId) == expected && expected.acceptedMs != null && expected.closedMs == null)
        check(row.slot == 1 && row.commandId == expected.commandId && row.proofRequestId == expected.proofRequestId &&
            row.associationB64url == expected.associationB64url && row.aesProbeB64url == expected.aesProbeB64url &&
            row.bundleB64url == expected.bundleB64url && row.installedMs > 0)
        require(row.expectedTag.matches(Regex("[0-9a-f]{64}")))
        val ready = InboundProtectionRecord(expectedTag = row.expectedTag, originId = prepared.command.openingId,
            blocked = false, reason = null, debtMask = 0, firstObservedMs = row.installedMs).also { it.requireShape() }
        val prior = installed(); val state = protection()
        if (prior != null) {
            check(prior == row && state == ready) { "Original installation cannot be replaced" }
        } else {
            check(state == null) { "Protection recovery cannot clear negative history" }
            insertInstalled(row); insertProtection(ready)
        }
        current(); return checkNotNull(installed()).also { check(it == row && protection() == ready) }
    }

    private fun encode(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
    private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
    private fun hash(bytes: ByteArray) = hex(ProtectionOriginProof.sha(bytes))
}
