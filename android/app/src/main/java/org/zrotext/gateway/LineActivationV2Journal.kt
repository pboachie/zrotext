// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import java.util.UUID

/** Nonce-free provenance and replay fence. Reading this row never issues a live lease. */
@Entity(tableName = "line_activation_v2", primaryKeys = ["purpose", "challengeId"])
data class LineActivationV2Record(
    val purpose: String, val challengeId: String, val accountId: String, val deviceId: String,
    val lineId: String, val generation: Long, val expiresAtMs: Long,
    /** Existing authenticated socket routing hash; never replaced by a protocol HTTPS digest. */
    val proofConnectionEpoch: Long, val originHash: String, val signerFingerprint: String,
    val observationB64url: String, val state: String = "reserved",
    val signatureDerB64url: String? = null, val statementSha256: String? = null,
    val signatureSha256: String? = null, val confirmationSha256: String? = null
) {
    internal fun requireShape() {
        require(purpose in setOf("sms", "sealed") && listOf(challengeId, accountId, deviceId, lineId).all {
            runCatching { UUID.fromString(it).toString() == it && UUID.fromString(it) != UUID(0, 0) }.getOrDefault(false)
        } && generation > 0 && expiresAtMs in 1..(Long.MAX_VALUE - 900_000L) && proofConnectionEpoch > 0 &&
            originHash.matches(HEX) && signerFingerprint.matches(HEX))
        LineActivationV2Observation.decode(LineActivationV2JournalEncoding.decode(observationB64url))
        require(state in setOf("reserved", "signed", "proof_recorded", "final_recorded", "installed", "retired"))
        if (signatureDerB64url == null) require(state in setOf("reserved", "retired") &&
            statementSha256 == null && signatureSha256 == null && confirmationSha256 == null)
        else {
            SealedLineActivationTranscript.requireCanonicalDer(LineActivationV2JournalEncoding.decode(signatureDerB64url))
            require(listOf(statementSha256, signatureSha256, confirmationSha256).all { it?.matches(HEX) == true })
        }
    }
    internal fun sameReservation(other: LineActivationV2Record) = copy(state = "reserved",
        signatureDerB64url = null, statementSha256 = null, signatureSha256 = null, confirmationSha256 = null) ==
        other.copy(state = "reserved", signatureDerB64url = null, statementSha256 = null,
            signatureSha256 = null, confirmationSha256 = null)
    internal fun sameProof(other: LineActivationV2Record) = sameReservation(other) &&
        signatureDerB64url == other.signatureDerB64url && statementSha256 == other.statementSha256 &&
        signatureSha256 == other.signatureSha256 && confirmationSha256 == other.confirmationSha256
    internal fun isInstalled() = state == "installed" && signatureDerB64url != null
    internal fun matches(receipt: LineActivationV2IncomingFrames.Receipt): Boolean =
        purpose == receipt.purpose.journalName() && challengeId == receipt.challengeId.toString() &&
        accountId == receipt.accountId.toString() && deviceId == receipt.deviceId.toString() &&
        lineId == receipt.lineId.toString() && generation == receipt.generation &&
        statementSha256 == Draft02OutboundPreparation.hex(receipt.deviceStatementSha256()) &&
        signatureSha256 == Draft02OutboundPreparation.hex(receipt.deviceSignatureSha256())
    internal fun matchesBinding(binding: LocalLineBinding): Boolean = binding.slot == 1 && binding.installedAtMs > 0 &&
        binding.protocolVersion == 2 && binding.subscriptionId == selectedSubscription() &&
        binding.accountId == accountId && binding.deviceId == deviceId && binding.lineId == lineId &&
        binding.generation == generation && binding.v2Purpose == purpose && binding.v2ChallengeId == challengeId &&
        binding.v2ObservationB64url == observationB64url && binding.v2StatementSha256 == statementSha256 &&
        binding.v2SignatureSha256 == signatureSha256 && binding.cardId == null &&
        binding.continuityKind == "complete_v2" && binding.profilePortIndex == null &&
        binding.profileLogicalSlotIndex == null && binding.profileIncarnation == null &&
        binding.profileObservationEpoch == null && binding.profileLeaseId == null
    private fun selectedSubscription(): Int = java.nio.ByteBuffer.wrap(
        LineActivationV2Observation.decode(LineActivationV2JournalEncoding.decode(observationB64url)).bytes()).getInt(4)
    internal fun binding(subscription: Int, now: Long) = LocalLineBinding(accountId = accountId,
        deviceId = deviceId, lineId = lineId, generation = generation, subscriptionId = subscription,
        installedAtMs = now, cardId = null, continuityKind = "complete_v2", protocolVersion = 2,
        v2Purpose = purpose, v2ChallengeId = challengeId, v2ObservationB64url = observationB64url,
        v2StatementSha256 = statementSha256, v2SignatureSha256 = signatureSha256)
    override fun toString() = "LineActivationV2Record(redacted)"
    companion object { private val HEX = Regex("[0-9a-f]{64}") }
}

internal fun LineActivationV2Purpose.journalName() = if (this == LineActivationV2Purpose.SMS) "sms" else "sealed"
internal object LineActivationV2JournalEncoding {
    private val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
    fun encode(bytes: ByteArray) = encoder.encodeToString(bytes)
    fun decode(text: String): ByteArray {
        require(text.length in 1..256 && text.matches(Regex("[A-Za-z0-9_-]+")))
        return java.util.Base64.getUrlDecoder().decode(text).also { require(encode(it) == text) }
    }
}

@Dao
abstract class LineActivationV2Dao {
    @Query("SELECT * FROM line_activation_v2 WHERE purpose = :purpose AND challengeId = :challenge")
    abstract fun find(purpose: String, challenge: String): LineActivationV2Record?
    @Query("SELECT COUNT(*) FROM line_activation_v2")
    protected abstract fun count(): Int
    @Insert
    protected abstract fun insert(record: LineActivationV2Record)
    @Query("UPDATE line_activation_v2 SET state = :state, signatureDerB64url = :signature, statementSha256 = :statement, signatureSha256 = :signatureDigest, confirmationSha256 = :confirmation WHERE purpose = :purpose AND challengeId = :challenge AND state = 'reserved' AND signatureDerB64url IS NULL")
    protected abstract fun signed(purpose: String, challenge: String, state: String, signature: String,
        statement: String, signatureDigest: String, confirmation: String): Int
    @Query("UPDATE line_activation_v2 SET state = :next WHERE purpose = :purpose AND challengeId = :challenge AND state = :prior")
    protected abstract fun transition(purpose: String, challenge: String, prior: String, next: String): Int
    @Query("SELECT * FROM local_line_binding WHERE slot = 1")
    protected abstract fun line(): LocalLineBinding?
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    protected abstract fun putLine(binding: LocalLineBinding)

    /** Never reinterpret an old reservation using another process, observer or socket lease. */
    @Transaction
    open fun reserve(record: LineActivationV2Record, current: () -> Unit): Boolean {
        record.requireShape(); require(record.state == "reserved" && record.signatureDerB64url == null)
        current()
        if (find(record.purpose, record.challengeId) != null || count() >= CAPACITY) return false
        insert(record)
        current()
        return find(record.purpose, record.challengeId) == record
    }
    @Transaction
    open fun recordSigned(record: LineActivationV2Record, current: () -> Unit): Boolean {
        record.requireShape(); require(record.state == "signed" && record.signatureDerB64url != null)
        current()
        val old = find(record.purpose, record.challengeId) ?: return false
        if (!old.sameReservation(record)) return false
        if (old.state != "reserved") return old.sameProof(record) && old.state == "signed"
        check(signed(record.purpose, record.challengeId, "signed", checkNotNull(record.signatureDerB64url),
            checkNotNull(record.statementSha256), checkNotNull(record.signatureSha256),
            checkNotNull(record.confirmationSha256)) == 1)
        current()
        return find(record.purpose, record.challengeId) == record
    }
    @Transaction
    open fun proofRecorded(record: LineActivationV2Record, current: () -> Unit): Boolean =
        move(record, setOf("signed", "proof_recorded"), "proof_recorded", current)

    /** Provisional binding and exact receipt provenance commit together, without publishing authority. */
    @Transaction
    open fun recordFinal(record: LineActivationV2Record, binding: LocalLineBinding,
        current: () -> Unit): Boolean {
        record.requireShape()
        current()
        val old = find(record.purpose, record.challengeId) ?: return false
        if (!old.sameProof(record) || old.state !in setOf("signed", "proof_recorded", "final_recorded", "installed") ||
            !record.matchesBinding(binding)) return false
        val prior = line()
        if (prior != null && !record.matchesBinding(prior) && (prior.accountId != binding.accountId ||
                prior.deviceId != binding.deviceId || prior.lineId != binding.lineId || prior.generation >= binding.generation)) return false
        if (prior != null && !record.matchesBinding(prior)) {
            prior.profileAuthority()?.let(SimProfileContinuity::retireAuthority)
            LineActivationV2SelectedLineMount.retireInstalled()
        }
        if (prior == null || !record.matchesBinding(prior)) putLine(binding)
        if (old.state != "installed" && old.state != "final_recorded")
            check(transition(record.purpose, record.challengeId, old.state, "final_recorded") == 1)
        current()
        return find(record.purpose, record.challengeId)?.let { it.sameProof(record) &&
            it.state in setOf("final_recorded", "installed") } == true && line()?.let(record::matchesBinding) == true
    }
    @Transaction
    open fun installed(record: LineActivationV2Record, current: () -> Unit): Boolean {
        record.requireShape()
        current()
        if (line()?.let(record::matchesBinding) != true) return false
        return move(record, setOf("final_recorded", "installed"), "installed", current)
    }
    @Transaction
    open fun retire(record: LineActivationV2Record) {
        val old = find(record.purpose, record.challengeId) ?: return
        if (old.sameReservation(record) && old.state != "installed" && old.state != "retired")
            transition(record.purpose, record.challengeId, old.state, "retired")
    }
    private fun move(record: LineActivationV2Record, allowed: Set<String>, next: String,
        current: () -> Unit): Boolean {
        current()
        val old = find(record.purpose, record.challengeId) ?: return false
        if (!old.sameProof(record) || old.state !in allowed) return false
        if (old.state != next) check(transition(record.purpose, record.challengeId, old.state, next) == 1)
        current()
        return find(record.purpose, record.challengeId)?.let { it.sameProof(record) && it.state == next } == true
    }
    companion object { const val CAPACITY = 1024 }
}
