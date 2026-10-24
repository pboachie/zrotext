// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Transaction
import java.util.UUID

/** Permanent public election provenance. A row never reconstructs a live SIM/session permit. */
@Entity(tableName = "profile03_elections", primaryKeys = ["challengeId"],
    indices = [Index(value = ["newBindingId"], unique = true)])
data class Profile03ElectionRecord(
    val challengeId: String, val accountId: String, val deviceId: String, val lineId: String,
    val oldBindingId: String, val newBindingId: String, val oldGeneration: Long, val newGeneration: Long,
    /** originHash is the signed HTTPS protocol digest at E500 offset400, not socket routing. */
    val rootFingerprint: String, val readerKeyId: String, val originHash: String,
    val connectionEpoch: Long, val deploymentEpoch: Long,
    val coreB64url: String, val state: String = "reserved",
    val deviceSignatureB64url: String? = null, val acceptedEvidenceSha256: String? = null,
) {
    internal fun requireShape() {
        require(listOf(challengeId, accountId, deviceId, lineId, oldBindingId, newBindingId).all { value ->
            runCatching { UUID.fromString(value).toString() == value && UUID.fromString(value) != UUID(0, 0) }
                .getOrDefault(false)
        })
        require(oldBindingId != newBindingId && oldGeneration > 0 && newGeneration > oldGeneration &&
            connectionEpoch > 0 && deploymentEpoch > 0 &&
            listOf(rootFingerprint, readerKeyId, originHash).all { it.matches(HEX) })
        val core = Profile03ElectionEncoding.decode(coreB64url, 500)
        require(core.copyOfRange(0, 8).contentEquals(byteArrayOf(90, 84, 80, 69, 3, 1, 2, 3)) &&
            core.copyOfRange(496, 500).all { it == 0.toByte() })
        fun id(at: Int) = java.nio.ByteBuffer.wrap(core, at, 16).let { UUID(it.long, it.long).toString() }
        fun number(at: Int) = java.nio.ByteBuffer.wrap(core, at, 8).long
        fun digest(at: Int) = Draft02OutboundPreparation.hex(core.copyOfRange(at, at + 32))
        require(id(8) == accountId && id(24) == deviceId && id(40) == lineId && id(56) == challengeId &&
            id(72) == oldBindingId && number(88) == oldGeneration && number(96) == newGeneration &&
            digest(136) == rootFingerprint && digest(256) == readerKeyId && digest(400) == originHash)
        require(state in setOf("reserved", "signed", "installed", "retired"))
        deviceSignatureB64url?.let { Profile03ElectionEncoding.decode(it, 64) }
        acceptedEvidenceSha256?.let { require(it.matches(HEX)) }
        require(state != "installed" || deviceSignatureB64url != null && acceptedEvidenceSha256 != null)
        require(deviceSignatureB64url != null || state in setOf("reserved", "retired"))
    }
    internal fun sameReservation(other: Profile03ElectionRecord) = copy(state = "reserved",
        deviceSignatureB64url = null, acceptedEvidenceSha256 = null) == other.copy(state = "reserved",
        deviceSignatureB64url = null, acceptedEvidenceSha256 = null)
    override fun toString() = "Profile03ElectionRecord(redacted)"
    companion object { private val HEX = Regex("[0-9a-f]{64}") }
}

internal object Profile03ElectionEncoding {
    fun encode(bytes: ByteArray): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun decode(value: String, width: Int): ByteArray {
        require(value.length == (width * 8 + 5) / 6 && value.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        return java.util.Base64.getUrlDecoder().decode(value).also { require(it.size == width && encode(it) == value) }
    }
}

@Dao
abstract class Profile03ElectionDao {
    @Query("SELECT * FROM profile03_elections WHERE challengeId = :challenge")
    abstract fun find(challenge: String): Profile03ElectionRecord?
    @Query("SELECT * FROM profile03_elections WHERE accountId = :account AND lineId = :line AND state = 'installed'")
    abstract fun installed(account: String, line: String): Profile03ElectionRecord?
    @Query("SELECT * FROM profile03_elections WHERE accountId = :account AND lineId = :line AND state = 'signed' AND challengeId NOT IN (SELECT challengeId FROM profile03_unaccepted_closures) ORDER BY newGeneration DESC LIMIT 1")
    abstract fun signedOpening(account: String, line: String): Profile03ElectionRecord?
    @Query("SELECT COUNT(*) FROM profile03_elections")
    protected abstract fun count(): Int
    @Query("SELECT COUNT(*) FROM profile03_elections WHERE accountId = :account AND (state IN ('reserved','signed','installed') OR deviceSignatureB64url IS NOT NULL OR acceptedEvidenceSha256 IS NOT NULL)")
    protected abstract fun outstanding(account: String): Int
    @Query("SELECT * FROM profile03_elections WHERE accountId = :account AND challengeId != :target AND (state IN ('reserved','signed','installed') OR deviceSignatureB64url IS NOT NULL OR acceptedEvidenceSha256 IS NOT NULL)")
    protected abstract fun priorReservations(account: String, target: String): List<Profile03ElectionRecord>
    @Query("SELECT * FROM profile03_unaccepted_closures WHERE challengeId = :challenge")
    abstract fun closedUnaccepted(challenge: String): Profile03UnacceptedClosureRecord?
    @Query("SELECT COUNT(*) FROM profile03_unaccepted_closures")
    protected abstract fun closureCount(): Int
    @Query("SELECT * FROM profile03_unaccepted_closures")
    protected abstract fun retainedClosures(): List<Profile03UnacceptedClosureRecord>
    @Query("SELECT * FROM local_line_binding WHERE slot = 1")
    protected abstract fun line(): LocalLineBinding?
    @Query("SELECT COUNT(*) FROM sealed_preparations WHERE accountId = :account")
    protected abstract fun oldPreparations(account: String): Int
    @Query("SELECT COUNT(*) FROM sms_attempts WHERE (accountId = :account OR accountId IS NULL) AND attemptId != :excluded AND (evidenceConflict = 1 OR state IN ('reserved','radio_started','submitting','submitted','unknown','delivery_unknown','partial_failure'))")
    protected abstract fun unresolvedEffects(account: String, excluded: String): Int
    @Insert
    protected abstract fun insert(record: Profile03ElectionRecord)
    @Insert
    protected abstract fun insertClosure(record: Profile03UnacceptedClosureRecord)
    @Query("UPDATE profile03_elections SET state = 'signed', deviceSignatureB64url = :signature WHERE challengeId = :challenge AND state = 'reserved' AND deviceSignatureB64url IS NULL")
    protected abstract fun signed(challenge: String, signature: String): Int
    @Query("UPDATE profile03_elections SET state = 'installed', acceptedEvidenceSha256 = :evidence WHERE challengeId = :challenge AND state = 'signed' AND acceptedEvidenceSha256 IS NULL")
    protected abstract fun accepted(challenge: String, evidence: String): Int
    /** Retirement cannot retract a released proof or resolve its unknown server outcome. */
    @Query("UPDATE profile03_elections SET state = 'retired' WHERE challengeId = :challenge AND state IN ('reserved','signed','installed')")
    abstract fun retire(challenge: String): Int

    /** Reserve before signing. A crash burns the challenge; no timeout or cold load signs it again. */
    @Transaction
    open fun reserve(record: Profile03ElectionRecord, current: (LocalLineBinding?) -> Unit): Boolean {
        record.requireShape()
        require(record.state == "reserved" && record.deviceSignatureB64url == null && record.acceptedEvidenceSha256 == null)
        current(line())
        if (find(record.challengeId) != null || count() >= CAPACITY || outstanding(record.accountId) != 0 ||
            oldPreparations(record.accountId) != 0 || unresolvedEffects(record.accountId, "") != 0) return false
        insert(record)
        current(line())
        return find(record.challengeId) == record
    }

    private fun requireClosures(record: Profile03ElectionRecord, closures: List<Profile03UnacceptedClosureRecord>,
        authenticatedNow: Long, current: (LocalLineBinding?) -> Unit, retain: Boolean) {
        current(line())
        Profile03ClosedUnaccepted.requireChain(record, closures, authenticatedNow)
        val indexed = closures.associateBy { it.challengeId }
        val targetCore = Profile03ClosedUnaccepted.Core.decode(Profile03ElectionEncoding.decode(record.coreB64url, 500))
        // Previously unseen server intermediates also become immutable retained history.
        // A later opening may not omit them merely because no local signature row exists.
        for (saved in retainedClosures()) {
            saved.requireShape()
            val savedCore = Profile03ClosedUnaccepted.Core.decode(Profile03ElectionEncoding.decode(saved.coreB64url, 500))
            if (savedCore.sameOriginalScope(targetCore)) check(indexed[saved.challengeId] == saved)
        }
        // Every locally active or ever-signed ancestor must be present. An accepted local
        // election contradicts original02 and can NEVER be resolved through this operation.
        for (prior in priorReservations(record.accountId, record.challengeId)) {
            prior.requireShape()
            check(prior.state != "installed" && prior.acceptedEvidenceSha256 == null)
            val closure = checkNotNull(indexed[prior.challengeId])
            check(prior.coreB64url == closure.coreB64url && prior.newBindingId == closure.newBindingId)
        }
        for (closure in closures) {
            find(closure.challengeId)?.let { prior ->
                prior.requireShape()
                check(prior.accountId == record.accountId && prior.coreB64url == closure.coreB64url &&
                    prior.newBindingId == closure.newBindingId && prior.acceptedEvidenceSha256 == null && prior.state != "installed")
            }
            val saved = closedUnaccepted(closure.challengeId)
            check(saved == null && retain || saved == closure) // Exact original receipt; no timestamp/link replacement.
        }
        check(oldPreparations(record.accountId) == 0 && unresolvedEffects(record.accountId, "") == 0)
        current(line())
    }

    /** Only the authenticated original02/epoch0 challenge consumer may call this after full
     * independent proof validation. Closures and the fresh reservation share this writer.
     * Legacy reserve/02 preparation/radio fences remain irreversible for every released proof.
     */
    @Transaction
    open fun reserveWithClosures(record: Profile03ElectionRecord, closures: List<Profile03UnacceptedClosureRecord>,
        authenticatedNow: Long, current: (LocalLineBinding?) -> Unit): Boolean {
        record.requireShape()
        require(record.state == "reserved" && record.deviceSignatureB64url == null && record.acceptedEvidenceSha256 == null)
        requireClosures(record, closures, authenticatedNow, current, true)
        if (find(record.challengeId) != null || count() >= CAPACITY ||
            closureCount() + closures.count { closedUnaccepted(it.challengeId) == null } > CLOSURE_CAPACITY) return false
        for (closure in closures) if (closedUnaccepted(closure.challengeId) == null) insertClosure(closure)
        insert(record)
        requireClosures(record, closures, authenticatedNow, current, false)
        return find(record.challengeId) == record
    }

    /** Passive exact-proof resume: a signed opening cannot import missing closure history. */
    @Transaction
    open fun requireClosureHistory(record: Profile03ElectionRecord, closures: List<Profile03UnacceptedClosureRecord>,
        authenticatedNow: Long, current: (LocalLineBinding?) -> Unit) {
        val saved = checkNotNull(find(record.challengeId))
        saved.requireShape()
        check(saved.state == "signed" && saved.sameReservation(record) && closedUnaccepted(record.challengeId) == null)
        requireClosures(record, closures, authenticatedNow, current, false)
    }

    @Transaction
    open fun recordSigned(record: Profile03ElectionRecord, current: (LocalLineBinding?) -> Unit): Boolean {
        record.requireShape()
        require(record.state == "signed" && record.deviceSignatureB64url != null && record.acceptedEvidenceSha256 == null)
        current(line())
        val prior = find(record.challengeId) ?: return false
        if (!prior.sameReservation(record) || prior.state != "reserved" || closedUnaccepted(record.challengeId) != null) return false
        check(signed(record.challengeId, checkNotNull(record.deviceSignatureB64url)) == 1)
        current(line())
        return find(record.challengeId) == record
    }

    /** The original accepted evidence and the old physical activation are compared in one Room transaction. */
    @Transaction
    open fun install(record: Profile03ElectionRecord, current: (LocalLineBinding?) -> Unit): Boolean {
        record.requireShape()
        require(record.state == "installed" && record.deviceSignatureB64url != null && record.acceptedEvidenceSha256 != null)
        current(line())
        val prior = find(record.challengeId) ?: return false
        if (!prior.sameReservation(record) || prior.deviceSignatureB64url != record.deviceSignatureB64url ||
            closedUnaccepted(record.challengeId) != null) return false
        if (prior.state == "installed") return prior == record // Exact retry does not renew anything.
        if (prior.state != "signed") return false
        if (oldPreparations(record.accountId) != 0 || unresolvedEffects(record.accountId, "") != 0) return false
        check(accepted(record.challengeId, checkNotNull(record.acceptedEvidenceSha256)) == 1)
        current(line())
        return find(record.challengeId) == record
    }

    /** Used inside the preparation reservation transaction, never a detached read followed by a write. */
    @Transaction
    open fun requireInstalled(record: Profile03ElectionRecord, excludedAttempt: String,
        current: (LocalLineBinding?) -> Unit) {
        record.requireShape()
        require(record.state == "installed")
        current(line())
        check(find(record.challengeId) == record)
        check(unresolvedEffects(record.accountId, excludedAttempt) == 0)
        current(line())
    }
    companion object { const val CAPACITY = 128; const val CLOSURE_CAPACITY = CAPACITY * 16 }
}
