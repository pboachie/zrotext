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
    @Query("SELECT COUNT(*) FROM profile03_elections")
    protected abstract fun count(): Int
    @Query("SELECT COUNT(*) FROM profile03_elections WHERE accountId = :account AND (state IN ('reserved','signed','installed') OR deviceSignatureB64url IS NOT NULL OR acceptedEvidenceSha256 IS NOT NULL)")
    protected abstract fun outstanding(account: String): Int
    @Query("SELECT * FROM local_line_binding WHERE slot = 1")
    protected abstract fun line(): LocalLineBinding?
    @Query("SELECT COUNT(*) FROM sealed_preparations WHERE accountId = :account")
    protected abstract fun oldPreparations(account: String): Int
    @Query("SELECT COUNT(*) FROM sms_attempts WHERE (accountId = :account OR accountId IS NULL) AND attemptId != :excluded AND (evidenceConflict = 1 OR state IN ('reserved','radio_started','submitting','submitted','unknown','delivery_unknown','partial_failure'))")
    protected abstract fun unresolvedEffects(account: String, excluded: String): Int
    @Insert
    protected abstract fun insert(record: Profile03ElectionRecord)
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

    @Transaction
    open fun recordSigned(record: Profile03ElectionRecord, current: (LocalLineBinding?) -> Unit): Boolean {
        record.requireShape()
        require(record.state == "signed" && record.deviceSignatureB64url != null && record.acceptedEvidenceSha256 == null)
        current(line())
        val prior = find(record.challengeId) ?: return false
        if (!prior.sameReservation(record) || prior.state != "reserved") return false
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
        if (!prior.sameReservation(record) || prior.deviceSignatureB64url != record.deviceSignatureB64url) return false
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
    companion object { const val CAPACITY = 128 }
}
