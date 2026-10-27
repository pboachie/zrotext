// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Transaction
import java.util.UUID

/** Permanent refresh provenance. No persisted observation/signature can issue a live SIM lease. */
@Entity(tableName = "selection_refresh03", primaryKeys = ["refreshId"],
    indices = [Index(value = ["bindingId", "deviceSessionSha256"])])
data class SelectionRefresh03Record(
    val refreshId: String, val accountId: String, val deviceId: String, val lineId: String,
    val bindingId: String, val bindingGeneration: Long, val originalActivationId: String,
    val originalGeneration: Long, val electionChallengeId: String, val electionIdentitySha256: String,
    val deviceSessionSha256: String, val connectionEpoch: Long, val deploymentEpoch: Long,
    /** The core's signed HTTPS origin. The actual socket/v2 record retains its WSS domain. */
    val originHash: String, val selectedSubscription: Int,
    val consentId: String, val consentConfirmedMs: Long, val consentExpiresMs: Long,
    val coreB64url: String, val observationB64url: String, val state: String = "reserved",
    val deviceSignatureB64url: String? = null, val ownerSignatureB64url: String? = null,
    val bundleSha256: String? = null, val acceptedMs: Long? = null,
    val installedSignatureB64url: String? = null, val installedMs: Long? = null,
) {
    internal fun requireShape() {
        for (value in listOf(refreshId, accountId, deviceId, lineId, bindingId, originalActivationId, electionChallengeId, consentId))
            require(UUID.fromString(value).let { it != UUID(0, 0) && it.toString() == value })
        require(bindingGeneration > originalGeneration && originalGeneration > 0 && selectedSubscription >= 0 &&
            connectionEpoch > 0 && deploymentEpoch > 0 && consentConfirmedMs > 0 && consentExpiresMs > consentConfirmedMs &&
            consentExpiresMs - consentConfirmedMs <= 300_000 &&
            listOf(electionIdentitySha256, deviceSessionSha256, originHash).all { it.matches(HEX) })
        val core = SelectionRefresh03.Core.decode(Profile03ElectionEncoding.decode(coreB64url, 496))
        val observation = Profile03ElectionEncoding.decode(observationB64url, 121)
        require(core.refresh.toString() == refreshId && core.account.toString() == accountId && core.device.toString() == deviceId &&
            core.line.toString() == lineId && core.binding.toString() == bindingId && core.bindingGeneration == bindingGeneration &&
            Draft02OutboundPreparation.hex(core.deviceSessionDigest) == deviceSessionSha256 &&
            Draft02OutboundPreparation.hex(core.originDigest) == originHash &&
            SelectionRefresh03.selectedSubscription(observation) == selectedSubscription)
        require(state in setOf("reserved", "signed", "accepted", "ack_reserved", "ack_signed", "installed", "retired"))
        deviceSignatureB64url?.let { Profile03ElectionEncoding.decode(it, 64) }
        ownerSignatureB64url?.let { Profile03ElectionEncoding.decode(it, 64) }
        installedSignatureB64url?.let { Profile03ElectionEncoding.decode(it, 64) }
        bundleSha256?.let { require(it.matches(HEX)) }
        if (deviceSignatureB64url == null) require(state in setOf("reserved", "retired") && ownerSignatureB64url == null &&
            bundleSha256 == null && acceptedMs == null && installedSignatureB64url == null && installedMs == null)
        if (ownerSignatureB64url != null) require(deviceSignatureB64url != null && bundleSha256 != null &&
            acceptedMs != null && acceptedMs in core.issuedMs until core.expiresMs)
        if (state in setOf("accepted", "ack_reserved", "ack_signed", "installed")) require(ownerSignatureB64url != null)
        if (state in setOf("ack_signed", "installed")) require(installedSignatureB64url != null)
        if (state == "signed") require(deviceSignatureB64url != null && ownerSignatureB64url == null &&
            bundleSha256 == null && acceptedMs == null && installedSignatureB64url == null && installedMs == null)
        if (state in setOf("accepted", "ack_reserved")) require(installedSignatureB64url == null && installedMs == null)
        if (state == "ack_signed") require(installedMs == null)
        if (installedMs != null) require(acceptedMs != null && installedMs >= acceptedMs && installedMs < core.expiresMs)
        if (state == "installed") require(installedMs != null)
    }
    internal fun reservation() = copy(state = "reserved", deviceSignatureB64url = null, ownerSignatureB64url = null,
        bundleSha256 = null, acceptedMs = null, installedSignatureB64url = null, installedMs = null)
    override fun toString() = "SelectionRefresh03Record(redacted)"
    companion object { private val HEX = Regex("[0-9a-f]{64}") }
}

@Dao
abstract class SelectionRefresh03Dao {
    @Query("SELECT * FROM selection_refresh03 WHERE refreshId = :id")
    abstract fun find(id: String): SelectionRefresh03Record?
    @Query("SELECT COUNT(*) FROM selection_refresh03")
    protected abstract fun count(): Int
    @Query("SELECT EXISTS(SELECT 1 FROM selection_refresh03 WHERE bindingId = :binding AND deviceSessionSha256 = :session AND (state != 'retired' OR deviceSignatureB64url IS NOT NULL))")
    protected abstract fun outstanding(binding: String, session: String): Boolean
    @Query("SELECT EXISTS(SELECT 1 FROM selection_refresh03 WHERE bindingId = :binding AND deviceSessionSha256 = :session AND deviceSignatureB64url IS NOT NULL)")
    abstract fun everSigned(binding: String, session: String): Boolean
    @Query("SELECT COUNT(*) FROM selection_refresh03 WHERE bindingId = :binding AND deviceSessionSha256 = :session")
    protected abstract fun connectionCount(binding: String, session: String): Int
    @Query("SELECT * FROM selection_refresh03 WHERE bindingId = :binding AND deviceSessionSha256 = :session AND refreshId != :target AND (state != 'retired' OR deviceSignatureB64url IS NOT NULL)")
    protected abstract fun priorReservations(binding: String, session: String, target: String): List<SelectionRefresh03Record>
    @Query("SELECT * FROM selection_refresh03_closures WHERE refreshId = :id")
    abstract fun closure(id: String): SelectionRefresh03ClosureRecord?
    @Query("SELECT * FROM selection_refresh03_closures")
    protected abstract fun retainedClosures(): List<SelectionRefresh03ClosureRecord>
    @Query("SELECT COUNT(*) FROM selection_refresh03_closures")
    protected abstract fun closureCount(): Int
    @Query("SELECT * FROM local_line_binding WHERE slot = 1")
    protected abstract fun line(): LocalLineBinding?
    @Query("SELECT * FROM profile03_elections WHERE challengeId = :id")
    protected abstract fun election(id: String): Profile03ElectionRecord?
    @Query("SELECT COUNT(*) FROM sms_attempts WHERE (accountId = :account OR accountId IS NULL) AND (evidenceConflict = 1 OR state IN ('reserved','radio_started','submitting','submitted','unknown','delivery_unknown','partial_failure'))")
    protected abstract fun unresolvedEffects(account: String): Int
    @Insert
    protected abstract fun insert(record: SelectionRefresh03Record)
    @Insert
    protected abstract fun insertClosure(record: SelectionRefresh03ClosureRecord)
    @Query("UPDATE selection_refresh03 SET state = :state, deviceSignatureB64url = :device, ownerSignatureB64url = :owner, bundleSha256 = :bundle, acceptedMs = :accepted, installedSignatureB64url = :ack, installedMs = :installed WHERE refreshId = :id AND state = :expected")
    protected abstract fun transition(id: String, expected: String, state: String, device: String?, owner: String?,
        bundle: String?, accepted: Long?, ack: String?, installed: Long?): Int
    @Query("UPDATE selection_refresh03 SET state = 'retired' WHERE refreshId = :id AND state != 'retired'")
    abstract fun retire(id: String): Int

    private fun original(record: SelectionRefresh03Record, current: (LocalLineBinding?) -> Unit) {
        current(line()) // RAM-only lifetime/selection guard, after acquiring the writer.
        val selected = checkNotNull(line())
        val accepted = checkNotNull(election(record.electionChallengeId))
        check(selected.accountId == record.accountId && selected.deviceId == record.deviceId && selected.lineId == record.lineId &&
            selected.generation == record.originalGeneration && selected.subscriptionId == record.selectedSubscription &&
            selected.protocolVersion == 2 && selected.v2Purpose == "sealed" && selected.v2ChallengeId == record.originalActivationId &&
            accepted.state == "installed" && accepted.accountId == record.accountId && accepted.deviceId == record.deviceId &&
            accepted.lineId == record.lineId && accepted.newBindingId == record.bindingId && accepted.newGeneration == record.bindingGeneration &&
            accepted.acceptedEvidenceSha256 == record.electionIdentitySha256)
        check(unresolvedEffects(record.accountId) == 0)
        current(selected)
    }

    private fun connectionReservations(record: SelectionRefresh03Record, incoming: List<SelectionRefresh03ClosureRecord>): Int {
        val ids = (retainedClosures() + incoming).filter {
            val core = it.core()
            core.binding.toString() == record.bindingId &&
                Draft02OutboundPreparation.hex(core.deviceSessionDigest) == record.deviceSessionSha256
        }.map { it.refreshId }.toSet()
        // Unseen server reservations count toward the same bound without fabricated local rows.
        return connectionCount(record.bindingId, record.deviceSessionSha256) + ids.count { find(it) == null }
    }

    /** A crash burns this challenge; every released signature keeps its unknown-outcome fence. */
    @Transaction
    open fun reserve(record: SelectionRefresh03Record, current: (LocalLineBinding?) -> Unit): Boolean {
        record.requireShape(); require(record == record.reservation())
        original(record, current)
        if (count() >= CAPACITY || connectionReservations(record, emptyList()) >= CONNECTION_CAPACITY ||
            find(record.refreshId) != null || outstanding(record.bindingId, record.deviceSessionSha256)) return false
        insert(record)
        original(record, current)
        return find(record.refreshId) == record
    }

    /** The full authenticated historical proofs/current hardware/actual fresh phone decision
     * must be checked outside Room first. No timeout or passive status invokes this writer.
     */
    @Transaction
    open fun reserveWithClosures(record: SelectionRefresh03Record, rows: List<SelectionRefresh03ClosureRecord>,
        now: Long, current: (LocalLineBinding?) -> Unit): Boolean {
        record.requireShape(); require(record == record.reservation())
        original(record, current)
        val target = SelectionRefresh03.Core.decode(Profile03ElectionEncoding.decode(record.coreB64url, 496))
        SelectionRefresh03Closure.requireChain(target, rows, now)
        require(rows.all { record.consentConfirmedMs >= it.core().expiresMs })
        val indexed = rows.associateBy { it.refreshId }
        for (saved in retainedClosures()) {
            if (SelectionRefresh03Closure.sameScope(saved.core(), target)) check(indexed[saved.refreshId] == saved)
        }
        for (prior in priorReservations(record.bindingId, record.deviceSessionSha256, record.refreshId)) {
            prior.requireShape()
            check(prior.ownerSignatureB64url == null && prior.acceptedMs == null && prior.installedMs == null)
            val row = checkNotNull(indexed[prior.refreshId])
            check(prior.coreB64url == row.coreB64url && prior.consentId != record.consentId &&
                prior.connectionEpoch == record.connectionEpoch && prior.deploymentEpoch == record.deploymentEpoch &&
                prior.originalActivationId == record.originalActivationId && prior.originalGeneration == record.originalGeneration &&
                prior.electionChallengeId == record.electionChallengeId && prior.electionIdentitySha256 == record.electionIdentitySha256)
        }
        for (row in rows) {
            find(row.refreshId)?.let { prior ->
                prior.requireShape()
                check(prior.bindingId == record.bindingId && prior.deviceSessionSha256 == record.deviceSessionSha256 &&
                    prior.coreB64url == row.coreB64url && prior.ownerSignatureB64url == null && prior.acceptedMs == null && prior.installedMs == null)
            }
            val saved = closure(row.refreshId)
            check(saved == null || saved == row)
        }
        if (count() >= CAPACITY || connectionReservations(record, rows) >= CONNECTION_CAPACITY ||
            closureCount() + rows.count { closure(it.refreshId) == null } > CLOSURE_CAPACITY || find(record.refreshId) != null) return false
        for (row in rows) if (closure(row.refreshId) == null) insertClosure(row)
        insert(record)
        original(record, current)
        check(rows.all { closure(it.refreshId) == it })
        return find(record.refreshId) == record
    }

    @Transaction
    open fun advance(record: SelectionRefresh03Record, expectedState: String, current: (LocalLineBinding?) -> Unit): Boolean {
        record.requireShape()
        val expected = when (record.state) {
            "signed" -> "reserved"
            "accepted" -> "signed"
            "ack_reserved" -> "accepted"
            "ack_signed" -> "ack_reserved"
            "installed" -> "ack_signed"
            else -> error("Unsupported refresh transition")
        }
        require(expectedState == expected)
        original(record, current)
        val prior = find(record.refreshId) ?: return false
        if (closure(record.refreshId) != null) return false
        if (prior == record) return true // Exact retry returns original facts, never new timestamps.
        if (prior.state != expected || prior.reservation() != record.reservation()) return false
        if (prior.deviceSignatureB64url != null && prior.deviceSignatureB64url != record.deviceSignatureB64url ||
            prior.ownerSignatureB64url != null && prior.ownerSignatureB64url != record.ownerSignatureB64url ||
            prior.bundleSha256 != null && prior.bundleSha256 != record.bundleSha256 ||
            prior.acceptedMs != null && prior.acceptedMs != record.acceptedMs ||
            prior.installedSignatureB64url != null && prior.installedSignatureB64url != record.installedSignatureB64url ||
            prior.installedMs != null && prior.installedMs != record.installedMs) return false
        check(transition(record.refreshId, expected, record.state, record.deviceSignatureB64url, record.ownerSignatureB64url,
            record.bundleSha256, record.acceptedMs, record.installedSignatureB64url, record.installedMs) == 1)
        original(record, current)
        return find(record.refreshId) == record
    }
    companion object { const val CAPACITY = 128; const val CONNECTION_CAPACITY = 16; const val CLOSURE_CAPACITY = CAPACITY * 16 }
}
