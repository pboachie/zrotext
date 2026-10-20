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

/** All actual content ingress reserves here before either legacy writer. No provider,
 * key, crypto or network operation belongs inside this short process ordering gate. */
internal object Capture03IngressGate {
    private val lock = Any()
    fun <T> reserve(action: () -> T): T = synchronized(lock, action)
    fun requireHeld() = check(Thread.holdsLock(lock))
    fun requireOutside() = check(!Thread.holdsLock(lock))
}

/** Permanent keyed PDU routing fence. Drop/blocked rows contain no content/capture sequence. */
@Entity(tableName = "capture03_routes", indices = [Index(value = ["captureId"], unique = true)])
data class Capture03Route(@PrimaryKey val token: String, val route: String,
    val provenanceSha256: String?, val captureId: String?, val recordedMs: Long) {
    internal fun requireShape() {
        captureHash(token); require(recordedMs > 0)
        provenanceSha256?.let(::captureHash); captureId?.let(Profile03ClosedUnaccepted::uuid)
        require(route in setOf("legacy", "drop03", "blocked", "capture03"))
        require((route == "capture03") == (captureId != null))
        if (route in setOf("drop03", "capture03")) require(provenanceSha256 != null)
    }
    override fun toString() = "Capture03Route(content-free)"
}

/** Retained only after genuine original-proof verification. It excludes legacy capture on cold
 * load, but never grants a sequence/current physical or content permission. Exact original bytes
 * are protected outside Room; the immutable identity cannot be replaced by a later manifest. */
@Entity(tableName = "capture03_modes")
data class Capture03Mode(@PrimaryKey val electionId: String, val accountId: String, val deviceId: String,
    val lineId: String, val bindingId: String, val originalIdentity: String, val evidenceSha256: String,
    val protectedEvidence: ByteArray, val nonce: ByteArray) {
    internal fun requireShape() {
        listOf(electionId, accountId, deviceId, lineId, bindingId).forEach(Profile03ClosedUnaccepted::uuid)
        listOf(originalIdentity, evidenceSha256).forEach(::captureHash)
        require(nonce.size == 12 && protectedEvidence.size in 16..131_088)
    }
    internal fun sameIdentity(other: Capture03Mode) = listOf(electionId, accountId, deviceId, lineId,
        bindingId, originalIdentity, evidenceSha256) == listOf(other.electionId, other.accountId,
        other.deviceId, other.lineId, other.bindingId, other.originalIdentity, other.evidenceSha256)
    override fun toString() = "Capture03Mode(protected-original-history-only)"
}

/** Immutable first-ever origin and monotonically burned sequence. There is deliberately NO
 * insertion/initialization API in this source. A genuine two-sided bootstrap must install it.
 * Empty tables, a downloaded row or a server maximum can never construct a usable allocator. */
@Entity(tableName = "capture03_counters", primaryKeys = ["accountId", "deviceId"])
data class Capture03Counter(val accountId: String, val deviceId: String, val bootstrapId: String,
    val openingId: String, val associationSha256: String, val receiptSha256: String,
    val canaryKeyId: String, val enrolledSigningKeyId: String, val lastSequence: Long,
    val protectedOrigin: ByteArray, val nonce: ByteArray) {
    internal fun requireShape() {
        listOf(accountId, deviceId, bootstrapId, openingId).forEach(Profile03ClosedUnaccepted::uuid)
        listOf(associationSha256, receiptSha256, canaryKeyId, enrolledSigningKeyId).forEach(::captureHash)
        require(canaryKeyId != enrolledSigningKeyId && lastSequence >= 0 && nonce.size == 12 && protectedOrigin.size in 16..131_088)
    }
    internal fun same(other: Capture03Counter) = listOf(accountId, deviceId, bootstrapId, openingId,
        associationSha256, receiptSha256, canaryKeyId, enrolledSigningKeyId, lastSequence) ==
        listOf(other.accountId, other.deviceId, other.bootstrapId, other.openingId,
            other.associationSha256, other.receiptSha256, other.canaryKeyId, other.enrolledSigningKeyId, other.lastSequence) &&
        protectedOrigin.contentEquals(other.protectedOrigin) && nonce.contentEquals(other.nonce)
    override fun toString() = "Capture03Counter(protected-bootstrap-required)"
}

/** Personal material is protected before a writer. Phase/sequence/hash tombstones and route
 * survive redaction. A row never recreates its original first-receipt RAM ticket. */
@Entity(tableName = "capture03_records", indices = [Index(value = ["routeToken"], unique = true),
    Index(value = ["accountId", "deviceId", "sequence"], unique = true)])
data class Capture03Record(@PrimaryKey val captureId: String, val routeToken: String,
    val accountId: String, val deviceId: String, val lineId: String, val intervalId: String,
    val requestId: String, val statementSha256: String, val firstLowerMs: Long,
    val firstUpperMs: Long, val firstElapsedMs: Long, val phase: String,
    val sequence: Long? = null, val permissionExpiresMs: Long? = null,
    val unsignedEnvelopeSha256: String? = null, val envelopeSha256: String? = null,
    val envelopeSignatureSha256: String? = null, val intentSha256: String? = null,
    val intentSignatureSha256: String? = null, val packetSha256: String? = null,
    val receiptSha256: String? = null, val unknown: Boolean = false,
    val redactedMs: Long? = null, val protectedPayload: ByteArray?, val nonce: ByteArray?) {
    internal fun requireShape() {
        listOf(captureId, accountId, deviceId, lineId, intervalId, requestId).forEach(Profile03ClosedUnaccepted::uuid)
        require(captureId != requestId)
        listOfNotNull(routeToken, statementSha256, unsignedEnvelopeSha256, envelopeSha256,
            envelopeSignatureSha256, intentSha256, intentSignatureSha256, packetSha256, receiptSha256).forEach(::captureHash)
        require(firstLowerMs > 0 && firstUpperMs >= firstLowerMs && firstUpperMs - firstLowerMs <= 2_000 && firstElapsedMs >= 0)
        val step = steps.indexOf(phase); require(step >= 0)
        require((sequence != null) == (step >= 1) && (permissionExpiresMs != null) == (step >= 1))
        sequence?.let { require(it > 0) }; permissionExpiresMs?.let { require(it > firstUpperMs && it - firstLowerMs <= 60_000) }
        require((unsignedEnvelopeSha256 != null) == (step >= 2) && (envelopeSha256 != null) == (step >= 3) &&
            (envelopeSignatureSha256 != null) == (step >= 3) && (intentSha256 != null) == (step >= 4) &&
            (intentSignatureSha256 != null) == (step >= 5) && (packetSha256 != null) == (step >= 5) &&
            (receiptSha256 != null) == (step >= 7))
        if (redactedMs == null) require(protectedPayload != null && protectedPayload.size in 16..131_088 && nonce?.size == 12)
        else require(redactedMs > 0 && protectedPayload == null && nonce == null)
    }
    internal fun same(other: Capture03Record) = metadata() == other.metadata() &&
        arrays(protectedPayload, other.protectedPayload) && arrays(nonce, other.nonce)
    internal fun sameScope(other: Capture03Record) = listOf(captureId, routeToken, accountId, deviceId, lineId,
        intervalId, requestId, statementSha256, firstLowerMs, firstUpperMs, firstElapsedMs) ==
        listOf(other.captureId, other.routeToken, other.accountId, other.deviceId, other.lineId,
            other.intervalId, other.requestId, other.statementSha256, other.firstLowerMs, other.firstUpperMs, other.firstElapsedMs)
    private fun metadata() = listOf(captureId, routeToken, accountId, deviceId, lineId, intervalId, requestId,
        statementSha256, firstLowerMs, firstUpperMs, firstElapsedMs, phase, sequence, permissionExpiresMs,
        unsignedEnvelopeSha256, envelopeSha256, envelopeSignatureSha256, intentSha256, intentSignatureSha256,
        packetSha256, receiptSha256, unknown, redactedMs)
    override fun toString() = "Capture03Record(protected-content-and-permanent-burns)"
    companion object {
        internal val steps = listOf("identity", "sealing", "envelope_reserved", "envelope_signed", "intent_reserved", "packet", "submitted", "acknowledged")
        private fun arrays(a: ByteArray?, b: ByteArray?) = if (a == null || b == null) a == null && b == null else a.contentEquals(b)
    }
}

@Dao
abstract class Capture03Dao {
    @Query("SELECT * FROM capture03_routes WHERE token = :token") abstract fun route(token: String): Capture03Route?
    @Query("SELECT * FROM capture03_records WHERE captureId = :capture") abstract fun record(capture: String): Capture03Record?
    @Query("SELECT * FROM capture03_counters WHERE accountId = :account AND deviceId = :device")
    abstract fun counter(account: String, device: String): Capture03Counter?
    @Query("SELECT * FROM capture03_modes WHERE electionId = :election") abstract fun mode(election: String): Capture03Mode?
    @Query("SELECT * FROM capture03_modes") abstract fun modes(): List<Capture03Mode>
    @Query("SELECT * FROM profile03_elections WHERE state IN ('reserved','signed','installed') OR deviceSignatureB64url IS NOT NULL OR acceptedEvidenceSha256 IS NOT NULL")
    abstract fun releasedElections(): List<Profile03ElectionRecord>
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertMode(row: Capture03Mode)
    /** This writer is called only by the completed original proof reader. The callback is RAM
     * only; no Keystore/root-storage wait is permitted inside the transaction. */
    @Transaction open fun retainOriginal(row: Capture03Mode, current: () -> Unit) {
        row.requireShape(); current()
        val prior = mode(row.electionId)
        if (prior == null) insertMode(row) else require(prior.sameIdentity(row))
        current()
    }
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertRoute(row: Capture03Route)
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertRecord(row: Capture03Record)
    @Update protected abstract fun updateRecord(row: Capture03Record): Int
    @Query("UPDATE capture03_counters SET lastSequence = :next WHERE accountId = :account AND deviceId = :device AND lastSequence = :prior AND receiptSha256 = :receipt")
    protected abstract fun increment(account: String, device: String, prior: Long, next: Long, receipt: String): Int

    /** Existing route always wins. legacyEvidence can only exclude03; its false value never
     * authenticates a candidate. The actual caller verifies provenance/first ticket outside. */
    @Transaction open fun claim(candidate: Capture03Route, first: Capture03Record?, legacyEvidence: Boolean,
        ramCurrent: () -> Unit): Capture03Route {
        Capture03IngressGate.requireHeld(); candidate.requireShape(); ramCurrent()
        route(candidate.token)?.let { return it.also { row -> row.requireShape(); ramCurrent() } }
        val chosen = if (legacyEvidence) Capture03Route(candidate.token, "legacy", null, null, candidate.recordedMs) else candidate
        if (chosen.route == "capture03") {
            val row = checkNotNull(first); row.requireShape()
            require(row.phase == "identity" && row.captureId == chosen.captureId && row.routeToken == chosen.token &&
                !row.unknown && row.redactedMs == null && record(row.captureId) == null)
            insertRecord(row)
        } else require(first == null || legacyEvidence)
        insertRoute(chosen); ramCurrent(); return chosen
    }

    /** A duplicate/old identity cannot reserve another sequence. There is no0 insertion or
     * MAX recovery here: the actual bootstrap owner must already have installed the counter. */
    @Transaction open fun reserveSequence(old: Capture03Record, next: Capture03Record,
        expectedCounter: Capture03Counter, ramCurrent: () -> Unit) {
        Capture03IngressGate.requireHeld(); ramCurrent(); old.requireShape(); next.requireShape(); expectedCounter.requireShape()
        require(old.phase == "identity" && next.phase == "sealing" && old.sameScope(next) &&
            !old.unknown && !next.unknown && old.redactedMs == null && next.redactedMs == null)
        check(record(old.captureId)?.same(old) == true && route(old.routeToken)?.let { it.route == "capture03" && it.captureId == old.captureId } == true)
        require(expectedCounter.accountId == old.accountId && expectedCounter.deviceId == old.deviceId && expectedCounter.lastSequence < Long.MAX_VALUE)
        check(counter(old.accountId, old.deviceId)?.same(expectedCounter) == true)
        require(next.sequence == expectedCounter.lastSequence + 1)
        check(increment(old.accountId, old.deviceId, expectedCounter.lastSequence, checkNotNull(next.sequence), expectedCounter.receiptSha256) == 1)
        check(updateRecord(next) == 1); ramCurrent()
    }

    /** Provider work finished outside the writer. Strict forward-only CAS preserves every
     * previous commitment; a reserved or unknown key call is never entered again. */
    @Transaction open fun advance(old: Capture03Record, next: Capture03Record, ramCurrent: () -> Unit) {
        ramCurrent(); old.requireShape(); next.requireShape()
        check(record(old.captureId)?.same(old) == true)
        require(old.sameScope(next) && old.sequence == next.sequence && old.permissionExpiresMs == next.permissionExpiresMs &&
            !old.unknown && !next.unknown && old.redactedMs == null && next.redactedMs == null &&
            Capture03Record.steps.indexOf(next.phase) == Capture03Record.steps.indexOf(old.phase) + 1 && old.phase !in setOf("identity", "submitted", "acknowledged"))
        preserve(old, next); check(updateRecord(next) == 1); ramCurrent()
    }
    /** Negative history is irreversible and creates no capture/upload permission. */
    @Transaction open fun markUnknown(expected: Capture03Record): Capture03Record {
        expected.requireShape(); check(record(expected.captureId)?.same(expected) == true)
        val next = expected.copy(unknown = true); check(updateRecord(next) == 1); return next
    }
    /** Exact independently verified committed ACK/status may finish history after Stop.
     * It cannot reissue a RAM ticket or clear an unknown hardware/network burn. */
    @Transaction open fun acknowledge(old: Capture03Record, next: Capture03Record, historicalCurrent: () -> Unit) {
        historicalCurrent(); old.requireShape(); next.requireShape(); check(record(old.captureId)?.same(old) == true)
        require(old.phase in setOf("packet", "submitted") && next.phase == "acknowledged" && old.sameScope(next) &&
            old.sequence == next.sequence && old.permissionExpiresMs == next.permissionExpiresMs && old.unknown == next.unknown &&
            old.redactedMs == next.redactedMs)
        preserve(old, next); check(updateRecord(next) == 1); historicalCurrent()
    }
    @Transaction open fun redact(expected: Capture03Record, at: Long): Capture03Record {
        expected.requireShape(); require(at > 0); check(record(expected.captureId)?.same(expected) == true)
        if (expected.redactedMs != null) return expected
        val next = expected.copy(protectedPayload = null, nonce = null, redactedMs = at)
        next.requireShape(); check(updateRecord(next) == 1); return next
    }
    private fun preserve(old: Capture03Record, next: Capture03Record) {
        val before = listOf(old.unsignedEnvelopeSha256, old.envelopeSha256, old.envelopeSignatureSha256,
            old.intentSha256, old.intentSignatureSha256, old.packetSha256, old.receiptSha256)
        val after = listOf(next.unsignedEnvelopeSha256, next.envelopeSha256, next.envelopeSignatureSha256,
            next.intentSha256, next.intentSignatureSha256, next.packetSha256, next.receiptSha256)
        require(before.zip(after).all { (a, b) -> a == null || a == b })
    }
}

private fun captureHash(value: String) = require(value.matches(Regex("[0-9a-f]{64}")) && value.any { it != '0' })
