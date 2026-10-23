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
import java.util.concurrent.atomic.AtomicBoolean

/** The original source event precedes clock I/O. Its order is the same-writer RAW callback
 * ordinal, never a wall timestamp/UUID sort or the separate global capture sequence. */
@Entity(tableName = "typed_history03_sources", indices = [Index(value = ["eventId"], unique = true), Index("attemptId")])
internal data class TypedHistory03Source(
    @PrimaryKey val slot: String,
    val eventId: String,
    val attemptId: String,
    val commandSha256: String,
    val evidence: Int,
    /** -1 for aggregate/derived assertions; sent facts retain their actual index. */
    val segmentIndex: Int,
    val sourceOrdinal: Long,
    val rawEventIds: String,
    val derivation: String,
    val basisPhase: String,
    val assertionB64url: String? = null,
    val assertionSha256: String? = null,
    val assertionClockRequestId: String? = null
) {
    fun requireShape() {
        uuid(eventId); uuid(attemptId)
        require(evidence in 0..5 && segmentIndex in -1..5 && sourceOrdinal > 0 &&
            slot == "$attemptId:$evidence:$segmentIndex" && commandSha256.matches(Regex("[0-9a-f]{64}")) &&
            if (evidence <= 1) segmentIndex >= 0 else segmentIndex == -1)
        val raw = rawEventIds.split(',')
        require(raw.size in 1..12 && raw.distinct().size == raw.size)
        raw.forEach(::uuid)
        require(derivation in setOf("sent_callback", "complete_delivery", "contrary_callback"))
        require(basisPhase in setOf("reserved", "ack_authorized", "platform_entry_reserved", "pre_entry_closing", "closed_no_submit"))
        if (derivation == "sent_callback") require(evidence <= 1 && raw == listOf(eventId))
        if (derivation == "complete_delivery") require(evidence == 2 && eventId !in raw)
        if (derivation == "contrary_callback") require(evidence == 5 && eventId !in raw)
        require((assertionB64url == null) == (assertionSha256 == null) &&
            (assertionB64url == null) == (assertionClockRequestId == null))
        assertionB64url?.let { encoded ->
            val command = TypedOutcome03Command.decode(TypedSubmit03Record.unbase(encoded))
            require(command.eventId == eventId && command.attemptId == attemptId && command.evidence == evidence &&
                command.segmentIndex == segmentIndex.takeUnless { it < 0 } &&
                TypedSubmit03Record.hex(command.commitment()) == assertionSha256)
            uuid(checkNotNull(assertionClockRequestId))
        }
    }
    override fun toString() = "TypedHistory03Source(immutable-original-fact)"
    fun requireRaw(command: TypedSubmit03Command, facts: List<TypedCallback03Record>) {
        requireShape()
        require(attemptId == command.attemptId && commandSha256 == TypedSubmit03Record.hex(command.commitment()))
        val raw = rawEventIds.split(',').map { id -> facts.single { it.eventId == id } }
        require(raw.all { it.attemptId == attemptId && checkNotNull(it.arrivalOrdinal) in 1..sourceOrdinal } &&
            raw.any { it.arrivalOrdinal == sourceOrdinal } &&
            raw.map { checkNotNull(it.arrivalOrdinal) } == raw.map { checkNotNull(it.arrivalOrdinal) }.sorted())
        when (derivation) {
            "sent_callback" -> require(raw.size == 1 && !raw[0].delivery && raw[0].segmentIndex == segmentIndex &&
                evidence == if (raw[0].resultCode == android.app.Activity.RESULT_OK) 0 else 1)
            "complete_delivery" -> require(raw.size == command.segmentCount &&
                raw.map { it.segmentIndex }.toSet() == (0 until command.segmentCount).toSet() && raw.all {
                    it.delivery && it.resultCode == android.app.Activity.RESULT_OK && it.deliveryStatus == DeliveryStatus.RECEIVED })
            "contrary_callback" -> require(basisPhase != "platform_entry_reserved" || raw.size == 2 &&
                raw[0].segmentIndex == raw[1].segmentIndex && raw[0].delivery == raw[1].delivery &&
                (if (raw[0].delivery) CallbackEvidence.delivery(raw[0].deliveryStatus, raw[1].deliveryStatus)
                else CallbackEvidence.sent(raw[0].resultCode, raw[1].resultCode)) == CallbackEvidence.Decision.CONFLICT)
        }
    }
    companion object {
        private fun uuid(value: String) { require(UUID.fromString(value).let { it != UUID(0, 0) && it.toString() == value }) }
    }
}

/** Each genuine new passive sample has its own permanently burned nonce and actual epoch.
 * An entered/unknown request cannot become a second transport invocation or a fresh clock. */
@Entity(tableName = "typed_history03_clocks", indices = [Index("attemptId"), Index("subjectId")])
internal data class TypedHistory03Request(
    @PrimaryKey val requestId: String,
    val attemptId: String,
    val messageId: String,
    val commandSha256: String,
    val subjectId: String,
    val subjectKind: String,
    val accountId: String,
    val deviceId: String,
    val originSha256: String,
    val originalEnrolledPoint: String,
    val connectionEpoch: Long,
    val lineVersion: Int,
    val requestB64url: String,
    val entered: Boolean = false,
    val replyB64url: String? = null
) {
    fun query() = TypedHistory03Wire.Query(requestId, messageId, attemptId)
    fun requireShape() {
        query()
        for (id in listOf(subjectId, accountId, deviceId)) require(UUID.fromString(id).let { it != UUID(0, 0) && it.toString() == id })
        require(subjectKind in setOf("assertion", "closure") && connectionEpoch > 0 && lineVersion in 1..2 &&
            commandSha256.matches(Regex("[0-9a-f]{64}")) && originSha256.matches(Regex("[0-9a-f]{64}")))
        require(TypedSubmit03Record.unbase(originalEnrolledPoint).size == 65 &&
            TypedSubmit03Record.unbase(requestB64url).contentEquals(TypedHistory03Wire.request(connectionEpoch, query())))
        require(replyB64url == null || entered)
        replyB64url?.let { require(TypedSubmit03Record.unbase(it).size in 2..Profile03Json.MAX_BYTES) }
    }
    fun requireOriginal(row: TypedSubmit03Record) {
        requireShape(); row.requireShape()
        require(row.attemptId == attemptId && row.messageId == messageId && row.accountId == accountId &&
            row.deviceId == deviceId && row.commandSha256 == commandSha256 && row.originalOriginSha256 == originSha256 &&
            row.originalEnrolledPoint == originalEnrolledPoint && row.lastCallbackOrdinal != null)
    }
    override fun toString() = "TypedHistory03Request(retained-passive-nonce)"
}

/** Only the file-private implementation from the successful new-entry transaction exists.
 * A cold entered row cannot recreate this one-use transport ticket. It grants no effect. */
internal sealed interface TypedHistory03Entry {
    fun consume(): TypedHistory03Request
}
private class CommittedTypedHistory03Entry(private val original: TypedHistory03Request) : TypedHistory03Entry {
    private val unused = AtomicBoolean(true)
    override fun consume(): TypedHistory03Request {
        check(unused.compareAndSet(true, false)) { "Original history read already entered" }
        return original
    }
}

@Dao
internal abstract class TypedHistory03Dao {
    @Query("SELECT * FROM typed_history03_sources WHERE slot = :slot")
    abstract fun source(slot: String): TypedHistory03Source?
    @Query("SELECT * FROM typed_history03_sources WHERE attemptId = :attempt ORDER BY sourceOrdinal,slot")
    abstract fun sources(attempt: String): List<TypedHistory03Source>
    @Query("SELECT * FROM typed_history03_clocks WHERE requestId = :request")
    abstract fun clock(request: String): TypedHistory03Request?
    @Query("SELECT * FROM typed_history03_clocks WHERE attemptId = :attempt")
    abstract fun clocks(attempt: String): List<TypedHistory03Request>
    @Query("SELECT s.attemptId FROM typed_submit03 s WHERE s.accountId = :account AND s.deviceId = :device AND s.originalOriginSha256 = :origin AND s.originalEnrolledPoint = :point AND s.attemptId > :after AND ((s.phase = 'pre_entry_closing' AND s.conflict = 0) OR EXISTS(SELECT 1 FROM typed_history03_sources f WHERE f.attemptId = s.attemptId AND f.assertionB64url IS NULL)) ORDER BY s.attemptId LIMIT 16")
    abstract fun pendingAttempts(account: String, device: String, origin: String, point: String, after: String): List<String>
    @Query("SELECT * FROM typed_submit03 WHERE attemptId = :attempt")
    protected abstract fun submit(attempt: String): TypedSubmit03Record?
    @Query("SELECT * FROM typed_callback03 WHERE attemptId = :attempt")
    protected abstract fun callbacks(attempt: String): List<TypedCallback03Record>
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertClock(row: TypedHistory03Request)
    @Update(onConflict = OnConflictStrategy.ABORT) protected abstract fun updateClock(row: TypedHistory03Request): Int
    @Update(onConflict = OnConflictStrategy.ABORT) protected abstract fun updateSource(row: TypedHistory03Source): Int

    @Transaction
    open fun reserveClock(expected: TypedSubmit03Record, candidate: TypedHistory03Request, current: () -> Unit): Boolean {
        candidate.requireOriginal(expected); require(!candidate.entered && candidate.replyB64url == null)
        current()
        if (submit(expected.attemptId) != expected || clock(candidate.requestId) != null) return false
        if (candidate.subjectKind == "assertion") {
            val source = sources(expected.attemptId).singleOrNull { it.eventId == candidate.subjectId } ?: return false
            source.requireShape(); if (source.assertionB64url != null || source.commandSha256 != expected.commandSha256) return false
            source.requireRaw(expected.command(), callbacks(expected.attemptId))
        } else if (expected.phase != "pre_entry_closing" || expected.closingId != candidate.subjectId ||
            expected.conflict || callbacks(expected.attemptId).isNotEmpty()) return false
        insertClock(candidate); current(); return true
    }

    @Transaction
    open fun enterClock(expected: TypedHistory03Request, current: () -> Unit): TypedHistory03Entry? {
        expected.requireShape(); require(!expected.entered && expected.replyB64url == null)
        current()
        if (clock(expected.requestId) != expected) return null
        val row = checkNotNull(submit(expected.attemptId))
        expected.requireOriginal(row)
        if (expected.subjectKind == "assertion") {
            val source = sources(expected.attemptId).singleOrNull { it.eventId == expected.subjectId } ?: return null
            if (source.assertionB64url != null) return null
            source.requireRaw(row.command(), callbacks(row.attemptId))
        } else if (row.phase != "pre_entry_closing" || row.closingId != expected.subjectId ||
            row.conflict || callbacks(row.attemptId).isNotEmpty()) return null
        val next = expected.copy(entered = true)
        check(updateClock(next) == 1)
        current(); return CommittedTypedHistory03Entry(next)
    }

    /** Actual returned bytes are candidate history only. This append creates no clock. */
    @Transaction
    open fun retainClockReply(expected: TypedHistory03Request, reply: ByteArray): Boolean {
        expected.requireShape(); require(expected.entered && expected.replyB64url == null && reply.size in 2..Profile03Json.MAX_BYTES)
        if (clock(expected.requestId) != expected) return false
        check(updateClock(expected.copy(replyB64url = TypedSubmit03Record.base(reply))) == 1); return true
    }

    @Transaction
    open fun retainFirstAssertion(expected: TypedHistory03Source, actual: TypedHistory03Clock.Sample): TypedHistory03Source? {
        expected.requireShape(); require(expected.assertionB64url == null)
        val row = submit(expected.attemptId) ?: return null
        if (source(expected.slot) != expected || expected.commandSha256 != row.commandSha256) return null
        expected.requireRaw(row.command(), callbacks(row.attemptId))
        val request = clock(actual.requestId) ?: return null
        request.requireOriginal(row)
        if (!request.entered || request.replyB64url == null || request.subjectKind != "assertion" || request.subjectId != expected.eventId) return null
        val stamp = actual.nowFor(row, request)
        val command = TypedOutcome03Command.create(row.command(), expected.eventId, expected.evidence,
            expected.segmentIndex.takeUnless { it < 0 }, stamp)
        val next = expected.copy(assertionB64url = TypedSubmit03Record.base(command.bytes()),
            assertionSha256 = TypedSubmit03Record.hex(command.commitment()), assertionClockRequestId = request.requestId)
        next.requireShape(); check(updateSource(next) == 1)
        actual.nowFor(row, request) // RAM-only post-wait guard; any expiry rolls back the first command.
        return next
    }
}
