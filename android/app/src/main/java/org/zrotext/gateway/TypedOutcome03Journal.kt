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

/** Created atomically with a genuinely NEW first211 assertion. Upgraded old assertions
 * have no such classification: absence never means that their outcome was never sent. */
@Entity(tableName = "typed_outcome03_reports", indices = [Index("attemptId")])
internal data class TypedOutcome03Report(@PrimaryKey val eventId: String, val attemptId: String,
    val sourceSlot: String, val assertionSha256: String, val automaticFirst: Boolean) {
    fun requireSource(source: TypedHistory03Source) {
        source.requireShape()
        require(source.eventId == eventId && source.attemptId == attemptId && source.slot == sourceSlot &&
            source.assertionB64url != null && source.assertionSha256 == assertionSha256)
    }
}

/** Every transport invocation has a permanently retained envelope burn. Reconnection may
 * change only its outer epoch: original211, source event and assertion time never change. */
@Entity(tableName = "typed_outcome03_uploads", indices = [Index("eventId"), Index("attemptId")])
internal data class TypedOutcome03Upload(@PrimaryKey val requestId: String, val eventId: String,
    val attemptId: String, val sourceSlot: String, val submitCommandSha256: String,
    val assertionB64url: String, val assertionSha256: String, val originSha256: String,
    val originalEnrolledPoint: String, val connectionEpoch: Long, val requestB64url: String,
    val ackB64url: String? = null) {
    fun assertion() = TypedOutcome03Command.decode(TypedSubmit03Record.unbase(assertionB64url))
    fun bytes() = TypedSubmit03Record.unbase(requestB64url)
    fun requireOriginal(row: TypedSubmit03Record, source: TypedHistory03Source) {
        require(UUID.fromString(requestId).let { it != UUID(0, 0) && it.toString() == requestId })
        row.requireShape(); source.requireShape()
        require(row.attemptId == attemptId && row.commandSha256 == submitCommandSha256 &&
            row.originalOriginSha256 == originSha256 && row.originalEnrolledPoint == originalEnrolledPoint &&
            row.lastCallbackOrdinal != null && source.slot == sourceSlot && source.eventId == eventId &&
            source.attemptId == attemptId && source.commandSha256 == submitCommandSha256 &&
            source.assertionB64url == assertionB64url && source.assertionSha256 == assertionSha256)
        val command = assertion()
        require(TypedSubmit03Record.hex(command.commitment()) == assertionSha256)
        TypedOutcome03Wire.requireRequest(bytes(), row.command(), command, connectionEpoch)
        ackB64url?.let { TypedOutcome03Wire.Ack.decode(TypedSubmit03Record.unbase(it), row.command(), command, connectionEpoch) }
    }
    override fun toString() = "TypedOutcome03Upload(permanent-history-I/O-burn)"
}

/** Only this actual new writer commit mints a one-use send ticket. Cold rows remain
 * evidence, never a reconstructed ticket. This class cannot create a platform permit. */
internal class TypedOutcome03Entry internal constructor(val upload: TypedOutcome03Upload,
    val original: TypedSubmit03Record, val source: TypedHistory03Source) {
    private val unused = AtomicBoolean(true)
    fun consume(): ByteArray {
        check(unused.compareAndSet(true, false))
        upload.requireOriginal(original, source)
        return upload.bytes()
    }
}

@Dao
internal abstract class TypedOutcome03Dao {
    @Query("SELECT * FROM typed_outcome03_reports WHERE eventId = :event")
    abstract fun report(event: String): TypedOutcome03Report?
    @Query("SELECT * FROM typed_outcome03_uploads WHERE requestId = :id")
    abstract fun get(id: String): TypedOutcome03Upload?
    @Query("SELECT * FROM typed_outcome03_uploads WHERE eventId = :event ORDER BY requestId")
    abstract fun uploads(event: String): List<TypedOutcome03Upload>
    @Query("SELECT f.slot FROM typed_history03_sources f JOIN typed_submit03 s ON s.attemptId=f.attemptId WHERE s.accountId=:account AND s.deviceId=:device AND s.originalOriginSha256=:origin AND s.originalEnrolledPoint=:point AND f.assertionB64url IS NOT NULL AND f.slot>:after AND NOT EXISTS(SELECT 1 FROM typed_outcome03_uploads u WHERE u.eventId=f.eventId AND u.ackB64url IS NOT NULL) ORDER BY f.slot LIMIT 16")
    abstract fun unacknowledged(account: String, device: String, origin: String, point: String, after: String): List<String>
    @Query("SELECT DISTINCT s.attemptId FROM typed_submit03 s JOIN typed_history03_sources f ON f.attemptId=s.attemptId JOIN typed_outcome03_reports r ON r.eventId=f.eventId WHERE s.accountId=:account AND s.deviceId=:device AND s.originalOriginSha256=:origin AND s.originalEnrolledPoint=:point AND s.attemptId>:after AND r.automaticFirst=1 AND f.assertionB64url IS NOT NULL AND NOT EXISTS(SELECT 1 FROM typed_outcome03_uploads u WHERE u.eventId=f.eventId) ORDER BY s.attemptId LIMIT 16")
    abstract fun pendingAutomaticAttempts(account: String, device: String, origin: String, point: String, after: String): List<String>
    @Query("SELECT * FROM typed_submit03 WHERE attemptId = :attempt")
    protected abstract fun submit(attempt: String): TypedSubmit03Record?
    @Query("SELECT * FROM typed_history03_sources WHERE slot = :slot")
    protected abstract fun source(slot: String): TypedHistory03Source?
    @Query("SELECT * FROM typed_callback03 WHERE attemptId = :attempt")
    protected abstract fun callbacks(attempt: String): List<TypedCallback03Record>
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insert(row: TypedOutcome03Upload)
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertReport(row: TypedOutcome03Report)
    @Update(onConflict = OnConflictStrategy.ABORT) protected abstract fun update(row: TypedOutcome03Upload): Int

    /** Automatic first upload cannot retry an uncertain prior I/O. Only an explicit sync
     * decision may append a fresh envelope for the exact same original211 evidence. */
    @Transaction
    open fun enter(expected: TypedSubmit03Record, fact: TypedHistory03Source, candidate: TypedOutcome03Upload,
        explicitReplay: Boolean, current: () -> Unit): TypedOutcome03Entry? {
        candidate.requireOriginal(expected, fact); require(candidate.ackB64url == null)
        current()
        val actual = submit(expected.attemptId) ?: return null
        if (actual != expected || source(fact.slot) != fact || get(candidate.requestId) != null) return null
        fact.requireRaw(actual.command(), callbacks(actual.attemptId))
        val prior = uploads(fact.eventId)
        for (old in prior) old.requireOriginal(actual, fact)
        if (prior.any { it.ackB64url != null } || !explicitReplay && prior.isNotEmpty()) return null
        val retained = report(fact.eventId)
        retained?.requireSource(fact)
        if (!explicitReplay && retained?.automaticFirst != true) return null
        if (retained == null) insertReport(TypedOutcome03Report(fact.eventId, fact.attemptId, fact.slot,
            checkNotNull(fact.assertionSha256), automaticFirst = false))
        insert(candidate)
        current()
        return TypedOutcome03Entry(candidate, actual, fact)
    }

    /** Only exact actually returned receipt bytes may complete this captured envelope.
     * It is historical retention even if the current socket has since been withdrawn. */
    @Transaction
    open fun retainAck(expected: TypedOutcome03Upload, raw: ByteArray): Boolean {
        if (get(expected.requestId) != expected) return false
        require(expected.ackB64url == null)
        val actual = submit(expected.attemptId) ?: return false
        val fact = source(expected.sourceSlot) ?: return false
        expected.requireOriginal(actual, fact)
        fact.requireRaw(actual.command(), callbacks(actual.attemptId))
        TypedOutcome03Wire.Ack.decode(raw, actual.command(), expected.assertion(), expected.connectionEpoch)
        check(update(expected.copy(ackB64url = TypedSubmit03Record.base(raw))) == 1)
        return true
    }
}
