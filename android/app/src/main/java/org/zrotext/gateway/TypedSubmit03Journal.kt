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
import java.math.BigInteger
import java.util.Base64
import java.util.UUID

/** Permanent, content-free classification, independent of legacy attempt/content pruning.
 * These metadata phases NEVER construct a platform-entry or current-permission capability. */
@Entity(tableName = "typed_submit03", indices = [Index(value = ["eventId"], unique = true),
    Index(value = ["accountId", "messageId"], unique = true)])
internal data class TypedSubmit03Record(
    @PrimaryKey val attemptId: String,
    val eventId: String,
    val accountId: String,
    val deviceId: String,
    val messageId: String,
    val commandB64url: String,
    val commandSha256: String,
    val originalEnrolledPoint: String,
    val originalEnrolledKeyId: String,
    val phase: String = "reserved",
    val ackSha256: String? = null,
    val entryReservedMs: Long? = null,
    val closureB64url: String? = null,
    val closureSha256: String? = null,
    val conflict: Boolean = false
) {
    fun command(): TypedSubmit03Command = TypedSubmit03Command.decode(unbase(commandB64url)).also {
        require(it.attemptId == attemptId && it.eventId == eventId && it.accountId == accountId &&
            it.deviceId == deviceId && it.messageId == messageId && hex(it.commitment()) == commandSha256)
    }
    fun requireShape() {
        command()
        val point = unbase(originalEnrolledPoint)
        requirePoint(point)
        require(hex(keyId(point)) == originalEnrolledKeyId)
        require(phase in setOf("reserved", "ack_authorized", "platform_entry_reserved", "closed_no_submit"))
        when (phase) {
            "reserved" -> require(ackSha256 == null && entryReservedMs == null && closureB64url == null)
            "ack_authorized" -> require(ackSha256 != null && entryReservedMs == null && closureB64url == null)
            "platform_entry_reserved" -> require(ackSha256 != null && entryReservedMs != null && closureB64url == null)
            "closed_no_submit" -> require(entryReservedMs == null && closureB64url != null)
        }
        if (ackSha256 != null) require(ackSha256.matches(Regex("[0-9a-f]{64}")))
        require((entryReservedMs != null) == (phase == "platform_entry_reserved"))
        if (entryReservedMs != null) require(entryReservedMs > 0 && ackSha256 != null)
        require((closureB64url != null) == (phase == "closed_no_submit") &&
            (closureB64url == null) == (closureSha256 == null))
        closureB64url?.let { encoded -> TypedNoSubmit03Record.decode(unbase(encoded)).also {
            it.requireCommand(command()); require(hex(it.commitment()) == closureSha256)
            require(it.closedFrom == if (ackSha256 == null) 0 else 1)
        } }
    }
    override fun toString() = "TypedSubmit03Record(retained-no-effect-authority)"
    companion object {
        fun candidate(command: TypedSubmit03Command, originalEnrolledPoint: ByteArray): TypedSubmit03Record {
            val point = originalEnrolledPoint.copyOf()
            return TypedSubmit03Record(command.attemptId, command.eventId, command.accountId, command.deviceId,
                command.messageId, base(command.bytes()), hex(command.commitment()),
                base(point), hex(keyId(point))).also { it.requireShape() }
        }
        // Public arithmetic only: no KeyFactory, Keystore or framework/provider wait under Room.
        private fun requirePoint(point: ByteArray) {
            require(point.size == 65 && point[0] == 4.toByte())
            val prime = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
            val b = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
            val x = BigInteger(1, point.copyOfRange(1, 33)); val y = BigInteger(1, point.copyOfRange(33, 65))
            require(x < prime && y < prime && y.multiply(y).mod(prime) ==
                x.multiply(x).multiply(x).subtract(x.multiply(BigInteger.valueOf(3))).add(b).mod(prime))
        }
        private fun keyId(point: ByteArray) = TypedSubmit03Command.sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
        internal fun base(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        internal fun unbase(text: String): ByteArray = Base64.getUrlDecoder().decode(text).also { require(base(it) == text) }
        internal fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}

/** Every distinct actual callback observation stays immutable, including contrary evidence.
 * No FK to a droppable legacy row, message body, line or interval. */
@Entity(tableName = "typed_callback03", indices = [Index("attemptId"),
    Index(value = ["attemptId", "segmentIndex", "delivery", "resultCode", "deliveryStatus"], unique = true)])
internal data class TypedCallback03Record(
    @PrimaryKey val eventId: String,
    val attemptId: String,
    val segmentIndex: Int,
    val delivery: Boolean,
    val resultCode: Int,
    /** -1 for sent; 0..2 are the actual existing delivery-status classification. */
    val deliveryStatus: Int,
    val observedMs: Long
)

@Dao
internal abstract class TypedSubmit03Dao {
    @Query("SELECT * FROM typed_submit03 WHERE attemptId = :attempt")
    abstract fun get(attempt: String): TypedSubmit03Record?
    @Query("SELECT * FROM typed_callback03 WHERE attemptId = :attempt ORDER BY observedMs,eventId")
    abstract fun callbacks(attempt: String): List<TypedCallback03Record>
    @Query("SELECT EXISTS(SELECT 1 FROM sms_attempts WHERE attemptId = :attempt) OR EXISTS(SELECT 1 FROM alpha_radio_events WHERE attemptId = :attempt)")
    protected abstract fun hasLegacy(attempt: String): Boolean
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insert(row: TypedSubmit03Record)
    @Update(onConflict = OnConflictStrategy.ABORT) protected abstract fun update(row: TypedSubmit03Record): Int
    @Insert(onConflict = OnConflictStrategy.ABORT) protected abstract fun insertCallback(row: TypedCallback03Record)

    /** Negative classification/retention only. The future verifier must independently check
     * the genuine grant, actor and V2/current/physical state BEFORE requesting any effect. */
    @Transaction
    open fun reserve(candidate: TypedSubmit03Record, current: () -> Unit): TypedSubmit03Record {
        candidate.requireShape()
        require(candidate.phase == "reserved" && !candidate.conflict)
        current()
        val existing = get(candidate.attemptId)
        if (existing != null) {
            require(existing.copy(phase = "reserved", ackSha256 = null, entryReservedMs = null,
                closureB64url = null, closureSha256 = null, conflict = false) == candidate)
            return existing.also { it.requireShape(); current() }
        }
        check(!hasLegacy(candidate.attemptId)) { "Existing legacy history cannot become a typed attempt" }
        insert(candidate); current()
        return checkNotNull(get(candidate.attemptId))
    }

    /** Component-only journal phase, not an ACK verifier or a radio capability. No shipping
     * caller invokes this until the distinct submit-specific permission consumer is mounted. */
    @Transaction
    open fun retainFirstAck(expected: TypedSubmit03Record, exactAck: ByteArray, current: () -> Unit): Boolean {
        expected.requireShape(); require(exactAck.isNotEmpty() && exactAck.size <= 192 * 1024)
        current()
        if (get(expected.attemptId) != expected || expected.phase != "reserved" || expected.conflict ||
            callbacks(expected.attemptId).isNotEmpty()) return false
        check(update(expected.copy(phase = "ack_authorized", ackSha256 = TypedSubmit03Record.hex(
            TypedSubmit03Command.sha(exactAck)))) == 1)
        current(); return true
    }

    /** Marker and negative closure compete in the SAME writer. The returned Boolean itself
     * must never be consumed as an invocation permit; a future RAM one-use verifier owns that. */
    @Transaction
    open fun retainPlatformEntry(expected: TypedSubmit03Record, observedMs: Long, current: () -> Unit): Boolean {
        expected.requireShape(); require(observedMs > 0); current()
        if (get(expected.attemptId) != expected || expected.phase != "ack_authorized" || expected.conflict ||
            callbacks(expected.attemptId).isNotEmpty()) return false
        check(update(expected.copy(phase = "platform_entry_reserved", entryReservedMs = observedMs)) == 1)
        current(); return true
    }

    /** The caller synchronously withdraws its actual RAM capability BEFORE entering Room.
     * No health/current-owner requirement is imposed on this permanent negative record. */
    @Transaction
    open fun closeBeforeEntry(expected: TypedSubmit03Record, closureId: String, closedMs: Long): TypedSubmit03Record? {
        expected.requireShape()
        if (get(expected.attemptId) != expected || expected.phase !in setOf("reserved", "ack_authorized") ||
            expected.conflict || callbacks(expected.attemptId).isNotEmpty()) return null
        val closure = TypedNoSubmit03Record.create(expected.command(), closureId,
            if (expected.phase == "reserved") 0 else 1, closedMs)
        val next = expected.copy(phase = "closed_no_submit", closureB64url = TypedSubmit03Record.base(closure.bytes()),
            closureSha256 = TypedSubmit03Record.hex(closure.commitment()))
        next.requireShape(); check(update(next) == 1); return next
    }

    /** Cold callback routing is independent of effect/protection health and never emits an
     * AlphaRadioEvent. Invalid/contrary observations cannot reopen a phase or prove no-entry. */
    @Transaction
    open fun recordCallback(attempt: String, index: Int, delivery: Boolean, result: Int,
        status: Int?, observedMs: Long): Boolean {
        val retained = get(attempt) ?: return false
        retained.requireShape()
        if (index !in 0 until retained.command().segmentCount || observedMs <= 0) return true
        val actualStatus = if (delivery) status ?: DeliveryStatus.UNVERIFIED else -1
        require(actualStatus in if (delivery) 0..2 else -1..-1)
        val old = callbacks(attempt)
        if (old.any { it.segmentIndex == index && it.delivery == delivery &&
                it.resultCode == result && it.deliveryStatus == actualStatus }) return true
        insertCallback(TypedCallback03Record(UUID.randomUUID().toString(), attempt, index, delivery, result, actualStatus, observedMs))
        val contrary = retained.phase != "platform_entry_reserved" || old.any {
            it.segmentIndex == index && it.delivery == delivery &&
                (if (delivery) CallbackEvidence.delivery(it.deliveryStatus, actualStatus)
                    else CallbackEvidence.sent(it.resultCode, result)) == CallbackEvidence.Decision.CONFLICT }
        if (contrary && !retained.conflict) check(update(retained.copy(conflict = true)) == 1)
        return true
    }
}
