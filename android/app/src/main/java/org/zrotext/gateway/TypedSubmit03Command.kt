// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Immutable public command identity. Parsing/retention conveys no current permission,
 * writer acknowledgement, platform-entry capability or proof of a radio action. */
internal class TypedSubmit03Command private constructor(private val exact: ByteArray) {
    val accountId get() = id(0)
    val deviceId get() = id(16)
    val eventId get() = id(32)
    val messageId get() = id(48)
    val attemptId get() = id(64)
    val fetchSha256 get() = exact.copyOfRange(80, 112)
    val originalSessionSha256 get() = exact.copyOfRange(112, 144)
    val segmentCount get() = exact[144].toInt() and 255
    val observedMs get() = ByteBuffer.wrap(exact, 145, 8).long
    fun bytes() = exact.copyOf()
    fun commitment() = sha(ReviewedIntent03.framed("ZTSE/conversation/submit-command03/v1", exact))
    private fun id(at: Int) = ByteBuffer.wrap(exact, at, 16).let { UUID(it.long, it.long) }.toString()
    override fun toString() = "TypedSubmit03Command(public-retained-identity)"

    companion object {
        fun decode(input: ByteArray): TypedSubmit03Command {
            require(input.size == 153)
            val owned = input.copyOf()
            for (at in 0 until 80 step 16) require(owned.copyOfRange(at, at + 16).any { it != 0.toByte() })
            for (at in listOf(80, 112)) require(owned.copyOfRange(at, at + 32).any { it != 0.toByte() })
            require((owned[144].toInt() and 255) in 1..6 && ByteBuffer.wrap(owned, 145, 8).long > 0)
            return TypedSubmit03Command(owned)
        }
        fun create(account: String, device: String, event: String, message: String, attempt: String,
            fetch: ByteArray, originalSession: ByteArray, segments: Int, observedMs: Long): TypedSubmit03Command {
            require(fetch.size == 32 && originalSession.size == 32 && segments in 1..6 && observedMs > 0)
            val out = ByteBuffer.allocate(153)
            for (value in listOf(account, device, event, message, attempt)) {
                val id = UUID.fromString(value)
                require(id.toString() == value && id != UUID(0, 0))
                out.putLong(id.mostSignificantBits).putLong(id.leastSignificantBits)
            }
            out.put(fetch).put(originalSession).put(segments.toByte()).putLong(observedMs)
            return decode(out.array())
        }
        internal fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    }
}

/** An already-durable negative assertion. It cannot infer non-entry from missing callbacks,
 * timeout or status. The caller must first win the journal's pre-entry closure transaction. */
internal class TypedNoSubmit03Record private constructor(private val exact: ByteArray) {
    val closureId get() = ByteBuffer.wrap(exact, 80, 16).let { UUID(it.long, it.long) }.toString()
    val closedFrom get() = exact[201].toInt() and 255
    val closedMs get() = ByteBuffer.wrap(exact, 202, 8).long
    fun bytes() = exact.copyOf()
    fun commitment() = TypedSubmit03Command.sha(ReviewedIntent03.framed("ZTSE/conversation/no-submit-record03/v1", exact))
    fun requireCommand(command: TypedSubmit03Command) {
        val commandBytes = command.bytes()
        require(MessageDigest.isEqual(exact.copyOfRange(0, 80), commandBytes.copyOfRange(0, 80)) &&
            MessageDigest.isEqual(exact.copyOfRange(96, 128), command.fetchSha256) &&
            MessageDigest.isEqual(exact.copyOfRange(128, 160), command.commitment()) &&
            MessageDigest.isEqual(exact.copyOfRange(160, 192), command.originalSessionSha256) &&
            (exact[192].toInt() and 255) == command.segmentCount &&
            ByteBuffer.wrap(exact, 193, 8).long == command.observedMs)
    }
    override fun toString() = "TypedNoSubmit03Record(public-negative-assertion)"
    companion object {
        fun decode(input: ByteArray): TypedNoSubmit03Record {
            require(input.size == 210)
            val owned = input.copyOf()
            for (at in 0 until 96 step 16) require(owned.copyOfRange(at, at + 16).any { it != 0.toByte() })
            for (at in listOf(96, 128, 160)) require(owned.copyOfRange(at, at + 32).any { it != 0.toByte() })
            require((owned[192].toInt() and 255) in 1..6 && ByteBuffer.wrap(owned, 193, 8).long > 0 &&
                (owned[201].toInt() and 255) in 0..1 && ByteBuffer.wrap(owned, 202, 8).long > 0)
            return TypedNoSubmit03Record(owned)
        }
        fun create(command: TypedSubmit03Command, closureId: String, closedFrom: Int, closedMs: Long): TypedNoSubmit03Record {
            val id = UUID.fromString(closureId)
            require(id != UUID(0, 0) && id.toString() == closureId && closedFrom in 0..1 && closedMs > 0)
            val out = ByteBuffer.allocate(210).put(command.bytes(), 0, 80)
                .putLong(id.mostSignificantBits).putLong(id.leastSignificantBits)
                .put(command.fetchSha256).put(command.commitment()).put(command.originalSessionSha256)
                .put(command.segmentCount.toByte()).putLong(command.observedMs).put(closedFrom.toByte()).putLong(closedMs)
            return decode(out.array()).also { it.requireCommand(command) }
        }
    }
}
