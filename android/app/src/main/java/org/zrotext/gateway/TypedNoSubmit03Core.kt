// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Public fixed441 grammar only. A decoded core is neither a live clock nor permission
 * to sign. The private live context and same-writer reservation are independent. */
internal class TypedNoSubmit03Core private constructor(private val exact: ByteArray) {
    fun id(index: Int): String { require(index in 0..7); return ByteBuffer.wrap(exact, 8 + index * 16, 16).let { UUID(it.long, it.long) }.toString() }
    fun number(index: Int): Long { require(index in 0..9); return ByteBuffer.wrap(exact, 136 + index * 8, 8).long }
    fun digest(index: Int): ByteArray { require(index in 0..6); return exact.copyOfRange(216 + index * 32, 248 + index * 32) }
    val proofRequestId get() = id(6)
    val challengeId get() = id(7)
    val issuedMs get() = number(8)
    val expiresMs get() = number(9)
    val closedFrom get() = exact[440].toInt() and 255
    fun bytes() = exact.copyOf()
    fun sha256() = TypedSubmit03Command.sha(exact)
    fun transcript() = ReviewedIntent03.framed("ZTSE/conversation/no-submit-proof03/v1", exact)
    fun requireOriginal(row: TypedSubmit03Record, nonce: ByteArray) {
        row.requireShape(); require(row.phase == "closed_no_submit")
        val command = row.command()
        val closed = TypedNoSubmit03Record.decode(TypedSubmit03Record.unbase(checkNotNull(row.closureB64url)))
        closed.requireCommand(command)
        require((0..5).map(::id) == listOf(row.accountId, row.deviceId, row.eventId, row.messageId, row.attemptId, closed.closureId) &&
            number(5) == command.segmentCount.toLong() && number(6) == command.observedMs && number(7) == closed.closedMs &&
            closedFrom == closed.closedFrom && same(digest(0), command.fetchSha256) && same(digest(1), command.commitment()) &&
            same(digest(2), command.originalSessionSha256) && TypedSubmit03Record.hex(digest(4)) == row.originalEnrolledKeyId &&
            nonce.size == 32 && same(digest(5), TypedSubmit03Command.sha(nonce)) && same(digest(6), closed.commitment()))
    }
    override fun toString() = "TypedNoSubmit03Core(public-fixed-closure-proof)"
    companion object {
        fun decode(raw: ByteArray): TypedNoSubmit03Core {
            require(raw.size == 441)
            val owned = raw.copyOf()
            require(owned.copyOfRange(0, 8).contentEquals(byteArrayOf(0x5a, 0x54, 0x4e, 0x53, 1, 3, 3, 0)))
            val core = TypedNoSubmit03Core(owned)
            for (index in 0..7) require(UUID.fromString(core.id(index)) != UUID(0, 0))
            for (index in 0..9) require(core.number(index) > 0)
            for (index in 0..6) require(core.digest(index).any { it != 0.toByte() })
            require(core.number(4) == 1L && core.number(5) in 1..6 && core.number(7) >= core.number(6) &&
                core.issuedMs < core.expiresMs && core.expiresMs - core.issuedMs <= 30_000 && core.closedFrom in 0..1)
            return core
        }
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    }
}
