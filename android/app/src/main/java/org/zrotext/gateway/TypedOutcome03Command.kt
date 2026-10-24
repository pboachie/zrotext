// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Exact public assertion, not an OS observation or an effect capability. The raw source
 * fact and its original identity must exist before acquiring the first assertion clock. */
internal class TypedOutcome03Command private constructor(private val exact: ByteArray) {
    val eventId get() = id(32)
    val messageId get() = id(48)
    val attemptId get() = id(64)
    val evidence get() = exact[201].toInt() and 255
    val assertionMs get() = ByteBuffer.wrap(exact, 202, 8).long
    val segmentIndex get() = (exact[210].toInt() and 255).takeUnless { it == 255 }
    fun bytes() = exact.copyOf()
    fun commitment() = TypedSubmit03Command.sha(ReviewedIntent03.framed(
        "ZTSE/conversation/outcome-command03/v1", exact))
    private fun id(at: Int) = ByteBuffer.wrap(exact, at, 16).let { UUID(it.long, it.long) }.toString()
    fun requireCommand(command: TypedSubmit03Command) {
        val original = command.bytes()
        require(MessageDigest.isEqual(exact.copyOfRange(0, 32), original.copyOfRange(0, 32)) &&
            MessageDigest.isEqual(exact.copyOfRange(48, 80), original.copyOfRange(48, 80)) &&
            MessageDigest.isEqual(exact.copyOfRange(80, 96), original.copyOfRange(32, 48)) &&
            MessageDigest.isEqual(exact.copyOfRange(96, 128), command.commitment()) &&
            MessageDigest.isEqual(exact.copyOfRange(128, 160), command.fetchSha256) &&
            MessageDigest.isEqual(exact.copyOfRange(160, 192), command.originalSessionSha256) &&
            ByteBuffer.wrap(exact, 192, 8).long == command.observedMs &&
            (exact[200].toInt() and 255) == command.segmentCount)
    }
    override fun toString() = "TypedOutcome03Command(retained-public-assertion)"

    companion object {
        val EVIDENCE = listOf("sent_callback_ok", "sent_callback_failed", "delivery_callback_ok",
            "delivery_timeout", "crash_without_callback", "callback_conflict")
        fun decode(input: ByteArray): TypedOutcome03Command {
            require(input.size == 211)
            val owned = input.copyOf()
            for (at in 0 until 96 step 16) require(owned.copyOfRange(at, at + 16).any { it != 0.toByte() })
            for (at in listOf(96, 128, 160)) require(owned.copyOfRange(at, at + 32).any { it != 0.toByte() })
            val count = owned[200].toInt() and 255
            val evidence = owned[201].toInt() and 255
            val index = owned[210].toInt() and 255
            val submit = ByteBuffer.wrap(owned, 192, 8).long
            require(count in 1..6 && evidence in 0..5 && submit > 0 &&
                ByteBuffer.wrap(owned, 202, 8).long >= submit &&
                if (evidence <= 1) index in 0 until count else index == 255)
            return TypedOutcome03Command(owned)
        }
        fun create(command: TypedSubmit03Command, eventId: String, evidence: Int,
            segmentIndex: Int?, assertionMs: Long): TypedOutcome03Command {
            val id = UUID.fromString(eventId)
            require(id != UUID(0, 0) && id.toString() == eventId && evidence in 0..5 &&
                assertionMs >= command.observedMs &&
                if (evidence <= 1) segmentIndex != null && segmentIndex in 0 until command.segmentCount
                else segmentIndex == null)
            val original = command.bytes()
            val out = ByteBuffer.allocate(211).put(original, 0, 32)
                .putLong(id.mostSignificantBits).putLong(id.leastSignificantBits)
                .put(original, 48, 32).put(original, 32, 16).put(command.commitment())
                .put(command.fetchSha256).put(command.originalSessionSha256).putLong(command.observedMs)
                .put(command.segmentCount.toByte()).put(evidence.toByte()).putLong(assertionMs)
                .put((segmentIndex ?: 255).toByte())
            return decode(out.array()).also { it.requireCommand(command) }
        }
    }
}
