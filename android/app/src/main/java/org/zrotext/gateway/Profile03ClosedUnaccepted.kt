// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Entity
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Permanent authenticated server reservation/closure provenance, never a local signature or
 * accepted election. Unknown intermediates do not create a profile03_elections row.
 */
@Entity(tableName = "profile03_unaccepted_closures", primaryKeys = ["challengeId"])
data class Profile03UnacceptedClosureRecord(val openingId: String, val challengeId: String,
    val newBindingId: String, val coreB64url: String, val closedUnacceptedMs: Long,
    val supersededByChallengeId: String) {
    internal fun requireShape() {
        listOf(openingId, challengeId, newBindingId, supersededByChallengeId).forEach { Profile03ClosedUnaccepted.uuid(it) }
        val core = Profile03ClosedUnaccepted.Core.decode(Profile03ElectionEncoding.decode(coreB64url, 500))
        require(core.challenge == challengeId && core.challenge != core.oldBinding && core.oldBinding != newBindingId && challengeId != newBindingId &&
            challengeId != supersededByChallengeId && closedUnacceptedMs >= core.expires)
    }
    override fun toString() = "Profile03UnacceptedClosureRecord(server-history-only)"
}

/** Structural candidates from the ACTUAL authenticated challenge listener only. Authentication,
 * original02 epoch0, independent local root/keys/SIM and Room writer fences remain mandatory.
 */
internal object Profile03ClosedUnaccepted {
    class Core private constructor(private val bytes: ByteArray) {
        val challenge get() = id(56)
        val oldBinding get() = id(72)
        val newGeneration get() = number(96)
        val issued get() = number(384)
        val expires get() = number(392)
        private fun id(at: Int) = ByteBuffer.wrap(bytes, at, 16).let { UUID(it.long, it.long).toString() }
        private fun number(at: Int) = ByteBuffer.wrap(bytes, at, 8).long
        fun sameOriginalScope(other: Core): Boolean = listOf(0 to 56, 72 to 96, 104 to 224, 256 to 352, 400 to 432).all { (start, end) ->
            MessageDigest.isEqual(bytes.copyOfRange(start, end), other.bytes.copyOfRange(start, end))
        }
        companion object {
            fun decode(input: ByteArray): Core {
                require(input.size == 500)
                val b = input.copyOf()
                fun number(at: Int) = ByteBuffer.wrap(b, at, 8).long
                require(b.copyOfRange(0, 8).contentEquals(byteArrayOf(90, 84, 80, 69, 3, 1, 2, 3)) &&
                    b.copyOfRange(496, 500).all { it == 0.toByte() })
                for (at in listOf(8, 24, 40, 56, 72)) require(b.copyOfRange(at, at + 16).any { it != 0.toByte() })
                for (at in listOf(104, 136, 184, 224, 256, 288, 320, 352, 400, 432, 464))
                    require(b.copyOfRange(at, at + 32).any { it != 0.toByte() })
                for (at in listOf(88, 96, 168, 176, 216, 384, 392)) require(number(at) > 0)
                require(number(168) == 1L && number(96) > number(88) && number(176) < Long.MAX_VALUE &&
                    number(216) == number(176) + 1 && number(392) > number(384) && number(392) - number(384) <= 300_000)
                return Core(b)
            }
        }
    }
    fun decode(fields: Map<String, Any>): List<Profile03UnacceptedClosureRecord> = Profile03Json.closedUnaccepted(fields).map { f ->
        require(f.keys == setOf("opening_id", "challenge_id", "new_binding_id", "core", "closed_unaccepted_ms", "superseded_by_challenge_id"))
        Profile03UnacceptedClosureRecord(uuid(Profile03Json.text(f, "opening_id")), uuid(Profile03Json.text(f, "challenge_id")),
            uuid(Profile03Json.text(f, "new_binding_id")), Profile03ElectionEncoding.encode(Profile03Json.binary(f, "core", 500, 500)),
            Profile03Json.decimal(f, "closed_unaccepted_ms"), uuid(Profile03Json.text(f, "superseded_by_challenge_id")))
            .also(Profile03UnacceptedClosureRecord::requireShape)
    }
    fun requireChain(target: Profile03ElectionRecord, closures: List<Profile03UnacceptedClosureRecord>, now: Long) {
        target.requireShape(); require(closures.size <= 16)
        val next = Core.decode(Profile03ElectionEncoding.decode(target.coreB64url, 500))
        require(now in next.issued until next.expires)
        require(closures.map { it.challengeId }.distinct().size == closures.size &&
            closures.map { it.openingId }.distinct().size == closures.size && closures.map { it.newBindingId }.distinct().size == closures.size &&
            closures.none { it.challengeId == target.challengeId || it.newBindingId == target.newBindingId })
        closures.forEachIndexed { index, row ->
            row.requireShape()
            val old = Core.decode(Profile03ElectionEncoding.decode(row.coreB64url, 500))
            val successor = closures.getOrNull(index + 1)
            val newer = successor?.let { Core.decode(Profile03ElectionEncoding.decode(it.coreB64url, 500)) } ?: next
            require(old.sameOriginalScope(next) && old.newGeneration < newer.newGeneration &&
                row.supersededByChallengeId == (successor?.challengeId ?: target.challengeId) &&
                row.closedUnacceptedMs == newer.issued && old.expires <= row.closedUnacceptedMs && row.closedUnacceptedMs <= now)
        }
    }
    internal fun uuid(value: String): String = UUID.fromString(value).let {
        require(it != UUID(0, 0) && it.toString() == value); value
    }
}
