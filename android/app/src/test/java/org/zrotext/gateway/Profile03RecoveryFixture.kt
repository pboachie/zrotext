// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID

/** Actual synthetic enrollment signer and original v2 fixture. Closure records are server
 * reservation candidates only; this fixture never labels one an accepted election.
 */
internal class Profile03RecoveryFixture : AutoCloseable {
    val f = Profile03ExecutionFixture()
    val first = f.record
    val second = successor(20, 21, 3, 102_000, 102_500)
    val third = successor(22, 23, 5, 103_000, 104_000) // Burned generations may have gaps.
    val now = 103_010L
    val closures = listOf(close(first, second, 30), close(second, third, 31))
    val dao get() = f.line.db.profile03Elections()
    fun successor(challenge: Long, binding: Long, generation: Long, issued: Long, expires: Long): Profile03ElectionRecord {
        val core = Profile03ElectionEncoding.decode(first.coreB64url, 500)
        ReviewedIntent03.uuid(UUID(0, challenge)).copyInto(core, 56)
        ByteBuffer.wrap(core, 96, 8).putLong(generation)
        ByteBuffer.wrap(core, 384, 8).putLong(issued)
        ByteBuffer.wrap(core, 392, 8).putLong(expires)
        // A new owner/device session and nonce are not historical original02 scope.
        core.fill(challenge.toByte(), 352, 384)
        core.fill((challenge + 1).toByte(), 432, 464)
        core.fill((challenge + 2).toByte(), 464, 496)
        return first.copy(challengeId = UUID(0, challenge).toString(), newBindingId = UUID(0, binding).toString(),
            newGeneration = generation, coreB64url = Profile03ElectionEncoding.encode(core))
    }
    fun signed(record: Profile03ElectionRecord): Profile03ElectionRecord = record.copy(state = "signed",
        deviceSignatureB64url = Profile03ElectionEncoding.encode(Profile03ExecutionFixture.rawSign(f.enrollment,
            ReviewedIntent03.framed("ZTSE/line/payload-profile/device/v1", Profile03ElectionEncoding.decode(record.coreB64url, 500)))))
    fun retainSignedFirst(retire: Boolean = false): Profile03ElectionRecord {
        check(dao.reserve(first) {})
        val signed = signed(first)
        check(dao.recordSigned(signed) {})
        if (retire) check(dao.retire(first.challengeId) == 1)
        return checkNotNull(dao.find(first.challengeId))
    }
    fun reserve() = dao.reserveWithClosures(third, closures, now) { check(it == f.binding) }
    fun mutateCore(record: Profile03ElectionRecord, block: (ByteArray) -> Unit): Profile03ElectionRecord {
        val core = Profile03ElectionEncoding.decode(record.coreB64url, 500)
        block(core)
        return record.copy(coreB64url = Profile03ElectionEncoding.encode(core))
    }
    fun wire(rows: List<Profile03UnacceptedClosureRecord> = closures): Map<String, Any> = mapOf("closed_unaccepted" to rows.map { row ->
        mapOf("opening_id" to row.openingId, "challenge_id" to row.challengeId, "new_binding_id" to row.newBindingId,
            "core" to row.coreB64url, "closed_unaccepted_ms" to row.closedUnacceptedMs.toString(),
            "superseded_by_challenge_id" to row.supersededByChallengeId)
    })
    override fun close() = f.close()
    companion object {
        fun close(prior: Profile03ElectionRecord, next: Profile03ElectionRecord, opening: Long): Profile03UnacceptedClosureRecord =
            Profile03UnacceptedClosureRecord(UUID(0, opening).toString(), prior.challengeId, prior.newBindingId, prior.coreB64url,
                ByteBuffer.wrap(Profile03ElectionEncoding.decode(next.coreB64url, 500), 384, 8).long, next.challengeId)
    }
}
