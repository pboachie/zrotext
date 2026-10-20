// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Explicit ZTRI02/03/03 decoding, with NO plaintext commitment. Historical V1 remains separate.
 * Public bytes/signatures grant no permission and acquire no key. */
internal class ReviewedIntent03V2 private constructor(
    private val exact: ByteArray, private val ids: List<UUID>, private val numbers: List<Long>,
    private val digests: List<ByteArray>, private val peerValue: ByteArray,
    private val recipients: List<Draft03ManifestAuthority.Reader>, val segmentCeiling: Int,
) {
    val accountId get() = ids[0]
    val deviceId get() = ids[1]
    val lineId get() = ids[2]
    val bindingId get() = ids[3]
    val ownerUserId get() = ids[4]
    val ownerSessionId get() = ids[5]
    val intervalId get() = ids[6]
    val messageId get() = ids[7]
    val bindingGeneration get() = numbers[0]
    val trustGeneration get() = numbers[1]
    val manifestVersion get() = numbers[2]
    val selectionEpoch get() = numbers[3]
    val observedMs get() = numbers[4]
    val expiresMs get() = numbers[5]
    val reviewIssuedMs get() = numbers[6]
    val reviewExpiresMs get() = numbers[7]
    val readerKeyId get() = digests[0].copyOf()
    val rootFingerprint get() = digests[1].copyOf()
    val manifestDigest get() = digests[2].copyOf()
    val electionDigest get() = digests[3].copyOf()
    val electionBundleSha256 get() = digests[4].copyOf()
    val originDigest get() = digests[6].copyOf()
    val signerKeyId get() = digests[7].copyOf()
    val envelopeSha256 get() = digests[8].copyOf()
    val unsignedSha256 get() = digests[9].copyOf()
    fun bytes() = exact.copyOf()
    fun transcript() = framed("zrotext/conversation/reviewed-send03/v2", exact)
    fun peer() = peerValue.copyOf()
    fun request() = Draft03ManifestAuthority.Request(uuid(accountId), uuid(messageId), uuid(deviceId),
        uuid(lineId), peerValue, signerKeyId, recipients)
    override fun toString() = "ReviewedIntent03V2(public-evidence-only)"

    /** The immutable acceptance time comes from the authenticated admission receipt. It is NOT
     * present time, and does not renew review permission when a message is delivered later.
     * The caller independently establishes live selection/session/interval authority.
     */
    fun verifyReceipt(signature: ByteArray, authority: Draft03ManifestAuthority,
        current: Draft03PayloadElectionProof.CurrentComparison03,
        acceptedMs: Long, nowMs: Long, expectedSelectionEpoch: Long, expectedOriginDigest: ByteArray,
        intervalStartsMs: Long, intervalExpiresMs: Long): Draft03ManifestAuthority.Request {
        require(signature.size == 64 && acceptedMs > 0 && nowMs >= acceptedMs &&
            observedMs <= reviewIssuedMs && reviewIssuedMs <= acceptedMs && acceptedMs < reviewExpiresMs &&
            reviewExpiresMs <= expiresMs && reviewExpiresMs - reviewIssuedMs in 1..30_000 &&
            expiresMs - observedMs in 1..900_000 && nowMs < expiresMs &&
            intervalStartsMs > 0 && observedMs >= intervalStartsMs && nowMs >= intervalStartsMs &&
            nowMs < intervalExpiresMs && expiresMs <= intervalExpiresMs && selectionEpoch == expectedSelectionEpoch)
        val c = current.authority
        require(same(uuid(accountId), c.accountId) && same(uuid(deviceId), c.deviceId) &&
            same(uuid(lineId), c.lineId) && same(uuid(bindingId), c.bindingId) &&
            bindingGeneration == c.bindingGeneration && trustGeneration == c.vaultGeneration &&
            manifestVersion == c.manifestVersion && same(readerKeyId, c.selectedReaderKeyId) &&
            same(rootFingerprint, c.rootFingerprint) && same(manifestDigest, c.manifestDigest) &&
            same(electionDigest, c.electionCommitment) && same(electionBundleSha256, c.electionBundleSha256) &&
            same(originDigest, expectedOriginDigest) && nowMs < c.permissionExpiresAtMs)
        val owner = uuid(accountId) + uuid(ownerUserId) + uuid(ownerSessionId)
        require(same(digests[5], sha(framed("ZTSE/line/payload-profile/owner-session/v1", owner))))
        val selected = request()
        val context = authority.reviewedContext(selected, observedMs, nowMs, expiresMs)
        require(ConversationContentCrypto.verifyRaw(signature, context.signerPoint,
            transcript())) { "Reviewed intent signature" }
        return selected
    }

    fun requireGrant(grant: SealedDispatch03Frames.Grant) {
        require(grant.accountId == accountId && grant.deviceId == deviceId && grant.lineId == lineId &&
            grant.messageId == messageId && grant.bindingGeneration == bindingGeneration &&
            grant.trustGeneration == trustGeneration && grant.manifestVersion == manifestVersion &&
            grant.segmentCount == segmentCeiling && grant.expiresAtMs <= expiresMs &&
            same(grant.readerKeyId, readerKeyId) && same(grant.rootFingerprint, rootFingerprint) &&
            same(grant.manifestDigest, manifestDigest) && same(grant.electionDigest, electionDigest) &&
            same(grant.envelopeSha256, envelopeSha256) && same(grant.unsignedSha256, unsignedSha256))
    }

    companion object {
        fun decode(input: ByteArray): ReviewedIntent03V2 {
            require(input.size in 592..803)
            val bytes = input.copyOf()
            val b = ByteBuffer.wrap(bytes)
            require(ByteArray(8).also(b::get).contentEquals(byteArrayOf(90, 84, 82, 73, 2, 3, 3, 0)))
            val ids = List(8) { UUID(b.long, b.long).also { require(it != UUID(0, 0)) } }
            val numbers = List(8) { b.long.also { require(it > 0) } }
            require(numbers[1] == 1L && numbers[3] == 1L &&
                numbers[4] <= numbers[6] && numbers[6] < numbers[7] && numbers[7] <= numbers[5] &&
                numbers[7] - numbers[6] <= 30_000 && numbers[5] - numbers[4] <= 900_000)
            val digests = List(10) { ByteArray(32).also(b::get).also { require(it.any { value -> value != 0.toByte() }) } }
            val peerLength = b.get().toInt() and 255
            require(peerLength in 3..16 && b.remaining() >= peerLength + 1)
            val peer = ByteArray(peerLength).also(b::get)
            require(peer[0] == 43.toByte() && peer[1] in 49.toByte()..57.toByte() &&
                peer.copyOfRange(2, peer.size).all { it in 48.toByte()..57.toByte() })
            val count = b.get().toInt() and 255
            require(count in 2..8 && b.remaining() == count * 33 + 1 && bytes.size == 523 + peerLength + count * 33)
            val readers = List(count) {
                val role = b.get().toInt() and 255
                require(role in 1..3)
                Draft03ManifestAuthority.Reader(role, ByteArray(32).also(b::get).also { id ->
                    require(id.any { it != 0.toByte() })
                })
            }
            require(readers.count { it.role == 1 } == 1 && readers.count { it.role == 2 } == 1 &&
                readers.first().role == 1 && same(readers.first().keyId, digests[0]))
            readers.zipWithNext().forEach { (a, next) ->
                require(next.role > a.role || next.role == a.role && compare(a.keyId, next.keyId) < 0)
            }
            val ceiling = b.get().toInt() and 255
            require(ceiling in 1..6 && !b.hasRemaining())
            return ReviewedIntent03V2(bytes, ids, numbers, digests, peer, readers, ceiling)
        }
        internal fun framed(label: String, bytes: ByteArray): ByteArray = label.toByteArray(Charsets.US_ASCII) +
            byteArrayOf(0) + ByteBuffer.allocate(4).putInt(bytes.size).array() + bytes
        internal fun uuid(value: UUID): ByteArray = ByteBuffer.allocate(16)
            .putLong(value.mostSignificantBits).putLong(value.leastSignificantBits).array()
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun compare(a: ByteArray, b: ByteArray): Int {
            for (at in a.indices) {
                val difference = (a[at].toInt() and 255) - (b[at].toInt() and 255)
                if (difference != 0) return difference
            }
            return 0
        }
    }
}
