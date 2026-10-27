// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Canonical public03 consent proofs only. Parsing or valid signatures cannot authenticate
 * current owner/MFA, physical continuity, integration grants or an installed active interval.
 */
internal object ConversationInterval03 {
    const val DISCLOSURE_VERSION = "conversation-content03-v1"
    const val DISCLOSURE = "With your approval, ZROtext sends and receives SMS for this selected phone line and conversation, and transfers encrypted message content to your paired browser and the explicitly listed customer-controlled readers. Stop closes new sending, capture and transfer; retained encrypted content is deleted separately."

    class Integration internal constructor(val connector: UUID, val readGrant: UUID, keyId: ByteArray) {
        private val key = keyId.copyOf()
        fun keyId() = key.copyOf()
        override fun toString() = "ConversationInterval03Integration(public-selection)"
    }
    class Statement private constructor(private val owned: ByteArray, val peer: String, private val mappings: List<Integration>) {
        fun bytes() = owned.copyOf()
        fun sha256() = sha(owned)
        val account get() = id(8)
        val device get() = id(24)
        val line get() = id(40)
        val binding get() = id(56)
        val interval get() = id(72)
        val receipt get() = id(88)
        val ownerUser get() = id(104)
        val ownerSession get() = id(120)
        val opening get() = id(136)
        val bindingGeneration get() = number(152)
        val vaultGeneration get() = number(160)
        val manifestVersion get() = number(168)
        val selectionEpoch get() = number(176)
        val issuedMs get() = number(184)
        val setupExpiresMs get() = number(192)
        val intervalStartsMs get() = number(200)
        val intervalExpiresMs get() = number(208)
        val readerKeyId get() = digest(216)
        val archiveReaderKeyId get() = digest(248)
        val phoneSignerKeyId get() = digest(280)
        val browserSignerKeyId get() = digest(312)
        val rootFingerprint get() = digest(344)
        val manifestDigest get() = digest(376)
        val electionCommitment get() = digest(408)
        val electionBundleSha256 get() = digest(440)
        val ownerSessionDigest get() = digest(472)
        val originDigest get() = digest(504)
        val deviceSessionDigest get() = digest(536)
        val physicalSelectionDigest get() = digest(568)
        val nonce get() = digest(600)
        private fun id(at: Int) = ByteBuffer.wrap(owned, at, 16).let { UUID(it.long, it.long) }
        private fun number(at: Int) = ByteBuffer.wrap(owned, at, 8).long
        private fun digest(at: Int) = owned.copyOfRange(at, at + 32)
        fun integrations() = mappings.map { Integration(it.connector, it.readGrant, it.keyId()) }
        fun requireSetupCurrent(now: Long) { require(now in issuedMs until setupExpiresMs && now < intervalExpiresMs) }
        fun requireIntervalCurrent(now: Long) { require(now in intervalStartsMs until intervalExpiresMs) }
        override fun toString() = "ConversationInterval03Statement(redacted)"

        companion object {
            fun decode(input: ByteArray): Statement {
                require(input.size in 695..1092)
                val bytes = input.copyOf()
                require(bytes.copyOfRange(0, 8).contentEquals(byteArrayOf(90, 84, 67, 65, 3, 3, 3, 0)))
                fun number(at: Int) = ByteBuffer.wrap(bytes, at, 8).long
                fun id(at: Int) = ByteBuffer.wrap(bytes, at, 16).let { UUID(it.long, it.long) }
                for (at in 8 until 152 step 16) require(id(at) != UUID(0, 0))
                for (at in 152 until 216 step 8) require(number(at) > 0)
                for (at in 216 until 632 step 32) require(bytes.copyOfRange(at, at + 32).any { it != 0.toByte() })
                require(number(160) == 1L && number(200) == number(184) && number(192) > number(184) &&
                    number(192) - number(184) <= 300_000 && number(208) > number(200) &&
                    number(208) - number(200) <= 86_400_000)
                val b = ByteBuffer.wrap(bytes).apply { position(632) }
                require((b.get().toInt() and 255) == 25)
                val version = ByteArray(25).also(b::get)
                require(version.contentEquals(DISCLOSURE_VERSION.toByteArray(Charsets.US_ASCII)))
                require(ByteArray(32).also(b::get).contentEquals(sha(DISCLOSURE.toByteArray(Charsets.UTF_8))))
                val peerSize = b.get().toInt() and 255
                require(peerSize in 3..16 && b.remaining() >= peerSize + 1)
                val peer = ByteArray(peerSize).also(b::get)
                require(peer[0] == '+'.code.toByte() && peer[1] in '1'.code.toByte()..'9'.code.toByte() &&
                    peer.copyOfRange(2, peer.size).all { it in '0'.code.toByte()..'9'.code.toByte() })
                val count = b.get().toInt() and 255
                require(count <= 6 && b.remaining() == count * 64)
                val connectors = HashSet<UUID>(); val grants = HashSet<UUID>(); val keys = HashSet<String>()
                val mappings = ArrayList<Integration>(count)
                repeat(count) {
                    val connector = UUID(b.long, b.long); val grant = UUID(b.long, b.long)
                    val key = ByteArray(32).also(b::get)
                    require(connector != UUID(0, 0) && grant != UUID(0, 0) && key.any { it != 0.toByte() } &&
                        connectors.add(connector) && grants.add(grant) && keys.add(Draft02OutboundPreparation.hex(key)))
                    mappings.lastOrNull()?.let { previous -> require(compare(previous.keyId(), key) < 0) }
                    mappings.add(Integration(connector, grant, key))
                }
                require(!b.hasRemaining())
                val result = Statement(bytes, peer.toString(Charsets.US_ASCII), mappings)
                require(same(result.ownerSessionDigest, sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/owner-session/v1",
                    ReviewedIntent03.uuid(result.account) + ReviewedIntent03.uuid(result.ownerUser) + ReviewedIntent03.uuid(result.ownerSession)))))
                return result
            }
        }
    }
    fun requestTranscript(statement: Statement) = ReviewedIntent03.framed("zrotext/conversation/request03/v1", statement.bytes())
    fun approvalTranscript(statement: Statement, ownerSignature: ByteArray): ByteArray {
        requireRaw(ownerSignature)
        return ReviewedIntent03.framed("zrotext/conversation/approve03/v1", statement.bytes() + sha(ownerSignature))
    }
    fun installedTranscript(statement: Statement, ownerSignature: ByteArray, phoneSignature: ByteArray): ByteArray {
        requireRaw(ownerSignature); requireRaw(phoneSignature)
        return ReviewedIntent03.framed("zrotext/conversation/install03/v1", statement.bytes() + sha(ownerSignature) + sha(phoneSignature))
    }
    /** A commitment to independently verified original physical evidence, never a credential. */
    fun originalPhysicalDigest(account: UUID, device: UUID, line: UUID, binding: UUID, election: ByteArray,
        deviceSession: ByteArray, originalBinding: UUID, activationEvidence: ByteArray): ByteArray {
        require(originalBinding != UUID(0, 0) && activationEvidence.size in 1..2048)
        return physical(1, account, device, line, binding, election, deviceSession, ReviewedIntent03.uuid(originalBinding) + sha(activationEvidence))
    }
    fun refreshedPhysicalDigest(account: UUID, device: UUID, line: UUID, binding: UUID, election: ByteArray,
        deviceSession: ByteArray, refresh: InstalledSelectionRefresh03): ByteArray = physical(2, account, device, line, binding,
        election, deviceSession, ReviewedIntent03.uuid(refresh.bundle.core.refresh) + refresh.bundle.sha256() +
            ByteBuffer.allocate(16).putLong(checkNotNull(refresh.record.acceptedMs)).putLong(checkNotNull(refresh.record.installedMs)).array())
    private fun physical(tag: Int, account: UUID, device: UUID, line: UUID, binding: UUID, election: ByteArray,
        deviceSession: ByteArray, source: ByteArray): ByteArray {
        require(listOf(account, device, line, binding).all { it != UUID(0, 0) } && election.size == 32 && deviceSession.size == 32 &&
            election.any { it != 0.toByte() } && deviceSession.any { it != 0.toByte() })
        return sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/physical-selection/v1", byteArrayOf(tag.toByte()) +
            ReviewedIntent03.uuid(account) + ReviewedIntent03.uuid(device) + ReviewedIntent03.uuid(line) + ReviewedIntent03.uuid(binding) +
            election + deviceSession + source))
    }
    internal fun requireRaw(signature: ByteArray) {
        require(signature.size == 64)
        val r = BigInteger(1, signature.copyOfRange(0, 32)); val s = BigInteger(1, signature.copyOfRange(32, 64))
        require(r > BigInteger.ZERO && r < ORDER && s > BigInteger.ZERO && s <= ORDER.shiftRight(1))
    }
    private fun compare(a: ByteArray, b: ByteArray): Int {
        for (index in a.indices) { val difference = (a[index].toInt() and 255) - (b[index].toInt() and 255); if (difference != 0) return difference }
        return 0
    }
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
}
