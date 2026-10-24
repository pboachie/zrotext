// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest

/** Existing exact03/type2 grammar. Public proof is not installed interval/capture permission,
 * a durable sequence reservation, the future signed capture commitment, or upload authority. */
internal object Draft03InboundEnvelope {
    private class Wrap(val role: Int, val id: ByteArray)
    private class Parsed(val bytes: ByteArray, val protected: ByteArray, val observed: Long,
        val sequence: Long, val wraps: List<Wrap>)
    class Unsigned private constructor(private val parsed: Parsed,
        private val authority: Draft03ManifestAuthority, private val context: Draft03ManifestAuthority.InboundContext) {
        fun bytes() = parsed.bytes.copyOf()
        fun sha256() = MessageDigest.getInstance("SHA-256").digest(parsed.bytes)
        fun signerPoint() = context.signerPoint()
        fun transcript() = ReviewedIntent03.framed("ZTSE/sign/v3", parsed.bytes)
        fun requirePublicCurrent(now: Long) {
            require(now >= context.comparedMs)
            match(parsed, authority.inboundContext(context.request, context.observedMs, now, context.notAfterMs))
        }
        fun signed(signature: ByteArray): ByteArray {
            val raw = signature.copyOf()
            require(ConversationContentCrypto.verifyRaw(raw, context.signerPoint(), transcript()))
            return parsed.bytes + raw
        }
        override fun toString() = "Profile03UnsignedInbound(public-proof-only)"
        companion object {
            internal fun verified(bytes: ByteArray, authority: Draft03ManifestAuthority,
                request: Draft03ManifestAuthority.InboundRequest, observed: Long, sequence: Long,
                now: Long, deadline: Long): Unsigned {
                val parsed = parse(bytes)
                require(sequence > 0 && parsed.sequence == sequence && parsed.observed == observed)
                val context = authority.inboundContext(request, observed, now, deadline)
                match(parsed, context)
                return Unsigned(parsed, authority, context)
            }
        }
    }
    /** Select expected routing/observation/sequence independently of received ciphertext. */
    fun unsigned(bytes: ByteArray, authority: Draft03ManifestAuthority,
        request: Draft03ManifestAuthority.InboundRequest, observed: Long, sequence: Long,
        now: Long, deadline: Long) = Unsigned.verified(bytes, authority, request, observed, sequence, now, deadline)

    fun verify(bytes: ByteArray, authority: Draft03ManifestAuthority,
        request: Draft03ManifestAuthority.InboundRequest, observed: Long, sequence: Long,
        now: Long, deadline: Long): Unsigned {
        require(bytes.size in 426..34_082)
        val proof = unsigned(bytes.copyOfRange(0, bytes.size - 64), authority, request, observed, sequence, now, deadline)
        require(proof.signed(bytes.copyOfRange(bytes.size - 64, bytes.size)).contentEquals(bytes))
        return proof
    }
    private fun parse(input: ByteArray): Parsed {
        require(input.size in 362..34_018)
        val bytes = input.copyOf()
        require(bytes.copyOfRange(0, 8).contentEquals(byteArrayOf(90, 84, 83, 69, 3, 2, 0, 0)))
        val length = ByteBuffer.wrap(bytes, 8, 2).short.toInt() and 65535
        require(length in 172..185)
        val end = 10 + length; val p = bytes.copyOfRange(10, end)
        val peerLength = p[168].toInt() and 255
        require(peerLength in 3..16 && length == 169 + peerLength && p[169] == 43.toByte() &&
            p[170] in 49.toByte()..57.toByte() && p.copyOfRange(171, p.size).all { it in 48.toByte()..57.toByte() })
        require((0..3).all { n -> p.copyOfRange(n * 16, n * 16 + 16).any { it != 0.toByte() } } &&
            p.copyOfRange(16, 32).contentEquals(p.copyOfRange(144, 160)) && number(p, 64) > 0)
        val observed = number(p, 136); val sequence = number(p, 160)
        require(observed > 0 && sequence > 0)
        val bodyLength = ByteBuffer.wrap(bytes, end + 12, 4).int.toLong() and 0xffff_ffffL
        require(bodyLength in 17..32_784)
        val bodyEnd = end + 16 + bodyLength.toInt()
        require(bodyEnd < bytes.size)
        val count = bytes[bodyEnd].toInt() and 255
        require(count in 1..7 && bodyEnd + 1 + count * 146 == bytes.size)
        val wraps = ArrayList<Wrap>(count)
        for (index in 0 until count) {
            val at = bodyEnd + 1 + index * 146; val role = bytes[at].toInt() and 255
            val id = bytes.copyOfRange(at + 1, at + 33)
            require(role in 2..3 && id.any { it != 0.toByte() })
            wraps.lastOrNull()?.let { require(role > it.role || role == it.role && compare(id, it.id) > 0) }
            DevicePayloadKeyStore.decodePoint(bytes.copyOfRange(at + 33, at + 98))
            wraps.add(Wrap(role, id))
        }
        require(wraps.count { it.role == 2 } == 1)
        return Parsed(bytes, p, observed, sequence, wraps)
    }
    private fun match(parsed: Parsed, context: Draft03ManifestAuthority.InboundContext) {
        val p = parsed.protected; val r = context.request
        require(same(p.copyOfRange(0, 16), r.account()) && same(p.copyOfRange(16, 32), r.event()) &&
            same(p.copyOfRange(32, 48), r.device()) && same(p.copyOfRange(48, 64), r.line()) &&
            number(p, 64) == context.version && same(p.copyOfRange(72, 104), context.digest()) &&
            same(p.copyOfRange(104, 136), r.signer()) && same(p.copyOfRange(169, p.size), r.peer()))
        val readers = r.readers()
        require(readers.size == parsed.wraps.size && readers.zip(parsed.wraps).all { (a, b) -> a.role == b.role && same(a.keyId, b.id) })
    }
    private fun compare(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) { val d = (a[i].toInt() and 255) - (b[i].toInt() and 255); if (d != 0) return d }; return 0
    }
    private fun number(b: ByteArray, at: Int) = ByteBuffer.wrap(b, at, 8).long.also { require(it >= 0) }
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
}
