// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.Signature

/**
 * Dormant exact-byte outbound proof, not a durable admission, decryption or radio capability.
 * Reverify against current durable trust, trusted time and live grants before any later effect.
 */
internal class Draft02OutboundEnvelope private constructor(bytes: ByteArray, digest: ByteArray,
    private val protectedEnd: Int, private val bodyEnd: Int, private val deviceAt: Int,
    private val revalidate: (Draft02ManifestAuthority, Draft02ManifestAuthority.Request, Long) -> Unit) {
    private val received = bytes.copyOf()
    private val unsignedIdentity = digest.copyOf()
    val envelope: ByteArray get() = received.copyOf()
    val unsignedDigest: ByteArray get() = unsignedIdentity.copyOf()
    override fun toString() = "Draft02OutboundEnvelope(verified-ciphertext)"

    /** Slices retained by the existing verified parser; never reparses caller bytes. */
    internal class Parts(val header: ByteArray, val protected: ByteArray, val nonce: ByteArray,
                         val body: ByteArray, val keyId: ByteArray, val enc: ByteArray, val wrap: ByteArray) {
        override fun toString() = "VerifiedOutboundParts(redacted)"
    }
    internal fun checkContext(authority: Draft02ManifestAuthority, request: Draft02ManifestAuthority.Request, now: Long) =
        revalidate(authority, request, now)
    internal fun parts() = Parts(received.copyOfRange(0, 10), received.copyOfRange(10, protectedEnd),
        received.copyOfRange(protectedEnd, protectedEnd + 12), received.copyOfRange(protectedEnd + 16, bodyEnd),
        received.copyOfRange(deviceAt + 1, deviceAt + 33), received.copyOfRange(deviceAt + 33, deviceAt + 98),
        received.copyOfRange(deviceAt + 98, deviceAt + 146))

    companion object {
        private const val WRAP_SIZE = 146
        private const val SKEW = 300_000L
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        private val SIGN_LABEL = "ZTSE/sign/v2\u0000".toByteArray(Charsets.US_ASCII)

        /** Request is selected independently of the received bytes; a relay cannot supply authority. */
        fun verify(input: ByteArray, authority: Draft02ManifestAuthority,
                   request: Draft02ManifestAuthority.Request, trustedNow: () -> Long): Draft02OutboundEnvelope {
            val parsed = parse(input) // Bound and own all bytes before calling external code.
            require(request.direction == Draft02ManifestAuthority.Direction.OUTBOUND) { "Outbound context required" }
            val now = trustedNow()
            val context = authority.context(request, now)
            match(parsed, context)
            fresh(parsed, now)
            require(signatureMatches(parsed, context.signerPoint)) { "Envelope signature" }
            val finalNow = trustedNow()
            require(finalNow >= now) { "Clock regression" }
            match(parsed, authority.context(request, finalNow))
            fresh(parsed, finalNow)
            return Draft02OutboundEnvelope(parsed.bytes,
                MessageDigest.getInstance("SHA-256").digest(parsed.bytes.copyOfRange(0, parsed.unsignedEnd)),
                10 + parsed.protected.size, parsed.bodyEnd, parsed.deviceAt) { nextAuthority, nextRequest, time ->
                    match(parsed, nextAuthority.context(nextRequest, time)); fresh(parsed, time)
                }
        }

        /**
         * UNAUTHENTICATED routing claims of a structurally bounded outbound envelope, read by the same
         * parser [verify] uses. They are only an early refusal fence for an execution grant (#539):
         * nothing here is authority, and [verify] still authenticates every claimed field.
         */
        internal class RoutingClaims(val accountId: ByteArray, val messageId: ByteArray, val deviceId: ByteArray,
                                     val lineId: ByteArray, val deviceReaderKeyId: ByteArray) {
            override fun toString() = "OutboundRoutingClaims(unauthenticated)"
        }

        /** Throws on any bound the sealed-v1 profile-02 outbound parser refuses (size, kind, lengths, wraps). */
        internal fun routingClaims(input: ByteArray): RoutingClaims {
            val parsed = parse(input)
            val p = parsed.protected
            return RoutingClaims(p.copyOfRange(0, 16), p.copyOfRange(16, 32), p.copyOfRange(32, 48),
                p.copyOfRange(48, 64), parsed.bytes.copyOfRange(parsed.deviceAt + 1, parsed.deviceAt + 33))
        }

        /** Low-level signature corpus entry point; this returns no trusted-envelope result. */
        internal fun signatureMatches(input: ByteArray, signerPoint: ByteArray): Boolean {
            require(signerPoint.size == 65) { "Signer point size" }
            val ownedPoint = signerPoint.copyOf()
            return signatureMatches(parse(input), ownedPoint)
        }

        private class Wrap(val role: Int, val id: ByteArray)
        private class Parsed(val bytes: ByteArray, val unsignedEnd: Int, val protected: ByteArray,
                             val wraps: List<Wrap>, val observed: Long, val expires: Long,
                             val bodyEnd: Int, val deviceAt: Int)

        private fun parse(input: ByteArray): Parsed {
            require(input.size in 557..34_213) { "Envelope size" }
            val bytes = input.copyOf()
            require(bytes.copyOfRange(0, 8).contentEquals(byteArrayOf(0x5a, 0x54, 0x53, 0x45, 2, 1, 0, 0))) {
                "Envelope profile/kind/flags"
            }
            val length = ((bytes[8].toInt() and 255) shl 8) or (bytes[9].toInt() and 255)
            require(length in 157..170) { "Protected length" }
            val end = 10 + length
            val protected = bytes.copyOfRange(10, end)
            val peerLength = protected[153].toInt() and 255
            require(peerLength in 3..16 && length == 154 + peerLength) { "Peer length" }
            require(protected[154] == '+'.code.toByte() && protected[155] in '1'.code.toByte()..'9'.code.toByte() &&
                protected.copyOfRange(156, protected.size).all { it in '0'.code.toByte()..'9'.code.toByte() }) { "Peer encoding" }
            require((0..3).all { slot -> protected.copyOfRange(slot * 16, slot * 16 + 16).any { it != 0.toByte() } }) {
                "Zero routing identity"
            }
            require(u64(protected, 64) > 0) { "Manifest version" }
            val observed = u64(protected, 136)
            val expires = u64(protected, 144)
            require(protected[152] == 1.toByte() && expires > observed && expires - observed <= 900_000) {
                "Intent/expiry interval"
            }
            val bodyLength = ByteBuffer.wrap(bytes, end + 12, 4).int.toLong() and 0xffff_ffffL
            require(bodyLength in 17..32_784) { "Body ciphertext length" }
            // Checked small bounds above make Int arithmetic safe; verify every tail before slicing it.
            val bodyEnd = end + 16 + bodyLength.toInt()
            require(bodyEnd < bytes.size) { "Truncated body" }
            val count = bytes[bodyEnd].toInt() and 255
            require(count in 2..8 && bodyEnd + 1 + count * WRAP_SIZE + 64 == bytes.size) { "Wrap count/EOF" }
            val wraps = ArrayList<Wrap>(count)
            var deviceAt = 0
            var deviceCount = 0
            var archiveCount = 0
            for (index in 0 until count) {
                val start = bodyEnd + 1 + index * WRAP_SIZE
                val role = bytes[start].toInt() and 255
                require(role in 1..3) { "Wrap role" }
                val id = bytes.copyOfRange(start + 1, start + 33)
                DevicePayloadKeyStore.decodePoint(bytes.copyOfRange(start + 33, start + 98))
                wraps.lastOrNull()?.let { previous ->
                    require(role > previous.role || role == previous.role && compare(id, previous.id) > 0) { "Wrap order/duplicate" }
                }
                if (role == 1) { deviceCount++; deviceAt = start }
                if (role == 2) archiveCount++
                wraps.add(Wrap(role, id))
            }
            require(deviceCount == 1 && archiveCount == 1) { "Recipient cardinality" }
            val unsignedEnd = bytes.size - 64
            val r = BigInteger(1, bytes.copyOfRange(unsignedEnd, unsignedEnd + 32))
            val s = BigInteger(1, bytes.copyOfRange(unsignedEnd + 32, bytes.size))
            require(r.signum() > 0 && r < ORDER && s.signum() > 0 && s <= ORDER.shiftRight(1)) { "Canonical signature scalars" }
            return Parsed(bytes, unsignedEnd, protected, wraps, observed, expires, bodyEnd, deviceAt)
        }

        private fun match(parsed: Parsed, context: Draft02ManifestAuthority.Context) {
            val p = parsed.protected
            require(context.direction == Draft02ManifestAuthority.Direction.OUTBOUND &&
                same(p.copyOfRange(0, 16), context.accountId) && same(p.copyOfRange(16, 32), context.messageId) &&
                same(p.copyOfRange(32, 48), context.deviceId) && same(p.copyOfRange(48, 64), context.lineId) &&
                u64(p, 64) == context.version && same(p.copyOfRange(72, 104), context.manifestDigest) &&
                same(p.copyOfRange(104, 136), context.signerKeyId) && same(p.copyOfRange(154, p.size), context.peer)) {
                "Envelope authority context"
            }
            val readers = context.readers
            require(parsed.wraps.size == readers.size && parsed.wraps.zip(readers).all { (actual, expected) ->
                actual.role == expected.role && same(actual.id, expected.keyId)
            }) { "Exact reader set" }
        }

        private fun fresh(parsed: Parsed, now: Long) {
            require(now > 0 && now < parsed.expires &&
                !(parsed.observed > now && parsed.observed - now > SKEW)) { "Envelope freshness" }
        }

        private fun signatureMatches(parsed: Parsed, signerPoint: ByteArray): Boolean {
            val point = DevicePayloadKeyStore.decodePoint(signerPoint)
            val signerId = MessageDigest.getInstance("SHA-256").digest(
                "ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + signerPoint)
            if (!same(signerId, parsed.protected.copyOfRange(104, 136))) return false
            val signature = parsed.bytes.copyOfRange(parsed.unsignedEnd, parsed.bytes.size)
            return Signature.getInstance("SHA256withECDSA").run {
                initVerify(point)
                update(SIGN_LABEL)
                update(ByteBuffer.allocate(4).putInt(parsed.unsignedEnd).array())
                update(parsed.bytes, 0, parsed.unsignedEnd)
                verify(der(signature))
            }
        }

        private fun der(raw: ByteArray): ByteArray {
            fun integer(at: Int): ByteArray {
                var first = at
                while (first < at + 31 && raw[first] == 0.toByte()) first++
                val magnitude = raw.copyOfRange(first, at + 32)
                val positive = if (magnitude[0].toInt() and 128 != 0) byteArrayOf(0) + magnitude else magnitude
                return byteArrayOf(2, positive.size.toByte()) + positive
            }
            val fields = integer(0) + integer(32)
            return byteArrayOf(0x30, fields.size.toByte()) + fields
        }
        private fun u64(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long.also { require(it >= 0) { "Signed storage range" } }
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun compare(a: ByteArray, b: ByteArray): Int {
            for (i in a.indices) {
                val delta = (a[i].toInt() and 255) - (b[i].toInt() and 255)
                if (delta != 0) return delta
            }
            return 0
        }
    }
}
