// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.Signature

/** Exact public ciphertext proof. Never a durable admission, grant, receiver or radio capability. */
internal class Draft03OutboundEnvelope private constructor(private val parsed: Parsed, private val verifiedAtMs: Long) {
    val envelope get() = parsed.bytes.copyOf()
    val unsignedDigest get() = sha(parsed.bytes.copyOfRange(0, parsed.unsignedEnd))
    val envelopeDigest get() = sha(parsed.bytes)
    override fun toString() = "Draft03OutboundEnvelope(verified-ciphertext)"

    /** Only owned public ciphertext/context bytes. No key, plaintext or permission. */
    class Parts internal constructor(val header: ByteArray, val protected: ByteArray, val nonce: ByteArray,
                                     val body: ByteArray, val keyId: ByteArray, val enc: ByteArray,
                                     val wrap: ByteArray, val info: ByteArray, val aad: ByteArray,
                                     val bodyAad: ByteArray) {
        override fun toString() = "Draft03VerifiedCiphertextParts(redacted)"
    }

    /** Recheck public context at use; current binding, one-use grant and journal remain external. */
    fun parts(authority: Draft03ManifestAuthority, request: Draft03ManifestAuthority.Request, nowMs: Long): Parts {
        require(nowMs >= verifiedAtMs) { "Envelope comparison regression" }
        match(parsed, authority.context(request, nowMs, parsed.expires))
        fresh(parsed, nowMs)
        val p = parsed
        val header = p.bytes.copyOfRange(0, 10)
        val protected = p.protected.copyOf()
        val keyId = p.bytes.copyOfRange(p.deviceAt + 1, p.deviceAt + 33)
        val suffix = header + protected + byteArrayOf(1) + keyId
        return Parts(header, protected, p.bytes.copyOfRange(p.protectedEnd, p.protectedEnd + 12),
            p.bytes.copyOfRange(p.protectedEnd + 16, p.bodyEnd), keyId,
            p.bytes.copyOfRange(p.deviceAt + 33, p.deviceAt + 98), p.bytes.copyOfRange(p.deviceAt + 98, p.deviceAt + 146),
            ascii("ZTSE/wrap/v3\u0000") + suffix, ascii("ZTSE/wrap-aad/v3\u0000") + suffix,
            ascii("ZTSE/body/v3\u0000") + header + protected)
    }

    private class Wrap(val role: Int, val id: ByteArray)
    private class Parsed(val bytes: ByteArray, val unsignedEnd: Int, val protected: ByteArray,
                         val wraps: List<Wrap>, val observed: Long, val expires: Long,
                         val protectedEnd: Int, val bodyEnd: Int, val deviceAt: Int)

    companion object {
        private val ORDER = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

        fun verify(input: ByteArray, authority: Draft03ManifestAuthority, request: Draft03ManifestAuthority.Request,
                   trustedNow: () -> Long): Draft03OutboundEnvelope {
            val parsed = parse(input) // Own bounded input before invoking external time.
            val now = trustedNow()
            val context = authority.context(request, now, parsed.expires)
            match(parsed, context)
            fresh(parsed, now)
            require(signatureMatches(parsed, context.signerPoint)) { "Envelope signature" }
            val finalNow = trustedNow()
            require(finalNow >= now) { "Clock regression" }
            match(parsed, authority.context(request, finalNow, parsed.expires))
            fresh(parsed, finalNow)
            return Draft03OutboundEnvelope(parsed, finalNow)
        }

        private fun parse(input: ByteArray): Parsed {
            require(input.size in 557..34_213) { "Envelope size" }
            val bytes = input.copyOf()
            require(same(bytes.copyOfRange(0, 8), byteArrayOf(0x5a, 0x54, 0x53, 0x45, 3, 1, 0, 0))) { "Profile/kind/flags" }
            val length = ByteBuffer.wrap(bytes, 8, 2).short.toInt() and 65535
            require(length in 157..170) { "Protected length" }
            val end = 10 + length
            val p = bytes.copyOfRange(10, end)
            val peerLength = p[153].toInt() and 255
            require(peerLength in 3..16 && length == 154 + peerLength) { "Peer length" }
            require(p[154] == 43.toByte() && p[155] in 49.toByte()..57.toByte() &&
                p.copyOfRange(156, p.size).all { it in 48.toByte()..57.toByte() }) { "Peer shape" }
            require((0..3).all { slot -> p.copyOfRange(slot * 16, slot * 16 + 16).any { it != 0.toByte() } }) { "Zero UUID" }
            require(u64(p, 64) > 0) { "Manifest version" }
            val observed = u64(p, 136)
            val expires = u64(p, 144)
            require(observed > 0 && expires > observed && expires - observed <= 900_000 && p[152] == 1.toByte()) { "Intent/expiry" }
            val bodyLength = ByteBuffer.wrap(bytes, end + 12, 4).int.toLong() and 0xffff_ffffL
            require(bodyLength in 17..32_784) { "Body length" }
            val bodyEnd = end + 16 + bodyLength.toInt()
            require(bodyEnd < bytes.size) { "Truncated body" }
            val count = bytes[bodyEnd].toInt() and 255
            require(count in 2..8 && bodyEnd + 1 + count * 146 + 64 == bytes.size) { "Wrap count/EOF" }
            val wraps = ArrayList<Wrap>(count)
            var deviceAt = 0
            var devices = 0
            var archives = 0
            for (index in 0 until count) {
                val start = bodyEnd + 1 + index * 146
                val role = bytes[start].toInt() and 255
                require(role in 1..3) { "Wrap role" }
                val id = bytes.copyOfRange(start + 1, start + 33)
                DevicePayloadKeyStore.decodePoint(bytes.copyOfRange(start + 33, start + 98))
                wraps.lastOrNull()?.let { require(role > it.role || role == it.role && compare(id, it.id) > 0) }
                if (role == 1) { devices++; deviceAt = start }
                if (role == 2) archives++
                wraps.add(Wrap(role, id))
            }
            require(devices == 1 && archives == 1) { "Recipient cardinality" }
            val unsignedEnd = bytes.size - 64
            strictSignature(bytes.copyOfRange(unsignedEnd, bytes.size))
            return Parsed(bytes, unsignedEnd, p, wraps, observed, expires, end, bodyEnd, deviceAt)
        }

        private fun match(p: Parsed, context: Draft03ManifestAuthority.Context) {
            val bytes = p.protected
            val request = context.request
            require(same(bytes.copyOfRange(0, 16), request.account()) && same(bytes.copyOfRange(16, 32), request.message()) &&
                same(bytes.copyOfRange(32, 48), request.device()) && same(bytes.copyOfRange(48, 64), request.line()) &&
                u64(bytes, 64) == context.version && same(bytes.copyOfRange(72, 104), context.manifestDigest) &&
                same(bytes.copyOfRange(104, 136), request.signer()) && same(bytes.copyOfRange(154, bytes.size), request.peer())) { "Envelope routing" }
            val readers = request.readers()
            require(p.wraps.size == readers.size && p.wraps.zip(readers).all { (actual, expected) ->
                actual.role == expected.role && same(actual.id, expected.keyId)
            }) { "Exact reader set" }
        }
        private fun fresh(p: Parsed, now: Long) {
            require(now > 0 && now < p.expires && (p.observed <= now || p.observed - now <= 300_000)) { "Envelope freshness" }
        }
        private fun strictSignature(raw: ByteArray) {
            val r = BigInteger(1, raw.copyOfRange(0, 32))
            val s = BigInteger(1, raw.copyOfRange(32, 64))
            require(r.signum() > 0 && r < ORDER && s.signum() > 0 && s <= ORDER.shiftRight(1)) { "Canonical signature" }
        }
        private fun signatureMatches(p: Parsed, point: ByteArray): Boolean {
            val signerId = sha(ascii("ZTSE/key/v1\u0000") + byteArrayOf(1, 1) + point)
            if (!same(signerId, p.protected.copyOfRange(104, 136))) return false
            val raw = p.bytes.copyOfRange(p.unsignedEnd, p.bytes.size)
            fun integer(at: Int): ByteArray = BigInteger(1, raw.copyOfRange(at, at + 32)).toByteArray().let {
                byteArrayOf(2, it.size.toByte()) + it
            }
            val fields = integer(0) + integer(32)
            return Signature.getInstance("SHA256withECDSA").run {
                initVerify(DevicePayloadKeyStore.decodePoint(point))
                update(ascii("ZTSE/sign/v3\u0000")); update(ByteBuffer.allocate(4).putInt(p.unsignedEnd).array())
                update(p.bytes, 0, p.unsignedEnd)
                verify(byteArrayOf(0x30, fields.size.toByte()) + fields)
            }
        }
        private fun u64(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long.also { require(it >= 0) }
        private fun ascii(value: String) = value.toByteArray(Charsets.US_ASCII)
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
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
