// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.Signature

/**
 * Dormant candidate ZTSE draft-01 signature primitive. The caller must first validate the entire
 * envelope and obtain a signer point from an independently trusted manifest. A valid signature is
 * neither manifest authorization nor a radio grant. No production message route calls this class.
 */
internal object Draft01SignaturePrimitive {
    enum class LowSPolicy { ALLOW_BOTH_FOR_INTEROP, REQUIRE_LOW_S }

    private val order = BigInteger(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val signLabel = "ZTSE/sign/v1\u0000".toByteArray(Charsets.US_ASCII)
    private val keyLabel = "ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII)

    /** Verify the exact received unsigned bytes, not a reconstructed envelope or prehashed input. */
    fun verifyOutboundParsed(
        envelope: ByteArray, pinnedSignerPoint: ByteArray, policy: LowSPolicy
    ): Boolean {
        require(envelope.size in 557..34_213) { "Draft outbound envelope bound" }
        require(envelope.copyOfRange(0, 8).contentEquals(
            byteArrayOf(0x5a, 0x54, 0x53, 0x45, 1, 1, 0, 0)
        )) { "Draft outbound header" }
        val protectedLen = ((envelope[8].toInt() and 0xff) shl 8) or (envelope[9].toInt() and 0xff)
        require(protectedLen in 157..170) { "Draft protected length" }
        val publicKey = DevicePayloadKeyStore.decodePoint(pinnedSignerPoint)
        val expectedKeyId = MessageDigest.getInstance("SHA-256").digest(
            keyLabel + byteArrayOf(1, 1) + pinnedSignerPoint)
        if (!MessageDigest.isEqual(expectedKeyId, envelope.copyOfRange(114, 146))) return false

        val unsignedLength = envelope.size - 64
        val raw = envelope.copyOfRange(unsignedLength, envelope.size)
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        if (r.signum() == 0 || r >= order || s.signum() == 0 || s >= order) return false
        if (policy == LowSPolicy.REQUIRE_LOW_S && s > order.shiftRight(1)) return false

        val length = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(unsignedLength).array()
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(signLabel)
            update(length)
            update(envelope, 0, unsignedLength)
            verify(rawToDer(raw))
        }
    }

    /** Strict fixed-width Web Crypto r||s to minimal positive DER INTEGERs for JCA. */
    private fun rawToDer(raw: ByteArray): ByteArray {
        fun integer(offset: Int): ByteArray {
            var first = offset
            while (first < offset + 31 && raw[first] == 0.toByte()) first++
            val magnitude = raw.copyOfRange(first, offset + 32)
            val positive = if ((magnitude[0].toInt() and 0x80) != 0) byteArrayOf(0) + magnitude else magnitude
            return byteArrayOf(2, positive.size.toByte()) + positive
        }
        val fields = integer(0) + integer(32)
        return byteArrayOf(0x30, fields.size.toByte()) + fields
    }
}
