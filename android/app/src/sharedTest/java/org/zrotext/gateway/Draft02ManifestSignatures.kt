// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.Signature

/** Shared test-only primitive used by the Android manifest verifier and cross-client corpus. */
internal object Draft02ManifestSignatures {
    private val order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    fun verify(point: ByteArray, raw: ByteArray, label: String, unsigned: ByteArray) {
        require(raw.size == 64) { "Manifest signature width" }
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        require(r.signum() > 0 && r < order && s.signum() > 0 && s <= order.shiftRight(1)) {
            "Manifest noncanonical signature"
        }
        require(verifyPlain(point, raw, label, unsigned)) { "Manifest signature verification" }
    }

    /** Plain ECDSA is exposed only to demonstrate why the low-s policy is necessary. */
    fun verifyPlain(point: ByteArray, raw: ByteArray, label: String, unsigned: ByteArray): Boolean {
        require(raw.size == 64)
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(DevicePayloadKeyStore.decodePoint(point))
            update(label.toByteArray(Charsets.US_ASCII))
            update(ByteBuffer.allocate(4).putInt(unsigned.size).array())
            update(unsigned)
            verify(rawToDer(raw))
        }
    }

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
