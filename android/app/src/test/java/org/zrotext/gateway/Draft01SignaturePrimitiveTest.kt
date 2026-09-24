// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class Draft01SignaturePrimitiveTest {
    private val point = hex("0451590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ed" +
        "e0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4")
    private val order = BigInteger(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val permissive = Draft01SignaturePrimitive.LowSPolicy.ALLOW_BOTH_FOR_INTEROP
    private val lowOnly = Draft01SignaturePrimitive.LowSPolicy.REQUIRE_LOW_S

    @Test fun pinnedBrowserEnvelopeVerifiesExactSignedBytes() {
        val envelope = fixture()
        assertTrue(Draft01SignaturePrimitive.verifyOutboundParsed(envelope, point, permissive))
        assertFalse(Draft01SignaturePrimitive.verifyOutboundParsed(envelope, point, lowOnly))
        val lowS = envelope.copyOf().apply {
            val s = BigInteger(1, copyOfRange(size - 32, size))
            fixed32(order.subtract(s)).copyInto(this, size - 32)
        }
        assertTrue(Draft01SignaturePrimitive.verifyOutboundParsed(lowS, point, lowOnly))
        assertTrue(Draft01SignaturePrimitive.verifyOutboundParsed(lowS, point, permissive))
    }

    @Test fun jcaDerSigningConvertsToCanonicalWireSignature() {
        val pair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1")); generateKeyPair()
        }
        val signerPoint = DevicePayloadKeyStore.encodePoint(pair.public as ECPublicKey)
        val envelope = ByteArray(557)
        byteArrayOf(0x5a, 0x54, 0x53, 0x45, 1, 1, 0, 0, 0, 157.toByte()).copyInto(envelope)
        MessageDigest.getInstance("SHA-256").digest(
            "ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + signerPoint
        ).copyInto(envelope, 114)
        val unsigned = envelope.copyOfRange(0, envelope.size - 64)
        val transcript = "ZTSE/sign/v1\u0000".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(0, 0, (unsigned.size ushr 8).toByte(), unsigned.size.toByte()) + unsigned
        val der = Signature.getInstance("SHA256withECDSA").run {
            initSign(pair.private); update(transcript); sign()
        }
        val raw = Draft01SignaturePrimitive.canonicalRawFromDer(der)
        assertTrue(BigInteger(1, raw.copyOfRange(32, 64)) <= order.shiftRight(1))
        raw.copyInto(envelope, unsigned.size)
        assertTrue(Draft01SignaturePrimitive.verifyOutboundParsed(envelope, signerPoint, lowOnly))
        assertThrows(IllegalArgumentException::class.java) {
            Draft01SignaturePrimitive.canonicalRawFromDer(der + 0.toByte())
        }
        assertThrows(IllegalArgumentException::class.java) {
            Draft01SignaturePrimitive.canonicalRawFromDer(der.copyOf().apply { this[0] = 0x31 })
        }
    }

    @Test fun changedTranscriptIdentityAndSignatureFail() {
        val envelope = fixture()
        fun changed(index: Int) = envelope.copyOf().apply { this[index] = (this[index].toInt() xor 1).toByte() }
        assertFalse(Draft01SignaturePrimitive.verifyOutboundParsed(changed(180), point, permissive))
        assertFalse(Draft01SignaturePrimitive.verifyOutboundParsed(changed(envelope.lastIndex), point, permissive))
        assertFalse(Draft01SignaturePrimitive.verifyOutboundParsed(changed(114), point, permissive))
        assertFalse(Draft01SignaturePrimitive.verifyOutboundParsed(envelope, hex(
            "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a8" +
                "26a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"), permissive))
    }

    @Test fun outOfRangeAndMalformedInputsFail() {
        val envelope = fixture()
        assertFalse(Draft01SignaturePrimitive.verifyOutboundParsed(envelope.copyOf().apply {
            fill(0, size - 64, size - 32)
        }, point, permissive))
        assertFalse(Draft01SignaturePrimitive.verifyOutboundParsed(envelope.copyOf().apply {
            fixed32(order).copyInto(this, size - 32)
        }, point, permissive))
        assertThrows(IllegalArgumentException::class.java) {
            Draft01SignaturePrimitive.verifyOutboundParsed(envelope.copyOf(556), point, permissive)
        }
        assertThrows(IllegalArgumentException::class.java) {
            Draft01SignaturePrimitive.verifyOutboundParsed(envelope, ByteArray(65), permissive)
        }
    }

    private fun fixture(): ByteArray = hex(requireNotNull(javaClass.getResourceAsStream(
        "/ztse-draft01-outbound-envelope.hex")).bufferedReader().use { it.readText() }.trim())
    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun fixed32(value: BigInteger): ByteArray = value.toByteArray().let {
        val magnitude = if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it
        ByteArray(32).also { out -> magnitude.copyInto(out, 32 - magnitude.size) }
    }
}
