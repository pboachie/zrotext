// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.interfaces.ECPublicKey
import java.util.UUID

class EnrollmentProofTest {
    @Test fun enrollmentPayloadMatchesServerWireBytes() {
        val fingerprint = (0 until 32).map(Int::toByte).toByteArray()
        val nonce = (32 until 64).map(Int::toByte).toByteArray()
        val actual = EnrollmentProof.enrollmentBytes(
            UUID.fromString("00112233-4455-6677-8899-aabbccddeeff"),
            UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f"), fingerprint, nonce)
        assertEquals(
            "7a726f746578742d656e726f6c6c6d656e742d763100" +
                "00112233445566778899aabbccddeeff" +
                "102132435465768798a9bacbdcedfe0f" +
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            actual.toHexLower()
        )
        assertThrows(IllegalArgumentException::class.java) {
            EnrollmentProof.enrollmentBytes(UUID.randomUUID(), UUID.randomUUID(), ByteArray(31), nonce)
        }
    }

    @Test fun deviceAuthPayloadMatchesServerWireBytes() {
        val bytes = EnrollmentProof.deviceAuthBytes(
            UUID.fromString("00112233-4455-6677-8899-aabbccddeeff"),
            UUID.fromString("10213243-5465-7687-98a9-bacbdcedfe0f"),
            UUID.fromString("f0e1d2c3-b4a5-9687-7869-5a4b3c2d1e0f"), ByteArray(32) { 0xAB.toByte() })
        assertEquals(
            "7a726f746578742d6465766963652d617574682d763100" +
                "00112233445566778899aabbccddeeff" +
                "102132435465768798a9bacbdcedfe0f" +
                "f0e1d2c3b4a5968778695a4b3c2d1e0f" + "ab".repeat(32),
            bytes.toHexLower()
        )
    }

    @Test fun sec1FingerprintUsesUncompressedP256Point() {
        val params = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
            .getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        val generator = ECPoint(
            BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
            BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16))
        val key = KeyFactory.getInstance("EC")
            .generatePublic(ECPublicKeySpec(generator, params)) as ECPublicKey
        val sec1 = EnrollmentProof.uncompressedSec1(key)
        assertEquals("04" +
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            sec1.toHexLower())
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(sec1), EnrollmentProof.fingerprint(key))
        assertTrue(EnrollmentProof.hexUpper(EnrollmentProof.fingerprint(key)).matches(Regex("[0-9A-F]{64}")))
    }

    private fun ByteArray.toHexLower() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
