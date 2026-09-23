// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.UUID

/** Exact signing payloads expected by the server enrollment module. */
internal object EnrollmentProof {
    private val enrollmentPrefix = "zrotext-enrollment-v1\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val devicePrefix = "zrotext-device-auth-v1\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val p256Order = BigInteger(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
    )

    fun enrollmentBytes(accountId: UUID, pairingId: UUID, fingerprint: ByteArray, nonce: ByteArray): ByteArray {
        require(fingerprint.size == 32 && nonce.size == 32)
        return ByteBuffer.allocate(enrollmentPrefix.size + 16 + 16 + 32 + 32)
            .put(enrollmentPrefix).putUuid(accountId).putUuid(pairingId)
            .put(fingerprint).put(nonce).array()
    }

    fun deviceAuthBytes(accountId: UUID, deviceId: UUID, challengeId: UUID, nonce: ByteArray): ByteArray {
        require(nonce.size == 32)
        return ByteBuffer.allocate(devicePrefix.size + 16 + 16 + 16 + 32)
            .put(devicePrefix).putUuid(accountId).putUuid(deviceId)
            .putUuid(challengeId).put(nonce).array()
    }

    /** Server hashes the uncompressed 65-byte SEC1 point, not the SPKI wrapper. */
    fun fingerprint(publicKey: ECPublicKey): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(uncompressedSec1(publicKey))

    fun uncompressedSec1(publicKey: ECPublicKey): ByteArray {
        require(publicKey.params.curve.field.fieldSize == 256 && publicKey.params.order == p256Order) {
            "P-256 key required"
        }
        return byteArrayOf(0x04) + fixed32(publicKey.w.affineX) + fixed32(publicKey.w.affineY)
    }

    fun hexUpper(bytes: ByteArray): String = bytes.joinToString("") { "%02X".format(it.toInt() and 0xff) }

    private fun fixed32(value: BigInteger): ByteArray {
        require(value.signum() >= 0 && value.bitLength() <= 256)
        val source = value.toByteArray().let { if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it }
        require(source.size <= 32)
        return ByteArray(32 - source.size) + source
    }

    private fun ByteBuffer.putUuid(id: UUID): ByteBuffer =
        putLong(id.mostSignificantBits).putLong(id.leastSignificantBits)
}
