// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Public first-origin bytes, independent of conversation negotiation. A valid signature is
 * historical evidence only: it cannot establish an authenticated opening, provider freshness,
 * a usable protection pin, capture state, or an effect lease. */
internal object ProtectionOriginProof {
    private val associationHeader = byteArrayOf(90, 84, 80, 65, 1, 1, 0, 0)
    private val coreHeader = byteArrayOf(90, 84, 80, 82, 1, 1, 0, 0)

    class Association private constructor(private val exact: ByteArray) {
        fun bytes() = exact.copyOf()
        val accountId get() = id(exact, 8)
        val deviceId get() = id(exact, 24)
        val setupId get() = id(exact, 40)
        val openingId get() = id(exact, 56)
        val commandId get() = id(exact, 72)
        val sourcePairingId get() = id(exact, 88)
        val originDigest get() = exact.copyOfRange(104, 136)
        val enrolledKeyId get() = exact.copyOfRange(136, 168)
        val hmacProbe get() = exact.copyOfRange(200, 232)
        val canaryPoint get() = exact.copyOfRange(264, 329)
        fun sha256() = sha(exact)
        fun requireProviderClaims(openingNonce: ByteArray, aesProbe: ByteArray) {
            require(openingNonce.size == 32 && aesProbe.size == 120)
            require(same(sha(openingNonce), exact.copyOfRange(168, 200)))
            require(same(sha(aesProbe), exact.copyOfRange(232, 264)))
        }
        fun probeContext(openingNonce: ByteArray): ByteArray {
            val nonce = openingNonce.copyOf()
            require(nonce.size == 32 && same(sha(nonce), exact.copyOfRange(168, 200)))
            return exact.copyOfRange(8, 168) + nonce
        }
        fun requireOriginal(command: ProtectionSetupCommand) {
            command.requireShape()
            require(accountId.toString() == command.accountId && deviceId.toString() == command.deviceId &&
                setupId.toString() == command.setupId && openingId.toString() == command.openingId &&
                commandId.toString() == command.commandId && hex(originDigest) == command.originSha256 &&
                hex(enrolledKeyId) == command.enrolledSigningKeyId)
        }
        override fun toString() = "ProtectionOriginAssociation(public-candidate)"
        companion object {
            fun decode(input: ByteArray): Association {
                require(input.size == 329)
                val bytes = input.copyOf()
                require(bytes.copyOfRange(0, 8).contentEquals(associationHeader))
                for (at in 8 until 104 step 16) require(id(bytes, at) != UUID(0, 0))
                for (at in 104 until 264 step 32) require(bytes.copyOfRange(at, at + 32).any { it != 0.toByte() })
                DevicePayloadKeyStore.decodePoint(bytes.copyOfRange(264, 329))
                return Association(bytes)
            }
            fun create(command: ProtectionSetupCommand, sourcePairingId: UUID, openingNonce: ByteArray,
                hmacProbe: ByteArray, aesProbe: ByteArray, canaryPoint: ByteArray): Association {
                command.requireShape()
                val nonce = openingNonce.copyOf(); val hmac = hmacProbe.copyOf()
                val aes = aesProbe.copyOf(); val point = canaryPoint.copyOf()
                require(nonce.size == 32 && hmac.size == 32 && aes.size == 120 && point.size == 65)
                return decode(associationHeader + listOf(command.accountId, command.deviceId, command.setupId,
                    command.openingId, command.commandId, sourcePairingId.toString()).map { uuid(UUID.fromString(it)) }
                    .fold(ByteArray(0)) { a, b -> a + b } + unhex(command.originSha256) +
                    unhex(command.enrolledSigningKeyId) + sha(nonce) + hmac + sha(aes) + point)
            }
        }
    }

    class Core private constructor(private val exact: ByteArray, val association: Association) {
        fun bytes() = exact.copyOf()
        val attemptId get() = id(exact, 329)
        val issuedMs get() = number(exact, 345)
        val expiresMs get() = number(exact, 353)
        fun sha256() = sha(exact)
        fun requireNonce(input: ByteArray) {
            val nonce = input.copyOf()
            require(nonce.size == 32 && same(sha(nonce), exact.copyOfRange(361, 393)))
        }
        fun requireSigningTime(upperMs: Long) { require(upperMs >= issuedMs && upperMs < expiresMs) }
        fun requireAcceptedTime(acceptedMs: Long) { require(acceptedMs >= issuedMs && acceptedMs < expiresMs) }
        override fun toString() = "ProtectionOriginCore(public-candidate)"
        companion object {
            fun decode(input: ByteArray): Core {
                require(input.size == 393)
                val bytes = input.copyOf()
                require(bytes.copyOfRange(0, 8).contentEquals(coreHeader))
                val association = Association.decode(associationHeader + bytes.copyOfRange(8, 329))
                require(id(bytes, 329) != UUID(0, 0))
                val issued = number(bytes, 345); val expires = number(bytes, 353)
                require(issued > 0 && expires > issued && expires - issued <= 30_000)
                require(bytes.copyOfRange(361, 393).any { it != 0.toByte() })
                return Core(bytes, association)
            }
        }
    }

    class Bundle private constructor(private val exact: ByteArray, val core: Core) {
        fun bytes() = exact.copyOf()
        fun deviceSignature() = exact.copyOfRange(393, 457)
        fun canarySignature() = exact.copyOfRange(457, 521)
        fun sha256() = sha(exact)
        override fun toString() = "ProtectionOriginBundle(verified-historical-signatures-only)"
        companion object {
            fun verify(input: ByteArray, expected: Association, enrolledPoint: ByteArray): Bundle {
                require(input.size == 521)
                val bytes = input.copyOf(); val point = enrolledPoint.copyOf()
                val core = Core.decode(bytes.copyOfRange(0, 393))
                require(same(core.association.bytes(), expected.bytes()) &&
                    same(signingKeyId(point), expected.enrolledKeyId) && !same(point, expected.canaryPoint))
                require(ConversationContentCrypto.verifyRaw(bytes.copyOfRange(393, 457), point, deviceTranscript(core)))
                require(ConversationContentCrypto.verifyRaw(bytes.copyOfRange(457, 521), expected.canaryPoint,
                    canaryTranscript(core, bytes.copyOfRange(393, 457))))
                return Bundle(bytes, core)
            }
        }
    }
    fun deviceTranscript(core: Core) = framed("ZT/protection/first-origin-device/v1", core.bytes())
    fun canaryTranscript(core: Core, deviceSignature: ByteArray): ByteArray {
        require(deviceSignature.size == 64)
        return framed("ZT/protection/first-origin-canary/v1", core.bytes() + sha(deviceSignature.copyOf()))
    }
    fun hmacTranscript(probeContext: ByteArray): ByteArray {
        require(probeContext.size == 192)
        return framed("ZT/protection/hmac-probe/v1", probeContext.copyOf())
    }
    fun aesPlaintext(purpose: String, probeContext: ByteArray): ByteArray {
        require(purpose in setOf("journal", "withdrawal") && probeContext.size == 192)
        return sha(framed("ZT/protection/aes-plaintext/$purpose/v1", probeContext.copyOf()))
    }
    fun aesAad(purpose: String, probeContext: ByteArray): ByteArray {
        require(purpose in setOf("journal", "withdrawal") && probeContext.size == 192)
        return framed("ZT/protection/aes-probe/$purpose/v1", probeContext.copyOf())
    }
    fun signingKeyId(input: ByteArray): ByteArray {
        val point = input.copyOf(); DevicePayloadKeyStore.decodePoint(point)
        return sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
    }
    fun probeContext(command: ProtectionSetupCommand, opening: ProtectionOriginWire.Opening): ByteArray {
        command.requireShape()
        return listOf(command.accountId, command.deviceId, command.setupId, command.openingId,
            command.commandId, opening.sourcePairingId.toString()).map { uuid(UUID.fromString(it)) }
            .fold(ByteArray(0)) { a, b -> a + b } + unhex(command.originSha256) +
            unhex(command.enrolledSigningKeyId) + opening.nonce
    }
    private fun framed(label: String, payload: ByteArray) = ReviewedIntent03.framed(label, payload)
    private fun number(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 8).long
    private fun id(bytes: ByteArray, at: Int) = ByteBuffer.wrap(bytes, at, 16).let { UUID(it.long, it.long) }
    private fun uuid(id: UUID) = ByteBuffer.allocate(16).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).array()
    internal fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    internal fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
    private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
    private fun unhex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
