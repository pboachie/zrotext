// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.math.BigInteger
import java.security.MessageDigest
import java.util.UUID

/** Public association/proof grammar only. This cannot create a hardware key, establish
 * zero history, close a remote attempt, activate a counter or restore capture permission.
 * Actual callers must independently verify retained origin, current enrolled actor,
 * one-way foreground decision, protected phase burns and the exact committed receipt. */
internal object CaptureBootstrap03 {
    const val ASSOCIATION_BYTES = 473
    const val CORE_BYTES = 521
    const val BUNDLE_BYTES = 649
    private val header = byteArrayOf(90, 84, 67, 66, 1, 3, 3, 0)
    private val order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

    data class Identities(val account: UUID, val device: UUID, val bootstrap: UUID,
        val opening: UUID, val originalRegistration: UUID, val oldBinding: UUID,
        val acceptedBinding: UUID, val electionChallenge: UUID, val line: UUID) {
        internal fun values() = listOf(account, device, bootstrap, opening, originalRegistration,
            oldBinding, acceptedBinding, electionChallenge, line)
    }
    data class Generations(val oldBinding: Long, val acceptedBinding: Long,
        val vault: Long = 1, val selection: Long = 1) {
        internal fun values() = listOf(oldBinding, acceptedBinding, vault, selection)
    }
    class Commitments(bootstrapNonce: ByteArray, enrolledKey: ByteArray, canaryKey: ByteArray,
        root: ByteArray, election: ByteArray, registration: ByteArray, activation: ByteArray) {
        private val owned = listOf(bootstrapNonce, enrolledKey, canaryKey, root, election, registration, activation).map {
            require(it.size == 32 && it.any { b -> b != 0.toByte() }); it.copyOf()
        }
        fun bootstrapNonce() = owned[0].copyOf()
        fun enrolledKey() = owned[1].copyOf()
        fun canaryKey() = owned[2].copyOf()
        fun root() = owned[3].copyOf()
        fun election() = owned[4].copyOf()
        fun registration() = owned[5].copyOf()
        fun activation() = owned[6].copyOf()
        internal fun values() = owned.map { it.copyOf() }
        override fun toString() = "CaptureBootstrapCommitments(public-only)"
    }
    /** Immutable473 preimage. There is deliberately no association signature API. */
    class Association private constructor(private val wire: ByteArray, val identities: Identities,
        val generations: Generations, val commitments: Commitments, private val canary: ByteArray) {
        fun bytes() = wire.copyOf()
        fun sha256() = sha(wire)
        fun canaryPoint() = canary.copyOf()
        fun requireOriginalNonce(raw: ByteArray) {
            val owned = raw.copyOf(); requireNonce(owned)
            require(same(sha(owned), commitments.bootstrapNonce()))
        }
        /** Known identities must come from independently verified original/current history,
         * not from this proof. Local actual new-alias/hardware checks remain mandatory. */
        fun requireKeySeparation(enrolledPoint: ByteArray, knownOriginalAndCurrentSigningPoints: List<ByteArray>) {
            DevicePayloadKeyStore.decodePoint(enrolledPoint)
            require(same(signingKeyId(enrolledPoint), commitments.enrolledKey()) && !same(canary, enrolledPoint))
            for (point in knownOriginalAndCurrentSigningPoints) {
                DevicePayloadKeyStore.decodePoint(point)
                require(!same(canary, point) && !same(commitments.canaryKey(), signingKeyId(point)))
            }
        }
        override fun toString() = "CaptureBootstrapAssociation(unverified-origin)"
        companion object {
            fun encode(ids: Identities, generations: Generations, commitments: Commitments,
                canaryPoint: ByteArray): Association {
                require(canaryPoint.size == 65)
                val b = ByteBuffer.allocate(ASSOCIATION_BYTES).put(header)
                ids.values().forEach { b.putLong(it.mostSignificantBits).putLong(it.leastSignificantBits) }
                generations.values().forEach(b::putLong)
                commitments.values().forEach(b::put)
                b.put(canaryPoint)
                return decode(b.array())
            }
            fun decode(source: ByteArray): Association {
                require(source.size == ASSOCIATION_BYTES)
                val wire = source.copyOf(); val b = ByteBuffer.wrap(wire)
                require(ByteArray(8).also(b::get).contentEquals(header))
                val ids = List(9) { UUID(b.long, b.long).also { require(it != UUID(0, 0)) } }
                val n = List(4) { b.long.also { require(it > 0) } }
                require(n[1] > n[0] && n[2] == 1L && n[3] == 1L)
                val d = List(7) { ByteArray(32).also(b::get) }
                val c = Commitments(d[0], d[1], d[2], d[3], d[4], d[5], d[6])
                val point = ByteArray(65).also(b::get)
                DevicePayloadKeyStore.decodePoint(point)
                require(same(signingKeyId(point), c.canaryKey()) && !same(c.enrolledKey(), c.canaryKey()))
                return Association(wire, Identities(ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7], ids[8]),
                    Generations(n[0], n[1], n[2], n[3]), c, point)
            }
        }
    }
    class Core private constructor(private val wire: ByteArray, val association: Association,
        val attempt: UUID, private val nonce: ByteArray) {
        fun bytes() = wire.copyOf()
        fun sha256() = sha(wire)
        fun attemptNonceCommitment() = nonce.copyOf()
        fun requireAttempt(expectedAttempt: UUID, actualRawNonce: ByteArray, expectedAssociation: Association) {
            val owned = actualRawNonce.copyOf(); requireNonce(owned)
            require(attempt == expectedAttempt && same(nonce, sha(owned)) &&
                same(association.bytes(), expectedAssociation.bytes()))
        }
        fun deviceTranscript() = ReviewedIntent03.framed("ZTSE/conversation/capture-bootstrap/device-attempt/v1", wire)
        fun canaryTranscript(exactDeviceSignature: ByteArray): ByteArray {
            val owned = exactDeviceSignature.copyOf(); requireRaw(owned)
            return ReviewedIntent03.framed("ZTSE/conversation/capture-bootstrap/canary-attempt/v1", wire + sha(owned))
        }
        override fun toString() = "CaptureBootstrapCore(unverified-attempt)"
        companion object {
            fun encode(association: Association, actualAttempt: UUID, actualRawNonce: ByteArray): Core {
                val ownedNonce = actualRawNonce.copyOf()
                require(actualAttempt != UUID(0, 0)); requireNonce(ownedNonce)
                val a = association.bytes()
                return decode(a.copyOfRange(0, 72) + ReviewedIntent03.uuid(actualAttempt) +
                    a.copyOfRange(72, 408) + sha(ownedNonce) + a.copyOfRange(408, ASSOCIATION_BYTES))
            }
            fun decode(source: ByteArray): Core {
                require(source.size == CORE_BYTES)
                val wire = source.copyOf()
                val a = Association.decode(wire.copyOfRange(0, 72) + wire.copyOfRange(88, 424) + wire.copyOfRange(456, CORE_BYTES))
                val attempt = ByteBuffer.wrap(wire, 72, 16).let { UUID(it.long, it.long) }
                val nonce = wire.copyOfRange(424, 456)
                require(attempt != UUID(0, 0) && nonce.any { it != 0.toByte() })
                return Core(wire, a, attempt, nonce)
            }
        }
    }
    class Bundle private constructor(private val wire: ByteArray, val core: Core,
        private val device: ByteArray, private val canary: ByteArray) {
        fun bytes() = wire.copyOf()
        fun sha256() = sha(wire)
        fun deviceSignature() = device.copyOf()
        fun canarySignature() = canary.copyOf()
        /** Valid TEST/public signatures are not hardware custody or a server receipt. */
        fun requireSignatures(independentlyEnrolledPoint: ByteArray, knownOriginalAndCurrentSigningPoints: List<ByteArray>) {
            val enrolled = independentlyEnrolledPoint.copyOf()
            val known = knownOriginalAndCurrentSigningPoints.map { it.copyOf() }
            core.association.requireKeySeparation(enrolled, known)
            require(ConversationContentCrypto.verifyRaw(device, enrolled, core.deviceTranscript()))
            require(ConversationContentCrypto.verifyRaw(canary, core.association.canaryPoint(), core.canaryTranscript(device)))
        }
        override fun toString() = "CaptureBootstrapBundle(public-proof-only)"
        companion object {
            fun decode(source: ByteArray): Bundle {
                require(source.size == BUNDLE_BYTES)
                val wire = source.copyOf()
                requireRaw(wire.copyOfRange(CORE_BYTES, CORE_BYTES + 64))
                requireRaw(wire.copyOfRange(CORE_BYTES + 64, BUNDLE_BYTES))
                return Bundle(wire, Core.decode(wire.copyOfRange(0, CORE_BYTES)),
                    wire.copyOfRange(CORE_BYTES, CORE_BYTES + 64), wire.copyOfRange(CORE_BYTES + 64, BUNDLE_BYTES))
            }
        }
    }
    fun signingKeyId(point: ByteArray): ByteArray {
        DevicePayloadKeyStore.decodePoint(point)
        return sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
    }
    private fun requireNonce(raw: ByteArray) = require(raw.size == 32 && raw.any { it != 0.toByte() })
    private fun requireRaw(raw: ByteArray) {
        require(raw.size == 64)
        val r = BigInteger(1, raw.copyOfRange(0, 32)); val s = BigInteger(1, raw.copyOfRange(32, 64))
        require(r.signum() > 0 && r < order && s.signum() > 0 && s <= order.shiftRight(1))
    }
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
}
