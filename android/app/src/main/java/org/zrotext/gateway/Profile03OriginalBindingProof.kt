// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Original signature evidence only. Its accepted timestamp is historical metadata, never a
 * present owner, device, selection, lease or effect permission. No missing proof is reconstructed.
 */
internal class Profile03OriginalBindingProof private constructor(
    val registrationId: UUID, val bindingId: UUID, val activationId: UUID,
    val accountId: UUID, val deviceId: UUID, val lineId: UUID, val generation: Long,
    val acceptedMs: Long, private val enrollmentPoint: ByteArray, private val ownerPoint: ByteArray,
    private val observation: ByteArray, private val deviceStatement: ByteArray,
    private val deviceSignature: ByteArray, private val ownerStatement: ByteArray,
    private val ownerSignature: ByteArray, private val registrationDigest: ByteArray,
    private val bindingDigest: ByteArray, private val routingOriginHash: String,
) {
    fun oldBindingProofDigest() = bindingDigest.copyOf()
    fun devicePoint() = enrollmentPoint.copyOf()
    fun approvalPoint() = ownerPoint.copyOf()
    fun registrationSha256() = registrationDigest.copyOf()
    /** Local read must still resolve an actual live complete-v2 issuer; this compares provenance. */
    fun matchesLocal(record: LineActivationV2Record): Boolean = record.isInstalled() && record.purpose == "sealed" &&
        record.accountId == accountId.toString() && record.deviceId == deviceId.toString() &&
        record.lineId == lineId.toString() && record.generation == generation && record.challengeId == activationId.toString() &&
        record.originHash == routingOriginHash && record.signerFingerprint == hex(sha(enrollmentPoint)) &&
        record.observationB64url == Profile03ElectionEncoding.encode(observation) &&
        record.statementSha256 == hex(sha(deviceStatement)) && record.signatureSha256 == hex(sha(deviceSignature)) &&
        record.confirmationSha256 == hex(sha(deviceStatement + deviceSignature)) &&
        record.signatureDerB64url == Profile03ElectionEncoding.encode(deviceSignature)
    override fun toString() = "Profile03OriginalBindingProof(historical-public-evidence)"

    companion object {
        /** Root history and both current local public identities come from actual local stores.
         * The authenticated server reader separately establishes original acceptance and current
         * binding allocation. These bytes alone cannot attest the database or grant permission.
         */
        fun verify(registrationBytes: ByteArray, activationBytes: ByteArray, expectedCore: ByteArray,
            localRootPin: ByteArray, existingEnrollmentPoint: ByteArray, selectedReaderKeyId: ByteArray,
            configuredOrigin: String): Profile03OriginalBindingProof {
            require(registrationBytes.size in 1..2048 && activationBytes.size in 1..2048 && expectedCore.size == 500 &&
                selectedReaderKeyId.size == 32 && selectedReaderKeyId.any { it != 0.toByte() })
            val registered = registrationBytes.copyOf()
            val activation = activationBytes.copyOf()
            val core = expectedCore.copyOf()
            val pin = Draft02RootComparison.validatePin(localRootPin)
            val existing = existingEnrollmentPoint.copyOf()
            DevicePayloadKeyStore.decodePoint(existing)
            val origin = configuredOrigin.toByteArray(Charsets.UTF_8)
            AndroidOwnerCustodyIdentity.validateAccountOrigin(UUID(0, 1), configuredOrigin)
            val r = registration(registered, pin, existing, configuredOrigin)
            val input = Cursor(unframe(activation, "ZTSE/line/payload-profile/activation-evidence/v1"))
            val registrationId = input.id()
            val bindingId = input.id()
            val devicePoint = input.take(65)
            val approvalPoint = input.take(65)
            DevicePayloadKeyStore.decodePoint(devicePoint); DevicePayloadKeyStore.decodePoint(approvalPoint)
            require(same(existing, devicePoint) && same(r.approvalPoint, approvalPoint) &&
                !same(devicePoint, approvalPoint) && !same(devicePoint, pin.copyOfRange(29, 94)))
            val deviceStatement = input.take(255)
            val deviceSignature = input.der()
            val ownerStatement = input.take(314)
            val ownerSignature = input.der()
            val accepted = input.positive()
            input.end()
            require(accepted >= r.completedMs && accepted < r.expiresMs && registrationId == r.challenge)

            val domain = LineActivationV2Purpose.SEALED.deviceDomain()
            require(deviceStatement.copyOfRange(0, domain.size).contentEquals(domain) &&
                deviceStatement[domain.size] == 2.toByte() && deviceStatement[domain.size + 1] == 2.toByte())
            val d = Cursor(deviceStatement.copyOfRange(domain.size + 2, deviceStatement.size))
            val account = d.id(); val line = d.id(); val device = d.id(); val generation = d.positive()
            val challenge = d.id(); val nonce = d.take(32)
            val observation = LineActivationV2Observation.decode(d.take(121))
            d.end()
            val fields = LineActivationV2StatementFields(account, line, device, generation, challenge, nonce)
            require(same(LineActivationV2Statements.device(LineActivationV2Purpose.SEALED, fields, observation), deviceStatement) &&
                same(LineActivationV2Statements.owner(LineActivationV2Purpose.SEALED, deviceStatement, deviceSignature), ownerStatement) &&
                account == r.account && line == r.line && device == r.device && generation == r.generation)
            // Parent v2 canonical DER accepts valid high-s. Hash and verify the original received DER.
            require(SealedLineActivationTranscript.verify(devicePoint, deviceStatement, deviceSignature) &&
                SealedLineActivationTranscript.verify(approvalPoint, ownerStatement, ownerSignature))
            val oldBinding = byteArrayOf(2, 2) + uuid(bindingId) + uuid(account) + uuid(device) + uuid(line) +
                number(generation) + uuid(challenge) + uuid(registrationId) + sha(registered) +
                sha(ownerStatement + ownerSignature) + sha(deviceStatement + deviceSignature) + selectedReaderKeyId
            val digest = sha(framed("ZTSE/line/payload-profile/old-binding/v1", oldBinding))
            require(core.copyOfRange(0, 8).contentEquals(byteArrayOf(90, 84, 80, 69, 3, 1, 2, 3)) &&
                same(core.copyOfRange(8, 24), uuid(account)) && same(core.copyOfRange(24, 40), uuid(device)) &&
                same(core.copyOfRange(40, 56), uuid(line)) && same(core.copyOfRange(72, 88), uuid(bindingId)) &&
                ByteBuffer.wrap(core, 88, 8).long == generation && same(core.copyOfRange(104, 136), digest) &&
                same(core.copyOfRange(136, 168), Draft02RootComparison.fingerprint(pin)) &&
                same(core.copyOfRange(256, 288), selectedReaderKeyId) &&
                same(core.copyOfRange(288, 320), signingId(existing)) && same(core.copyOfRange(400, 432), sha(origin)))
            return Profile03OriginalBindingProof(registrationId, bindingId, challenge, account, device, line,
                generation, accepted, devicePoint, approvalPoint, observation.bytes(), deviceStatement,
                deviceSignature, ownerStatement, ownerSignature, sha(registered), digest,
                Profile03Origins.fromProtocol(account, device, configuredOrigin).routingHash)
        }

        private class Registration(val account: UUID, val device: UUID, val line: UUID,
            val generation: Long, val challenge: UUID, val approvalPoint: ByteArray, val completedMs: Long, val expiresMs: Long)
        private fun registration(bytes: ByteArray, localPin: ByteArray, pairedPoint: ByteArray, origin: String): Registration {
            val input = Cursor(unframe(bytes, "ZTSE/line/payload-profile/registration-evidence/v1"))
            val transcript = input.take(input.length32(1024))
            val rootSignature = input.take(64)
            val approvalSignature = input.take(64)
            val approvalPoint = input.take(65)
            val approvalFingerprint = input.take(32)
            val pairedFingerprint = input.take(32)
            val issued = input.positive(); val expires = input.positive(); val completed = input.positive()
            input.end()
            require(expires > issued && expires - issued <= 300_000 && completed >= issued && completed < expires)
            val d = Cursor(transcript)
            require(same(d.take(REGISTER_DOMAIN.size), REGISTER_DOMAIN))
            val account = d.id(); d.id(); d.id() // Original owner actors: never current authentication.
            val device = d.id(); val line = d.id(); val generation = d.positive(); val challenge = d.id()
            require(d.take(32).any { it != 0.toByte() })
            require(d.positive() == issued && d.positive() == expires)
            val pin = Draft02RootComparison.validatePin(d.take(94))
            val fingerprint = d.take(32)
            val owner = d.take(65)
            val ownerFingerprint = d.take(32)
            val paired = d.take(32)
            d.positive(); d.positive() // Original registration lease identity only.
            d.text(128, ascii = true); d.text(128, ascii = true)
            require(d.text(255, ascii = true) == origin)
            d.end()
            DevicePayloadKeyStore.decodePoint(approvalPoint)
            require(same(pin, localPin) && same(pin.copyOfRange(5, 21), uuid(account)) &&
                same(fingerprint, Draft02RootComparison.fingerprint(pin)) && same(owner, approvalPoint) &&
                !same(owner, pin.copyOfRange(29, 94)) && same(sha(approvalPoint), approvalFingerprint) &&
                same(ownerFingerprint, approvalFingerprint) && same(paired, pairedFingerprint) &&
                same(sha(pairedPoint), pairedFingerprint) && !same(approvalFingerprint, pairedFingerprint))
            require(ConversationContentCrypto.verifyRaw(rootSignature, pin.copyOfRange(29, 94), transcript) &&
                ConversationContentCrypto.verifyRaw(approvalSignature, approvalPoint, transcript))
            return Registration(account, device, line, generation, challenge, approvalPoint, completed, expires)
        }
        private fun unframe(bytes: ByteArray, label: String): ByteArray {
            val d = Cursor(bytes)
            val prefix = label.toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
            require(same(d.take(prefix.size), prefix))
            val value = d.take(d.length32(2048))
            d.end()
            return value
        }
        private class Cursor(bytes: ByteArray) {
            private val input = ByteBuffer.wrap(bytes)
            fun take(size: Int): ByteArray {
                require(size >= 0 && input.remaining() >= size)
                return ByteArray(size).also(input::get)
            }
            fun id() = ByteBuffer.wrap(take(16)).let { UUID(it.long, it.long).also { id -> require(id != UUID(0, 0)) } }
            fun positive() = ByteBuffer.wrap(take(8)).long.also { require(it > 0) }
            fun length32(max: Int) = ByteBuffer.wrap(take(4)).int.also { require(it in 1..max) }
            fun shortLength(max: Int) = (ByteBuffer.wrap(take(2)).short.toInt() and 65535).also { require(it in 1..max) }
            fun text(max: Int, ascii: Boolean): String {
                val bytes = take(shortLength(max))
                require(!ascii || bytes.all { (it.toInt() and 255) in 33..126 })
                return Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
            }
            fun der(): ByteArray = take(shortLength(72)).also {
                require(it.size >= 8)
                SealedLineActivationTranscript.requireCanonicalDer(it)
            }
            fun end() { require(!input.hasRemaining()) }
        }
        private val REGISTER_DOMAIN = "ZTSE/line/owner-key/register/v1\u0000".toByteArray(Charsets.US_ASCII)
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
        private fun hex(bytes: ByteArray) = Draft02OutboundPreparation.hex(bytes)
        private fun uuid(value: UUID) = ReviewedIntent03.uuid(value)
        private fun number(value: Long) = ByteBuffer.allocate(8).putLong(value).array()
        private fun framed(label: String, bytes: ByteArray) = ReviewedIntent03.framed(label, bytes)
        private fun signingId(point: ByteArray) = sha("ZTSE/key/v1\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(1, 1) + point)
    }
}
