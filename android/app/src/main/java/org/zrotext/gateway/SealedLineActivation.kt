// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.Signature
import java.util.UUID

internal data class SealedLineChallenge(val connectionEpoch: Long, val challengeId: UUID,
    val accountId: UUID, val lineId: UUID, val deviceId: UUID, val generation: Long,
    val nonce: ByteArray, val expiresAtMs: Long)

/** Independent local phone-line acceptance. A remote challenge cannot create this selection. */
internal class SealedLineAcceptance(val accountId: UUID, val deviceId: UUID, val lineId: UUID,
    val generation: Long, val subscriptionId: Int, pairedSigningFingerprint: ByteArray) {
    private val fingerprint = pairedSigningFingerprint.copyOf()
    init {
        require(listOf(accountId, deviceId, lineId).none { it == UUID(0, 0) } &&
            generation > 0 && subscriptionId >= 0 && fingerprint.size == 32 && fingerprint.any { it != 0.toByte() })
    }
    fun fingerprint() = fingerprint.copyOf()
    fun matches(c: SealedLineChallenge) = c.accountId == accountId && c.deviceId == deviceId &&
        c.lineId == lineId && c.generation == generation
    override fun toString() = "SealedLineAcceptance(redacted)"
}

/** Exact Rust line_activation::device_line_statement bytes; neither SMS nor content consent. */
internal object SealedLineActivationTranscript {
    private val domain = "ZTSE/line/device-confirm/v1\u0000".toByteArray(Charsets.US_ASCII)
    const val CHALLENGE_LIFETIME_MS = 300_000L
    const val ACK_GRACE_MS = 900_000L
    fun validate(c: SealedLineChallenge) {
        require(c.connectionEpoch > 0 && listOf(c.accountId, c.lineId, c.deviceId, c.challengeId)
            .none { it == UUID(0, 0) } && c.generation > 0 && c.nonce.size == 32 &&
            c.nonce.any { it != 0.toByte() } && c.expiresAtMs in 1..(Long.MAX_VALUE - ACK_GRACE_MS))
    }
    fun deviceStatement(c: SealedLineChallenge, api: Int, subscription: Int): ByteArray {
        validate(c)
        require(api in 31..65535 && subscription >= 0)
        return ByteBuffer.allocate(domain.size + 16 * 4 + 8 + 32 + 2 + 1 + 4)
            .put(domain).putUuid(c.accountId).putUuid(c.lineId).putUuid(c.deviceId)
            .putLong(c.generation).putUuid(c.challengeId).put(c.nonce)
            .putShort(api.toShort()).put(1.toByte()).putInt(subscription).array()
    }
    fun requireCanonicalDer(signature: ByteArray) {
        // The existing strict parser checks minimal positive in-range P-256 DER scalars.
        // Its normalized raw result is deliberately discarded: verify/hash the original DER.
        Draft01SignaturePrimitive.canonicalRawFromDer(signature)
    }
    fun verify(point: ByteArray, statement: ByteArray, signature: ByteArray): Boolean = try {
        requireCanonicalDer(signature)
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(DevicePayloadKeyStore.decodePoint(point)); update(statement); verify(signature)
        }
    } catch (_: Exception) { false }
    fun digest(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun ByteBuffer.putUuid(id: UUID) = putLong(id.mostSignificantBits).putLong(id.leastSignificantBits)
}

internal class PreparedSealedLineActivation(c: SealedLineChallenge, val apiLevel: Int,
    val sim: ActivatedSimCard, statement: ByteArray, signature: ByteArray, fingerprint: ByteArray) {
    private val frozen = c.copy(nonce = c.nonce.copyOf())
    val challenge get() = frozen.copy(nonce = frozen.nonce.copyOf())
    private val bytes = statement.copyOf()
    private val der = signature.copyOf()
    private val signer = fingerprint.copyOf()
    init {
        require(sim.subscriptionId >= 0 && sim.cardId >= 0 && signer.size == 32 &&
            bytes.contentEquals(SealedLineActivationTranscript.deviceStatement(frozen, apiLevel, sim.subscriptionId)))
        SealedLineActivationTranscript.requireCanonicalDer(der)
    }
    fun statement() = bytes.copyOf()
    fun signature() = der.copyOf()
    fun fingerprint() = signer.copyOf()
    override fun toString() = "PreparedSealedLineActivation(redacted)"
}

internal class SealedLineActivationReceipt(val connectionEpoch: Long, val challengeId: UUID,
    val accountId: UUID, val lineId: UUID, val deviceId: UUID, val generation: Long,
    statementSha256: ByteArray, signatureSha256: ByteArray) {
    private val statementDigest = statementSha256.copyOf()
    private val signatureDigest = signatureSha256.copyOf()
    init {
        require(connectionEpoch > 0 && generation > 0 &&
            listOf(challengeId, accountId, lineId, deviceId).none { it == UUID(0, 0) } &&
            statementDigest.size == 32 && signatureDigest.size == 32)
    }
    fun statementDigest() = statementDigest.copyOf()
    fun signatureDigest() = signatureDigest.copyOf()
    fun matches(proof: PreparedSealedLineActivation): Boolean {
        val c = proof.challenge
        return challengeId == c.challengeId && accountId == c.accountId && lineId == c.lineId &&
            deviceId == c.deviceId && generation == c.generation &&
            MessageDigest.isEqual(statementDigest, SealedLineActivationTranscript.digest(proof.statement())) &&
            MessageDigest.isEqual(signatureDigest, SealedLineActivationTranscript.digest(proof.signature()))
    }
    override fun toString() = "SealedLineActivationReceipt(redacted)"
}

/** Injected observations let JVM fixtures exercise races without creating Android credentials. */
internal class SealedLineActivationDevice(private val apiLevel: () -> Int,
    private val selectedSubscriptionId: () -> Int, private val observe: () -> List<ActiveSimCard>?,
    private val existingSignerPoint: () -> ByteArray,
    private val sign: (SealedLineChallenge, Int, Int, ByteArray) -> ByteArray,
    private val nowMs: () -> Long) {
    fun prepare(c: SealedLineChallenge, selection: SealedLineAcceptance): PreparedSealedLineActivation? = try {
        val frozen = c.copy(nonce = c.nonce.copyOf())
        val now = nowMs()
        val api = apiLevel()
        val sim = singleActiveLineCandidate(observe(), selection.subscriptionId)
        val point = if (sim == null) null else existingSignerPoint().copyOf()
        if (now <= 0 || !selection.matches(frozen) || api !in 31..65535 || sim == null || point == null ||
            sim.subscriptionId != selection.subscriptionId || selectedSubscriptionId() != sim.subscriptionId ||
            frozen.expiresAtMs - now !in 1..SealedLineActivationTranscript.CHALLENGE_LIFETIME_MS ||
            !MessageDigest.isEqual(selection.fingerprint(), SealedLineActivationTranscript.digest(point))) null
        else {
            val statement = SealedLineActivationTranscript.deviceStatement(frozen, api, sim.subscriptionId)
            // Public-point lookup can wait; do not sign a count1 assertion after a peer appears.
            check(selectedSubscriptionId() == selection.subscriptionId &&
                singleActiveLineCandidate(observe(), selection.subscriptionId) == sim &&
                selectedSubscriptionId() == selection.subscriptionId)
            val signature = sign(frozen, api, sim.subscriptionId, selection.fingerprint())
            val proof = PreparedSealedLineActivation(frozen, api, sim, statement, signature, selection.fingerprint())
            proof.takeIf { validate(it, selection, false) && MessageDigest.isEqual(point, existingSignerPoint()) &&
                validate(it, selection, false) }
        }
    } catch (_: Exception) { null }
    /** Recovery validates the exact original signature, current hardware/SIM, and bounded ack grace. */
    fun validate(proof: PreparedSealedLineActivation, selection: SealedLineAcceptance,
                 acknowledgement: Boolean): Boolean = try {
        val c = proof.challenge
        val now = nowMs()
        val active = observe()
        val point = if (singleActiveLineCandidate(active, selection.subscriptionId) == null) null
            else existingSignerPoint()
        val end = c.expiresAtMs + if (acknowledgement) SealedLineActivationTranscript.ACK_GRACE_MS else 0
        val valid = point != null && now > 0 && now < end && c.expiresAtMs - now <= SealedLineActivationTranscript.CHALLENGE_LIFETIME_MS &&
            selection.matches(c) && apiLevel() == proof.apiLevel && proof.apiLevel in 31..65535 &&
            selectedSubscriptionId() == selection.subscriptionId && proof.sim.subscriptionId == selection.subscriptionId &&
            singleActiveLineMatches(proof.sim, active) &&
            MessageDigest.isEqual(selection.fingerprint(), proof.fingerprint()) &&
            MessageDigest.isEqual(selection.fingerprint(), SealedLineActivationTranscript.digest(point)) &&
            SealedLineActivationTranscript.verify(point, proof.statement(), proof.signature())
        // Hardware/SIM/verification providers can block. Never use their pre-call clock at publication.
        val stillSelected = valid && selectedSubscriptionId() == selection.subscriptionId &&
            singleActiveLineMatches(proof.sim, observe()) &&
            selectedSubscriptionId() == selection.subscriptionId
        val after = nowMs()
        stillSelected && after >= now && after < end &&
            c.expiresAtMs - after <= SealedLineActivationTranscript.CHALLENGE_LIFETIME_MS
    } catch (_: Exception) { false }
    /** Before Provider reserves a legacy challenge, not just before hardware lookup/signing. */
    fun hasSingleActiveSelection(subscription: Int): Boolean = try {
        selectedSubscriptionId() == subscription && singleActiveLineCandidate(observe(), subscription) != null &&
            selectedSubscriptionId() == subscription
    } catch (_: Exception) { false }
    fun now() = nowMs()
}
