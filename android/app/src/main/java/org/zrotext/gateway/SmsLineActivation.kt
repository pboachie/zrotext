// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Build
import android.telephony.SubscriptionManager
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Supplied by a future authenticated owner challenge route; no route invokes this today. */
internal data class SmsLineChallenge(
    val challengeId: UUID,
    val accountId: UUID,
    val lineId: UUID,
    val deviceId: UUID,
    val generation: Long,
    val nonce: ByteArray,
    val expiresAtMs: Long
)

/** Exact v1 bytes shared with protocol/v1/sms-line-activation-contract.md. */
internal object SmsLineActivationTranscript {
    private val deviceDomain = "ZTSMS/line/device-confirm/v1\u0000".toByteArray(Charsets.US_ASCII)
    private val ownerDomain = "ZTSMS/line/owner-approve/v1\u0000".toByteArray(Charsets.US_ASCII)
    private val zeroUuid = UUID(0, 0)
    private const val STATEMENT_FIELDS_BYTES = 16 * 4 + 8 + 32 + 2 + 1 + 4

    fun deviceStatement(challenge: SmsLineChallenge, apiLevel: Int,
                        selectedSubscriptionId: Int): ByteArray {
        require(challenge.accountId != zeroUuid && challenge.lineId != zeroUuid &&
            challenge.deviceId != zeroUuid && challenge.challengeId != zeroUuid &&
            challenge.generation > 0 && challenge.nonce.size == 32 &&
            apiLevel in 28..65535 && selectedSubscriptionId >= 0)
        return ByteBuffer.allocate(deviceDomain.size + STATEMENT_FIELDS_BYTES)
            .put(deviceDomain).putUuid(challenge.accountId).putUuid(challenge.lineId)
            .putUuid(challenge.deviceId).putLong(challenge.generation)
            .putUuid(challenge.challengeId).put(challenge.nonce)
            .putShort(apiLevel.toShort()).put(1.toByte()).putInt(selectedSubscriptionId)
            .array()
    }

    fun ownerStatement(deviceStatement: ByteArray, deviceSignatureDer: ByteArray): ByteArray {
        require(deviceStatement.size == deviceDomain.size + STATEMENT_FIELDS_BYTES &&
            deviceStatement.copyOfRange(0, deviceDomain.size).contentEquals(deviceDomain) &&
            deviceSignatureDer.size in 8..80)
        return ownerDomain + deviceStatement + MessageDigest.getInstance("SHA-256")
            .digest(deviceSignatureDer)
    }

    private fun ByteBuffer.putUuid(value: UUID): ByteBuffer =
        putLong(value.mostSignificantBits).putLong(value.leastSignificantBits)
}

/** In-memory only. The local card ID is deliberately absent from the signed wire statement. */
internal class PreparedSmsLineActivation internal constructor(
    challenge: SmsLineChallenge,
    val apiLevel: Int,
    val selectedSubscriptionId: Int,
    val sim: ActivatedSimCard,
    val simAfterSigning: ActivatedSimCard,
    statement: ByteArray,
    signatureDer: ByteArray
) {
    private val frozenChallenge = challenge.copy(nonce = challenge.nonce.copyOf())
    val challenge: SmsLineChallenge get() = frozenChallenge.copy(nonce = frozenChallenge.nonce.copyOf())
    private val statementBytes = statement.copyOf()
    private val signatureBytes = signatureDer.copyOf()
    fun deviceStatement(): ByteArray = statementBytes.copyOf()
    fun deviceSignatureDer(): ByteArray = signatureBytes.copyOf()
    fun ownerStatement(): ByteArray = SmsLineActivationTranscript.ownerStatement(
        statementBytes, signatureBytes)
}

/** No runtime factory exists until an authenticated server confirmation route is implemented. */
internal class AuthenticatedSmsLineActivationAck private constructor(
    val accepted: Boolean,
    val challengeId: UUID,
    val accountId: UUID,
    val lineId: UUID,
    val deviceId: UUID,
    val generation: Long,
    deviceStatementSha256: ByteArray,
    deviceSignatureSha256: ByteArray
) {
    private val statementDigest = deviceStatementSha256.copyOf()
    private val signatureDigest = deviceSignatureSha256.copyOf()

    fun matches(proof: PreparedSmsLineActivation): Boolean {
        val challenge = proof.challenge
        return accepted && challengeId == challenge.challengeId &&
            accountId == challenge.accountId && lineId == challenge.lineId &&
            deviceId == challenge.deviceId && generation == challenge.generation &&
            MessageDigest.isEqual(statementDigest, sha256(proof.deviceStatement())) &&
            MessageDigest.isEqual(signatureDigest, sha256(proof.deviceSignatureDer()))
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)
}

/** No UI, HTTP, or device-stream handler currently calls this dormant proof/installation path. */
internal class SmsLineActivationDevice(
    private val apiLevel: () -> Int,
    private val selectedSubscriptionId: () -> Int,
    private val observe: () -> List<ActiveSimCard>?,
    private val sign: (SmsLineChallenge, Int, Int) -> ByteArray,
    private val nowMs: () -> Long
) {
    fun prepare(challenge: SmsLineChallenge, authenticatedAccountId: UUID,
                authenticatedDeviceId: UUID): PreparedSmsLineActivation? = try {
        val now = nowMs()
        val frozen = challenge.copy(nonce = challenge.nonce.copyOf())
        val api = apiLevel()
        val selected = selectedSubscriptionId()
        val initial = observe()
        val sim = SimCardContinuity.activationCandidate(initial)
        if (api < 29 || sim == null || sim.subscriptionId != selected ||
            frozen.accountId != authenticatedAccountId ||
            frozen.deviceId != authenticatedDeviceId ||
            frozen.expiresAtMs - now !in 1..CHALLENGE_LIFETIME_MS) null
        else {
            val statement = SmsLineActivationTranscript.deviceStatement(frozen, api, selected)
            val signature = sign(frozen, api, selected)
            val afterSigning = SimCardContinuity.activationCandidate(observe())
            if (signature.size !in 8..80 || nowMs() >= frozen.expiresAtMs ||
                selectedSubscriptionId() != selected || afterSigning != sim) null
            else PreparedSmsLineActivation(frozen, api, selected, sim,
                afterSigning, statement, signature)
        }
    } catch (_: Exception) { null }

    /** The caller must authenticate the ack and session; this checks its exact proof binding. */
    fun installAfterAuthenticatedAck(dao: SmsAttemptDao, proof: PreparedSmsLineActivation,
                                     ack: AuthenticatedSmsLineActivationAck,
                                     authenticatedAccountId: UUID,
                                     authenticatedDeviceId: UUID): Boolean = try {
        val challenge = proof.challenge
        val now = nowMs()
        val active = observe()
        if (!ack.matches(proof) || now <= 0 || now >= challenge.expiresAtMs ||
            challenge.expiresAtMs - now > CHALLENGE_LIFETIME_MS ||
            apiLevel() != proof.apiLevel || proof.apiLevel < 29 ||
            selectedSubscriptionId() != proof.selectedSubscriptionId ||
            authenticatedAccountId != challenge.accountId ||
            authenticatedDeviceId != challenge.deviceId ||
            proof.simAfterSigning != proof.sim ||
            !SimCardContinuity.matches(proof.sim, active)) false
        else dao.installVerifiedLineBinding(LocalLineBinding(accountId =
            challenge.accountId.toString(), deviceId = challenge.deviceId.toString(),
            lineId = challenge.lineId.toString(), generation = challenge.generation,
            subscriptionId = proof.selectedSubscriptionId, installedAtMs = now,
            cardId = proof.sim.cardId), active)
    } catch (_: Exception) { false }

    companion object {
        private val CHALLENGE_LIFETIME_MS = TimeUnit.MINUTES.toMillis(5)

        fun forGateway(context: Context, keys: DeviceSigningKeyStore): SmsLineActivationDevice =
            SmsLineActivationDevice(
                apiLevel = { Build.VERSION.SDK_INT },
                selectedSubscriptionId = {
                    context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                        .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
                },
                observe = { SimCardContinuity.observe(context) },
                sign = keys::signSmsLineActivation,
                nowMs = System::currentTimeMillis
            )

    }
}
