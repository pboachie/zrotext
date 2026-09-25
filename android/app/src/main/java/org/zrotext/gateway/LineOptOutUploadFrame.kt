// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.UUID

/** Attempt-free, signed STOP/review metadata. The SMS body never enters this frame. */
internal object LineOptOutUploadFrame {
    private val domain = "zrotext-line-opt-out-v1\u0000".toByteArray(StandardCharsets.US_ASCII)

    fun signedBytes(accountId: UUID, deviceId: UUID, entry: LocalInboundWithdrawal,
                    recipientE164: String): ByteArray {
        val eventId = strictUuid(checkNotNull(entry.eventId))
        val lineId = strictUuid(checkNotNull(entry.lineId))
        val generation = checkNotNull(entry.bindingGeneration)
        val sequence = checkNotNull(entry.deviceSequence)
        require(accountId != UUID(0, 0) && deviceId != UUID(0, 0) &&
            eventId != UUID(0, 0) && lineId != UUID(0, 0) && generation > 0 &&
            sequence > 0 && entry.receivedAtMs > 0)
        val action: Byte = when (entry.classification) {
            InboundClassification.OPT_OUT -> 1
            InboundClassification.OPT_OUT_REVIEW -> 2
            else -> error("Only STOP and review can use the line opt-out contract")
        }
        require(InboundNormalizer.e164(recipientE164) == recipientE164)
        val recipient = recipientE164.toByteArray(StandardCharsets.US_ASCII)
        require(recipient.size in 3..16)
        return ByteBuffer.allocate(domain.size + 16 * 4 + 8 * 3 + 2 + recipient.size)
            .put(domain).putUuid(accountId).putUuid(deviceId).putUuid(lineId)
            .putLong(generation).putUuid(eventId).putLong(sequence)
            .putLong(entry.receivedAtMs).put(action).put(recipient.size.toByte())
            .put(recipient).array()
    }

    fun encode(connectionEpoch: Long, entry: LocalInboundWithdrawal,
               recipientE164: String): String {
        require(connectionEpoch > 0 && InboundNormalizer.e164(recipientE164) == recipientE164)
        require(checkNotNull(entry.deviceSequence) > 0 &&
            checkNotNull(entry.bindingGeneration) > 0 && entry.receivedAtMs > 0)
        val signature = checkNotNull(entry.signatureDer)
        require(signature.size in 8..80)
        val action = when (entry.classification) {
            InboundClassification.OPT_OUT, InboundClassification.OPT_OUT_REVIEW ->
                entry.classification
            else -> error("Invalid line opt-out action")
        }
        val frame = JSONObject().put("v", 1).put("type", "line_opt_out")
            .put("connection_epoch", connectionEpoch)
            .put("event_id", strictUuid(checkNotNull(entry.eventId)).toString())
            .put("sequence", checkNotNull(entry.deviceSequence))
            .put("line_id", strictUuid(checkNotNull(entry.lineId)).toString())
            .put("binding_generation", checkNotNull(entry.bindingGeneration))
            .put("action", action).put("recipient_e164", recipientE164)
            .put("observed_at_ms", entry.receivedAtMs)
            .put("signature_der", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signature))
        return frame.toString().also { require(it.toByteArray(Charsets.UTF_8).size <= 4096) }
    }

    fun ackEventId(frame: JSONObject): String {
        require(frame.keys().asSequence().toSet() == setOf("v", "type", "event_id", "created"))
        require(frame.opt("v") is Number && frame.getInt("v") == 1 &&
            frame.getString("type") == "line_opt_out_ack" && frame.opt("created") is Boolean)
        return strictUuid(frame.getString("event_id")).toString()
    }

    private fun strictUuid(value: String): UUID = UUID.fromString(value).also {
        require(value.length == 36 && it.toString() == value)
    }

    private fun ByteBuffer.putUuid(value: UUID): ByteBuffer =
        putLong(value.mostSignificantBits).putLong(value.leastSignificantBits)
}

/** A changed, missing or ambiguous line observation never authorizes upload. */
internal object LineOptOutUploadGate {
    fun allows(entry: LocalInboundWithdrawal, binding: LocalLineBinding?,
               accountId: UUID, deviceId: UUID, selectedSubscriptionId: Int,
               activeSubscriptionIds: Collection<Int>, nowMs: Long): Boolean {
        if (binding == null || entry.acknowledgedAtMs != null ||
            binding.accountId != accountId.toString() ||
            binding.deviceId != deviceId.toString() ||
            entry.lineId != binding.lineId ||
            entry.bindingGeneration != binding.generation ||
            entry.observedSubscriptionId != binding.subscriptionId ||
            selectedSubscriptionId != binding.subscriptionId ||
            activeSubscriptionIds.size != 1 ||
            activeSubscriptionIds.single() != binding.subscriptionId ||
            entry.encryptedSender == null || entry.senderNonce == null ||
            entry.encryptedSender.size !in 17..128 || entry.senderNonce.size != 12 ||
            entry.eventId == null || entry.deviceSequence == null ||
            entry.deviceSequence <= 0 || entry.receivedAtMs < binding.installedAtMs ||
            entry.receivedAtMs < nowMs - MAX_UPLOAD_AGE_MS ||
            entry.receivedAtMs > nowMs + MAX_FUTURE_MS ||
            entry.classification !in setOf(InboundClassification.OPT_OUT,
                InboundClassification.OPT_OUT_REVIEW)) return false
        return runCatching {
            UUID.fromString(entry.eventId).toString() == entry.eventId &&
                UUID.fromString(binding.lineId).toString() == binding.lineId
        }.getOrDefault(false)
    }

    private const val MAX_UPLOAD_AGE_MS = 6L * 24 * 60 * 60 * 1000
    private const val MAX_FUTURE_MS = 5L * 60 * 1000
}

/** Recover only at upload time and bind the decrypted sender to the capture token. */
internal object LineOptOutSender {
    fun recover(entry: LocalInboundWithdrawal,
                open: (InboundVault.Sealed, String) -> String,
                senderToken: (String) -> String): String? {
        val ciphertext = entry.encryptedSender ?: return null
        val nonce = entry.senderNonce ?: return null
        return try {
            val recipient = open(InboundVault.Sealed(ciphertext, nonce), entry.dedupeToken)
            recipient.takeIf { InboundNormalizer.e164(it) == it &&
                senderToken(it) == entry.senderToken }
        } catch (_: Exception) { null }
    }
}
