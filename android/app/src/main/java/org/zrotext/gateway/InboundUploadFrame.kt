// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/** M1 pilot metadata only. The phone vault ciphertext and SMS text never enter this frame. */
internal object InboundUploadFrame {
    private val prefix = "zrotext-inbound-v1\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val emptyDigest = MessageDigest.getInstance("SHA-256").digest(ByteArray(0))

    fun signedBytes(accountId: UUID, deviceId: UUID, upload: InboundUpload,
                    event: InboundEvent): ByteArray {
        require(upload.sequence > 0 && upload.eventId == event.eventId)
        require(event.classification == InboundClassification.CAPTURED_LOCAL)
        require(event.partCount in 1..6 && event.receivedAtMs > 0)
        val bytes = ByteBuffer.allocate(prefix.size + 16 * 5 + 8 + 1 + 8 + 2 + 1 + 32)
        bytes.put(prefix).putUuid(accountId).putUuid(deviceId)
            .putUuid(strictUuid(event.eventId)).putLong(upload.sequence)
            .putUuid(strictUuid(event.messageId)).putUuid(strictUuid(event.attemptId))
            .put(1.toByte()).putLong(event.receivedAtMs).putShort(event.partCount.toShort())
            .put(0.toByte()).put(emptyDigest)
        return bytes.array()
    }

    fun encode(epoch: Long, upload: InboundUpload, event: InboundEvent): String {
        require(epoch > 0 && upload.eventId == event.eventId)
        val signature = checkNotNull(upload.signatureDer)
        require(signature.size in 8..80)
        val frame = JSONObject().put("v", 1).put("type", "inbound_event")
            .put("connection_epoch", epoch).put("event_id", event.eventId)
            .put("sequence", upload.sequence).put("message_id", event.messageId)
            .put("attempt_id", event.attemptId).put("classification", event.classification)
            .put("observed_at_ms", event.receivedAtMs).put("part_count", event.partCount)
            .put("signature_der", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(signature))
        return frame.toString().also { require(it.toByteArray(Charsets.UTF_8).size <= 4096) }
    }

    private fun strictUuid(value: String): UUID = UUID.fromString(value).also {
        require(value.length == 36 && it.toString() == value)
    }

    private fun ByteBuffer.putUuid(value: UUID): ByteBuffer =
        putLong(value.mostSignificantBits).putLong(value.leastSignificantBits)
}
