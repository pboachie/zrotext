// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import org.json.JSONObject

/** The existing device-signed fetch contract; no bearer, payload or identity is placed in a URL. */
internal object SealedEnvelopeFetch {
    fun snapshot(value: SealedExecutionGrantValidator.Fields) = value.copy(
        envelopeDigest = value.envelopeDigest.copyOf(), readerKeyId = value.readerKeyId.copyOf(),
        unsignedDigest = value.unsignedDigest.copyOf())

    fun frame(value: SealedExecutionGrantValidator.Fields): JSONObject {
        val encode = Base64.getUrlEncoder().withoutPadding()
        return JSONObject().put("v", 1).put("type", SealedExecutionGrantFrame.TYPE).put("grant_version", 1)
            .put("account_id", value.accountId.toString()).put("device_id", value.deviceId.toString())
            .put("line_id", value.lineId.toString()).put("message_id", value.messageId.toString())
            .put("attempt_id", value.attemptId.toString()).put("connection_epoch", value.connectionEpoch)
            .put("deployment_epoch", value.deploymentEpoch).put("binding_generation", value.bindingGeneration)
            .put("attempt_generation", value.attemptGeneration).put("reader_role", value.readerRole)
            .put("reader_key_id", encode.encodeToString(value.readerKeyId))
            .put("envelope_sha256", encode.encodeToString(value.envelopeDigest))
            .put("unsigned_sha256", encode.encodeToString(value.unsignedDigest))
            .put("expires_at_ms", value.expiresAtMs).put("segment_count", value.segmentCount)
    }

    fun transcript(value: SealedExecutionGrantValidator.Fields): ByteArray {
        val owned = snapshot(value)
        SealedExecutionGrantFrame.parse(frame(owned))
        require(owned.readerRole == 1 && owned.segmentCount in 1..6)
        val output = ByteArrayOutputStream()
        output.write("ZT/sealed-envelope-fetch/v1\u0000".toByteArray(Charsets.US_ASCII))
        output.write(byteArrayOf(1, 1, 1, owned.segmentCount.toByte()))
        for (id in listOf(owned.accountId, owned.deviceId, owned.lineId, owned.messageId, owned.attemptId)) {
            require(id != UUID(0, 0))
            output.write(ByteBuffer.allocate(16).putLong(id.mostSignificantBits).putLong(id.leastSignificantBits).array())
        }
        for (number in listOf(owned.connectionEpoch, owned.deploymentEpoch, owned.bindingGeneration,
            owned.attemptGeneration, owned.expiresAtMs)) {
            require(number > 0)
            output.write(ByteBuffer.allocate(8).putLong(number).array())
        }
        for (digest in listOf(owned.readerKeyId, owned.envelopeDigest, owned.unsignedDigest)) {
            require(digest.size == 32)
            output.write(digest)
        }
        return output.toByteArray()
    }
}
