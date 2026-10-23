// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Separate passive history grammar. None of these public projections is a current/send,
 * setup-signing or physical-selection proof; existing session/current parsers stay strict. */
internal object TypedHistory03Wire {
    data class Query(val requestId: String, val messageId: String, val attemptId: String) {
        init { for (id in listOf(requestId, messageId, attemptId)) canonicalUuid(id) }
    }
    class Reply internal constructor(val serverMs: Long, val sampleExpiresMs: Long,
        val leaseExpiresMs: Long, val deploymentEpoch: Long, val site: String, val instance: String,
        sessionDigest: ByteArray) {
        private val session = sessionDigest.copyOf()
        fun sessionDigest() = session.copyOf()
        override fun toString() = "TypedHistory03Reply(passive-clock-candidate)"
    }

    fun request(epoch: Long, query: Query): ByteArray {
        require(epoch > 0)
        return Profile03Json.render(linkedMapOf("v" to Profile03Json.Integer(1),
            "type" to "payload_profile_history_clock03_request", "connection_epoch" to Profile03Json.Integer(epoch),
            "request_id" to query.requestId, "message_id" to query.messageId, "attempt_id" to query.attemptId))
            .also { require(it.size <= 4096) }
    }

    fun decode(raw: ByteArray, query: Query, account: String, device: String,
        epoch: Long, actualLineVersion: Int, originalHandshakePoint: ByteArray): Reply {
        canonicalUuid(account); canonicalUuid(device)
        require(epoch > 0 && actualLineVersion in 1..2 && raw.size <= Profile03Json.MAX_BYTES)
        val fields = Profile03Json.objectValue(raw)
        require(fields.keys == setOf("v", "type", "connection_epoch", "request_id", "message_id", "attempt_id",
            "account_id", "device_id", "server_time_ms", "sample_expires_ms", "lease") &&
            fields["v"] == Profile03Json.Integer(1) && fields["type"] == "payload_profile_history_clock03" &&
            fields["connection_epoch"] == Profile03Json.Integer(epoch))
        require(listOf("request_id", "message_id", "attempt_id", "account_id", "device_id", "server_time_ms",
            "sample_expires_ms").all { fields[it] is String } && fields["lease"] is Map<*, *>)
        for ((name, expected) in listOf("request_id" to query.requestId, "message_id" to query.messageId,
                "attempt_id" to query.attemptId, "account_id" to account, "device_id" to device))
            require(Profile03Json.text(fields, name) == expected)
        val lease = Profile03Json.nested(fields, "lease")
        require(lease.keys == setOf("site_id", "instance_id", "deployment_epoch", "line_activation_version",
            "enrolled_signing_key_id", "device_session_digest", "expires_ms") &&
            lease["line_activation_version"] == Profile03Json.Integer(actualLineVersion.toLong()))
        require(listOf("site_id", "instance_id", "deployment_epoch", "enrolled_signing_key_id",
            "device_session_digest", "expires_ms").all { lease[it] is String })
        val site = Profile03Json.text(lease, "site_id").also { textBytes(it) }
        val instance = Profile03Json.text(lease, "instance_id").also { textBytes(it) }
        val deployment = Profile03Json.decimal(lease, "deployment_epoch")
        val keyId = ProtectionOriginProof.signingKeyId(originalHandshakePoint)
        require(MessageDigest.isEqual(Profile03Json.binary(lease, "enrolled_signing_key_id", 32, 32), keyId))
        val session = deviceSession(account, device, site, instance, epoch, deployment, actualLineVersion, keyId)
        require(MessageDigest.isEqual(Profile03Json.binary(lease, "device_session_digest", 32, 32), session))
        val primary = Profile03Json.decimal(fields, "server_time_ms")
        val expires = Profile03Json.decimal(fields, "sample_expires_ms")
        val leaseExpires = Profile03Json.decimal(lease, "expires_ms")
        require(primary < leaseExpires && expires == minOf(Math.addExact(primary, 30_000), leaseExpires))
        return Reply(primary, expires, leaseExpires, deployment, site, instance, session)
    }

    private fun deviceSession(account: String, device: String, site: String, instance: String,
        epoch: Long, deployment: Long, version: Int, keyId: ByteArray): ByteArray {
        val payload = ReviewedIntent03.uuid(UUID.fromString(account)) + ReviewedIntent03.uuid(UUID.fromString(device)) +
            textBytes(site) + textBytes(instance) + ByteBuffer.allocate(18).putLong(epoch).putLong(deployment)
                .putShort(version.toShort()).array() + keyId
        return TypedSubmit03Command.sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/device-session/v1", payload))
    }
    private fun textBytes(value: String): ByteArray {
        val encoded = Charsets.UTF_8.newEncoder().encode(java.nio.CharBuffer.wrap(value))
        val raw = ByteArray(encoded.remaining()).also(encoded::get)
        require(raw.size in 1..256 && value.none { it.isISOControl() })
        return ByteBuffer.allocate(4).putInt(raw.size).array() + raw
    }
    private fun canonicalUuid(value: String) {
        val id = UUID.fromString(value)
        require(id != UUID(0, 0) && id.toString() == value)
    }
}
