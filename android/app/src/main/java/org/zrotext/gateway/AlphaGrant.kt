// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/** Validates the exact private-alpha grant against an authenticated, locally armed phone session. */
internal object AlphaGrantValidator {
    data class Grant(
        val messageId: UUID,
        val attemptId: UUID,
        val deviceId: UUID,
        val generation: Long,
        val connectionEpoch: Long,
        val deploymentEpoch: Long,
        val recipientDigest: String,
        val expiresAtMs: Long,
        val recipientE164: String,
        val body: String,
        val subscriptionId: Int
    )

    fun validate(
        frame: JSONObject,
        authenticatedDeviceId: UUID,
        authenticatedEpoch: Long,
        locallyApprovedRecipient: String,
        selectedSubscriptionId: Int,
        activeSubscriptionIds: Collection<Int>,
        nowMs: Long
    ): Grant {
        check(frame.keys().asSequence().toSet() == setOf(
            "v", "type", "message_id", "attempt_id", "device_id", "generation",
            "connection_epoch", "deployment_epoch", "recipient_digest", "expires_at_ms",
            "recipient_e164", "body"
        ))
        check(integer(frame, "v") == 1L)
        check(frame.getString("type") == "synthetic_grant")
        val messageId = uuid(frame, "message_id")
        val attemptId = uuid(frame, "attempt_id")
        val deviceId = uuid(frame, "device_id")
        check(messageId != ZERO_UUID && attemptId != ZERO_UUID && deviceId == authenticatedDeviceId)
        val generation = integer(frame, "generation")
        val connectionEpoch = integer(frame, "connection_epoch")
        val deploymentEpoch = integer(frame, "deployment_epoch")
        val expiresAtMs = integer(frame, "expires_at_ms")
        check(generation > 0 && connectionEpoch == authenticatedEpoch && deploymentEpoch > 0)
        check(expiresAtMs > nowMs && expiresAtMs - nowMs <= MAX_GRANT_FUTURE_MS)
        val recipient = frame.getString("recipient_e164")
        check(recipient.matches(E164) && recipient == locallyApprovedRecipient)
        check(SimSelection.isActive(selectedSubscriptionId, activeSubscriptionIds))
        val digest = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(recipient.toByteArray(Charsets.UTF_8)))
        check(frame.getString("recipient_digest") == digest)
        val body = frame.getString("body")
        check(body.startsWith(BODY_PREFIX))
        check(body.removePrefix(BODY_PREFIX).matches(CASE_ID))
        return Grant(messageId, attemptId, deviceId, generation, connectionEpoch,
            deploymentEpoch, digest, expiresAtMs, recipient, body, selectedSubscriptionId)
    }

    private fun uuid(frame: JSONObject, key: String): UUID {
        val value = frame.getString(key)
        check(value.length == 36)
        return UUID.fromString(value).also { check(it.toString() == value) }
    }

    private fun integer(frame: JSONObject, key: String): Long {
        val value = frame.opt(key)
        check(value is Int || value is Long)
        return (value as Number).toLong()
    }

    private val E164 = Regex("^\\+[1-9][0-9]{1,14}$")
    private val CASE_ID = Regex("[A-Za-z0-9_-]{1,32}")
    private const val BODY_PREFIX = "ZROtext synthetic test: "
    private const val MAX_GRANT_FUTURE_MS = 35_000L
    private val ZERO_UUID = UUID(0, 0)
}
