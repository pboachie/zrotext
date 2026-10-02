// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.util.Base64
import java.util.UUID

/**
 * PROPOSED optional device-stream frame `sealed_execution_grant`, grant version 1
 * (roadmap #539; `protocol/v1/device-stream.md`). Ordinary startup never negotiates
 * it; an explicit owner-provisioned candidate lease permits the v2 stream path.
 *
 * [parse] is the strict wire parser used by [SealedDispatchExecutor] and the shared
 * vector corpus: exact key set, integer-typed numbers, canonical UUIDs and unpadded
 * base64url 32-byte digests. Anything else throws, which the caller treats as a
 * protocol rejection of the whole frame; binding refusals are left to
 * [SealedExecutionGrantValidator].
 */
internal object SealedExecutionGrantFrame {
    const val TYPE = "sealed_execution_grant"
    const val REFUSAL_TYPE = "sealed_execution_refusal"
    const val GRANT_VERSION = 1L

    /** Legacy v1 token; the candidate service uses v2 authenticated time sampling instead. */
    const val NEGOTIATION_PROTOCOL = "zrotext-device-status-v2+sealed-dispatch-v1"

    enum class Disposition { IGNORED_NOT_NEGOTIATED }

    /**
     * The live stream handler's only use of this frame: this build never negotiates
     * sealed dispatch, so the frame is dropped without parsing it, touching the
     * journal or the Keystore, or tearing down the session.
     */
    fun dispositionWithoutNegotiation(): Disposition = Disposition.IGNORED_NOT_NEGOTIATED

    private val KEYS = setOf(
        "v", "type", "grant_version", "account_id", "device_id", "line_id", "message_id",
        "attempt_id", "connection_epoch", "deployment_epoch", "binding_generation",
        "attempt_generation", "reader_role", "reader_key_id", "envelope_sha256",
        "unsigned_sha256", "expires_at_ms", "segment_count",
    )

    fun parse(frame: JSONObject): SealedExecutionGrantValidator.Fields {
        check(frame.keys().asSequence().toSet() == KEYS) { "Sealed grant fields" }
        check(integer(frame, "v") == 1L && frame.opt("type") == TYPE) { "Sealed grant type" }
        check(integer(frame, "grant_version") == GRANT_VERSION) { "Sealed grant version" }
        val connectionEpoch = positive(frame, "connection_epoch")
        val deploymentEpoch = positive(frame, "deployment_epoch")
        val bindingGeneration = positive(frame, "binding_generation")
        val attemptGeneration = positive(frame, "attempt_generation")
        val expiresAtMs = positive(frame, "expires_at_ms")
        val readerRole = integer(frame, "reader_role")
        // Wire roles are the profile-02 wrap roles; only role 1 can ever pass validation.
        check(readerRole in 1L..3L) { "Sealed grant reader role" }
        val segmentCount = integer(frame, "segment_count")
        check(segmentCount in 0L..255L) { "Sealed grant segment count" }
        return SealedExecutionGrantValidator.Fields(
            accountId = uuid(frame, "account_id"),
            deviceId = uuid(frame, "device_id"),
            lineId = uuid(frame, "line_id"),
            messageId = uuid(frame, "message_id"),
            attemptId = uuid(frame, "attempt_id"),
            connectionEpoch = connectionEpoch,
            envelopeDigest = digest(frame, "envelope_sha256"),
            expiresAtMs = expiresAtMs,
            segmentCount = segmentCount.toInt(),
            readerRole = readerRole.toInt(),
            readerKeyId = digest(frame, "reader_key_id"),
            deploymentEpoch = deploymentEpoch,
            bindingGeneration = bindingGeneration,
            attemptGeneration = attemptGeneration,
            unsignedDigest = digest(frame, "unsigned_sha256"),
        )
    }

    /**
     * PROPOSED phone-to-hub report of a refused grant. It names only the attempt,
     * the epoch and a fixed reason code: no envelope bytes, digest, key ID or content.
     */
    fun refusal(
        attemptId: UUID,
        connectionEpoch: Long,
        reason: SealedExecutionGrantValidator.Verdict.Refused,
    ): JSONObject = JSONObject()
        .put("v", 1)
        .put("type", REFUSAL_TYPE)
        .put("grant_version", GRANT_VERSION)
        .put("attempt_id", attemptId.toString())
        .put("connection_epoch", connectionEpoch)
        .put("reason", reason.name.lowercase())

    private fun uuid(frame: JSONObject, key: String): UUID {
        val value = frame.opt(key)
        check(value is String && value.length == 36) { "Sealed grant UUID" }
        return UUID.fromString(value).also { check(it.toString() == value) { "Sealed grant UUID" } }
    }

    private fun integer(frame: JSONObject, key: String): Long {
        val value = frame.opt(key)
        check(value is Int || value is Long) { "Sealed grant integer" }
        return (value as Number).toLong()
    }

    private fun positive(frame: JSONObject, key: String): Long =
        integer(frame, key).also { check(it > 0) { "Sealed grant positive integer" } }

    private fun digest(frame: JSONObject, key: String): ByteArray {
        val value = frame.opt(key)
        check(value is String && value.length == 43 && B64URL.matches(value)) { "Sealed grant digest" }
        val bytes = Base64.getUrlDecoder().decode(value)
        check(bytes.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == value) {
            "Sealed grant digest encoding"
        }
        return bytes
    }

    private val B64URL = Regex("[A-Za-z0-9_-]{43}")
}
