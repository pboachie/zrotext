// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.util.Base64
import java.util.UUID

/**
 * Strict v1 device-stream frames for owner-approved SMS line activation. See
 * protocol/v1/sms-line-activation-contract.md. None of them authorizes an SMS.
 */
internal object SmsLineActivationFrames {
    data class ProofAck(val challengeId: UUID, val accepted: Boolean)

    fun challenge(frame: JSONObject): SmsLineChallenge {
        requireFields(frame, setOf("v", "type", "challenge_id", "account_id", "line_id",
            "device_id", "generation", "nonce", "expires_at_ms"), "sms_line_challenge")
        val generation = long(frame, "generation")
        val expiresAtMs = long(frame, "expires_at_ms")
        require(generation > 0 && expiresAtMs > 0)
        return SmsLineChallenge(uuid(frame, "challenge_id"), uuid(frame, "account_id"),
            uuid(frame, "line_id"), uuid(frame, "device_id"), generation,
            bytes(frame, "nonce", 32), expiresAtMs)
    }

    fun proof(connectionEpoch: Long, proof: PreparedSmsLineActivation): String {
        val signature = proof.deviceSignatureDer()
        require(connectionEpoch > 0 && signature.size in 8..80 &&
            proof.apiLevel in 28..65535 && proof.selectedSubscriptionId >= 0)
        return JSONObject().put("v", 1).put("type", "sms_line_proof")
            .put("connection_epoch", connectionEpoch)
            .put("challenge_id", proof.challenge.challengeId.toString())
            .put("android_api_level", proof.apiLevel)
            .put("active_subscription_count", 1)
            .put("selected_subscription_id", proof.selectedSubscriptionId)
            .put("signature_der", encoder.encodeToString(signature))
            .toString().also { require(it.toByteArray(Charsets.UTF_8).size <= 4096) }
    }

    fun proofAck(frame: JSONObject): ProofAck {
        requireFields(frame, setOf("v", "type", "challenge_id", "accepted"), "sms_line_proof_ack")
        require(frame.opt("accepted") is Boolean)
        return ProofAck(uuid(frame, "challenge_id"), frame.getBoolean("accepted"))
    }

    /** Built only from an authenticated stream frame; the caller checks the session. */
    fun activated(frame: JSONObject): AuthenticatedSmsLineActivationAck {
        requireFields(frame, setOf("v", "type", "challenge_id", "account_id", "line_id",
            "device_id", "generation", "device_statement_sha256", "device_signature_sha256"),
            "sms_line_activated")
        val generation = long(frame, "generation")
        require(generation > 0)
        return AuthenticatedSmsLineActivationAck.fromActivatedFrame(uuid(frame, "challenge_id"),
            uuid(frame, "account_id"), uuid(frame, "line_id"), uuid(frame, "device_id"),
            generation, bytes(frame, "device_statement_sha256", 32),
            bytes(frame, "device_signature_sha256", 32))
    }

    private val encoder = Base64.getUrlEncoder().withoutPadding()

    private fun requireFields(frame: JSONObject, expected: Set<String>, type: String) {
        require(frame.keys().asSequence().toSet() == expected)
        require(frame.opt("v") is Number && frame.getInt("v") == 1 && frame.getString("type") == type)
    }

    private fun long(frame: JSONObject, key: String): Long {
        val value = frame.opt(key)
        require(value is Int || value is Long)
        return (value as Number).toLong()
    }

    private fun uuid(frame: JSONObject, key: String): UUID {
        val value = frame.getString(key)
        require(value.length == 36)
        return UUID.fromString(value).also { require(it.toString() == value && it != UUID(0, 0)) }
    }

    private fun bytes(frame: JSONObject, key: String, size: Int): ByteArray {
        val value = frame.getString(key)
        require(value.matches(Regex("[A-Za-z0-9_-]+")))
        val decoded = Base64.getUrlDecoder().decode(value)
        require(decoded.size == size && encoder.encodeToString(decoded) == value)
        return decoded
    }
}
