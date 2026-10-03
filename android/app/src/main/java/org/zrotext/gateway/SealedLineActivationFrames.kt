// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.util.Base64
import java.util.UUID

/** Strict separate SEALED wire contract. No SMS framing, content consent or radio operation. */
internal object SealedLineActivationFrames {
    data class Ack(val connectionEpoch: Long, val challengeId: UUID, val accepted: Boolean) {
        init { require(connectionEpoch > 0 && challengeId != UUID(0, 0)) }
    }
    sealed class Incoming {
        data class Challenge(val value: SealedLineChallenge) : Incoming()
        data class ProofAck(val value: Ack) : Incoming()
        data class Activated(val value: SealedLineActivationReceipt) : Incoming()
        data class InstallAck(val value: Ack) : Incoming()
    }
    fun incoming(frame: JSONObject): Incoming = when (string(frame, "type")) {
        "sealed_line_challenge" -> Incoming.Challenge(challenge(frame))
        "sealed_line_proof_ack" -> Incoming.ProofAck(proofAck(frame))
        "sealed_line_activated" -> Incoming.Activated(activated(frame))
        "sealed_line_install_ack" -> Incoming.InstallAck(installAck(frame))
        else -> error("Not a SEALED line frame")
    }
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    fun challenge(frame: JSONObject): SealedLineChallenge {
        fields(frame, setOf("v", "type", "connection_epoch", "challenge_id", "account_id", "line_id",
            "device_id", "generation", "nonce", "expires_at_ms"), "sealed_line_challenge")
        return SealedLineChallenge(positive(frame, "connection_epoch"), uuid(frame, "challenge_id"),
            uuid(frame, "account_id"), uuid(frame, "line_id"), uuid(frame, "device_id"),
            positive(frame, "generation"), bytes(frame, "nonce", 32), positive(frame, "expires_at_ms"))
            .also(SealedLineActivationTranscript::validate)
    }
    fun challengeFrame(c: SealedLineChallenge): JSONObject {
        SealedLineActivationTranscript.validate(c)
        return JSONObject().put("v", 1).put("type", "sealed_line_challenge")
            .put("connection_epoch", c.connectionEpoch).put("challenge_id", c.challengeId.toString())
            .put("account_id", c.accountId.toString()).put("line_id", c.lineId.toString())
            .put("device_id", c.deviceId.toString()).put("generation", c.generation)
            .put("nonce", encode(c.nonce)).put("expires_at_ms", c.expiresAtMs)
    }
    fun proof(proof: PreparedSealedLineActivation): String {
        SealedLineActivationTranscript.requireCanonicalDer(proof.signature())
        return bounded(JSONObject().put("v", 1).put("type", "sealed_line_proof")
            .put("connection_epoch", proof.challenge.connectionEpoch)
            .put("challenge_id", proof.challenge.challengeId.toString())
            .put("android_api_level", proof.apiLevel).put("active_subscription_count", 1)
            .put("selected_subscription_id", proof.sim.subscriptionId)
            .put("signature_der", encode(proof.signature())))
    }
    fun proofAck(frame: JSONObject) = ack(frame, "sealed_line_proof_ack")
    fun installAck(frame: JSONObject) = ack(frame, "sealed_line_install_ack")
    private fun ack(frame: JSONObject, type: String): Ack {
        fields(frame, setOf("v", "type", "connection_epoch", "challenge_id", "accepted"), type)
        require(frame.opt("accepted") is Boolean)
        return Ack(positive(frame, "connection_epoch"), uuid(frame, "challenge_id"), frame.getBoolean("accepted"))
    }
    fun activated(frame: JSONObject): SealedLineActivationReceipt {
        fields(frame, setOf("v", "type", "connection_epoch", "challenge_id", "account_id", "line_id",
            "device_id", "generation", "device_statement_sha256", "device_signature_sha256"), "sealed_line_activated")
        return SealedLineActivationReceipt(positive(frame, "connection_epoch"), uuid(frame, "challenge_id"),
            uuid(frame, "account_id"), uuid(frame, "line_id"), uuid(frame, "device_id"), positive(frame, "generation"),
            bytes(frame, "device_statement_sha256", 32), bytes(frame, "device_signature_sha256", 32))
    }
    fun installed(receipt: SealedLineActivationReceipt, currentEpoch: Long): String {
        require(currentEpoch > 0 && receipt.connectionEpoch == currentEpoch)
        return bounded(receiptFrame(receipt, "sealed_line_installed"))
    }
    fun receiptFrame(r: SealedLineActivationReceipt, type: String = "sealed_line_activated"): JSONObject {
        require(type == "sealed_line_activated" || type == "sealed_line_installed")
        return JSONObject().put("v", 1).put("type", type).put("connection_epoch", r.connectionEpoch)
            .put("challenge_id", r.challengeId.toString()).put("account_id", r.accountId.toString())
            .put("line_id", r.lineId.toString()).put("device_id", r.deviceId.toString())
            .put("generation", r.generation).put("device_statement_sha256", encode(r.statementDigest()))
            .put("device_signature_sha256", encode(r.signatureDigest()))
    }
    fun bounded(frame: JSONObject): String = frame.toString().also { require(it.toByteArray(Charsets.UTF_8).size <= 4096) }
    fun fields(frame: JSONObject, expected: Set<String>, type: String? = null) {
        require(frame.keys().asSequence().toSet() == expected &&
            frame.toString().toByteArray(Charsets.UTF_8).size <= 4096)
        if (type != null) require(integer(frame, "v") == 1L && string(frame, "type") == type)
    }
    fun integer(frame: JSONObject, key: String): Long {
        val value = frame.opt(key)
        require(value is Int || value is Long)
        return (value as Number).toLong()
    }
    fun positive(frame: JSONObject, key: String): Long = integer(frame, key).also { require(it > 0) }
    fun string(frame: JSONObject, key: String): String = frame.opt(key).let { require(it is String); it }
    private fun uuid(frame: JSONObject, key: String): UUID {
        val value = string(frame, key)
        require(value.length == 36)
        return UUID.fromString(value).also { require(it != UUID(0, 0) && it.toString() == value) }
    }
    fun encode(bytes: ByteArray) = encoder.encodeToString(bytes)
    fun bytes(frame: JSONObject, key: String, size: Int): ByteArray = variableBytes(frame, key, size, size)
    fun variableBytes(frame: JSONObject, key: String, minimum: Int, maximum: Int): ByteArray {
        val value = string(frame, key)
        require(value.length <= (maximum * 4 + 2) / 3 && value.matches(Regex("[A-Za-z0-9_-]+")))
        return Base64.getUrlDecoder().decode(value).also {
            require(it.size in minimum..maximum && encode(it) == value)
        }
    }
}
