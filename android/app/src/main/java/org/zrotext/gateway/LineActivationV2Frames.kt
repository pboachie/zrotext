// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import java.util.Base64
import java.util.UUID

/** Only the two unused, closed PROOF shapes. All other v2 frame types are refused. */
internal object LineActivationV2Frames {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val keys = setOf("type", "v", "connection_epoch", "challenge_id",
        "observation_b64url", "signature_der")

    /** Parsed declarations are not authenticated proofs or live capabilities. */
    class ProofDeclaration(val purpose: LineActivationV2Purpose, val connectionEpoch: Long,
        val challengeId: UUID, val observation: LineActivationV2Observation, signatureDer: ByteArray) {
        private val signature = signatureDer.copyOf()
        init {
            require(connectionEpoch > 0 && challengeId != UUID(0, 0))
            SealedLineActivationTranscript.requireCanonicalDer(signature)
        }
        fun signatureDer() = signature.copyOf()
        override fun toString() = "LineActivationV2ProofDeclaration(redacted)"
    }
    fun proof(value: ProofDeclaration): String = JSONObject()
        .put("type", value.purpose.proofType()).put("v", 2)
        .put("connection_epoch", value.connectionEpoch.toString())
        .put("challenge_id", value.challengeId.toString())
        .put("observation_b64url", encoder.encodeToString(value.observation.bytes()))
        .put("signature_der", encoder.encodeToString(value.signatureDer()))
        .toString().also { require(it.toByteArray(Charsets.UTF_8).size <= 4096) }

    fun parseProof(frame: JSONObject, expectedPurpose: LineActivationV2Purpose): ProofDeclaration {
        require(frame.toString().toByteArray(Charsets.UTF_8).size <= 4096 &&
            frame.keys().asSequence().toSet() == keys)
        val version = frame.opt("v")
        require((version is Int || version is Long) && (version as Number).toLong() == 2L &&
            string(frame, "type") == expectedPurpose.proofType())
        val epoch = positiveDecimal(string(frame, "connection_epoch"))
        val idText = string(frame, "challenge_id")
        require(idText.length == 36)
        val id = UUID.fromString(idText)
        require(id != UUID(0, 0) && id.toString() == idText)
        return ProofDeclaration(expectedPurpose, epoch, id,
            LineActivationV2Observation.decode(bytes(frame, "observation_b64url", 121, 121)),
            bytes(frame, "signature_der", 8, 80))
    }
    fun positiveDecimal(value: String): Long {
        require(value.length in 1..19 && value.matches(Regex("[1-9][0-9]*")))
        return value.toLongOrNull()?.also { require(it > 0) }
            ?: throw IllegalArgumentException("Invalid positive decimal")
    }
    private fun string(frame: JSONObject, key: String): String {
        val value = frame.opt(key)
        require(value is String)
        return value
    }
    private fun bytes(frame: JSONObject, key: String, minimum: Int, maximum: Int): ByteArray {
        val value = string(frame, key)
        require(value.length in 1..((maximum * 4 + 2) / 3) &&
            value.matches(Regex("[A-Za-z0-9_-]+")))
        return Base64.getUrlDecoder().decode(value).also {
            require(it.size in minimum..maximum && encoder.encodeToString(it) == value)
        }
    }
}
