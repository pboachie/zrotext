// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject

/** Closed passive management frames. Exact returned bytes are history; a challenge or
 * status alone never mints the private proof-clock context or a signature reservation. */
internal object TypedNoSubmit03Wire {
    data class Predecessor(val challengeId: String, val coreSha256: String, val closedMs: Long, val successorId: String)
    class Challenge(val core: TypedNoSubmit03Core, nonce: ByteArray, val predecessor: Predecessor?) {
        private val nonce = nonce.copyOf()
        fun nonce() = nonce.copyOf()
    }
    class Status(val status: String, val challenge: Challenge?, val acceptedMs: Long?, val signatureSha256: String?)
    fun challengeRequest(row: TypedSubmit03Record, proof: TypedNoSubmit03Proof, epoch: Long): ByteArray {
        proof.requireOriginal(row); require(epoch > 0)
        val closed = TypedNoSubmit03Record.decode(TypedSubmit03Record.unbase(checkNotNull(row.closureB64url)))
        return emit(base("payload_profile_no_submit_challenge03_request", epoch).put("proof_request_id", proof.requestId)
            .put("closure_id", closed.closureId).put("event_id", row.eventId).put("message_id", row.messageId)
            .put("attempt_id", row.attemptId).put("submit_command_sha256", b64(row.command().commitment()))
            .put("fetch_transcript_sha256", b64(row.command().fetchSha256)).put("segment_count", row.command().segmentCount)
            .put("submit_observed_ms", row.command().observedMs.toString()).put("closed_from", if (closed.closedFrom == 0) "reserved" else "ack_authorized")
            .put("closed_ms", closed.closedMs.toString()).put("closure_record_sha256", b64(closed.commitment()))
            .put("previous_challenge_id", proof.previousChallengeId ?: JSONObject.NULL))
    }
    fun proofRequest(proof: TypedNoSubmit03Proof, epoch: Long): ByteArray {
        val challenge = proof.challenge(); val signature = TypedSubmit03Record.unbase(checkNotNull(proof.signatureB64url))
        require(signature.size == 64 && epoch > 0)
        return emit(base("payload_profile_no_submit_proof03", epoch).put("proof_request_id", proof.requestId)
            .put("closure_id", proof.closureId).put("challenge_id", challenge.core.challengeId)
            .put("core", b64(challenge.core.bytes())).put("signature", b64(signature)))
    }
    fun statusRequest(row: TypedSubmit03Record, proof: TypedNoSubmit03Proof, request: String, epoch: Long): ByteArray {
        proof.requireOriginal(row); uuid(request); require(epoch > 0)
        return emit(base("payload_profile_no_submit_status03_request", epoch).put("request_id", request)
            .put("proof_request_id", proof.requestId).put("closure_id", proof.closureId)
            .put("message_id", row.messageId).put("attempt_id", row.attemptId)
            .put("submit_command_sha256", b64(row.command().commitment()))
            .put("closure_record_sha256", b64(TypedNoSubmit03Record.decode(
                TypedSubmit03Record.unbase(checkNotNull(row.closureB64url))).commitment())))
    }
    fun decodeChallenge(raw: ByteArray, row: TypedSubmit03Record, proof: TypedNoSubmit03Proof, epoch: Long): Challenge {
        val f = fields(raw, "payload_profile_no_submit_challenge03", epoch, setOf("proof_request_id", "closure_id", "challenge_id", "core", "nonce", "closed_predecessor"))
        return challenge(f, row, proof)
    }
    private fun challenge(f: Map<String, Any>, row: TypedSubmit03Record, proof: TypedNoSubmit03Proof): Challenge {
        require(f["proof_request_id"] == proof.requestId && f["closure_id"] == proof.closureId)
        val core = TypedNoSubmit03Core.decode(Profile03Json.binary(f, "core", 441, 441))
        val nonce = Profile03Json.binary(f, "nonce", 32, 32)
        core.requireOriginal(row, nonce)
        require(core.proofRequestId == proof.requestId && f["challenge_id"] == core.challengeId)
        val predecessor = if (f["closed_predecessor"] === Profile03Json.Null) null else {
            val p = Profile03Json.nested(f, "closed_predecessor")
            require(p.keys == setOf("challenge_id", "core_sha256", "closed_ms", "superseded_by_challenge_id"))
            Predecessor(uuid(Profile03Json.text(p, "challenge_id")), TypedSubmit03Record.hex(Profile03Json.binary(p, "core_sha256", 32, 32)),
                Profile03Json.decimal(p, "closed_ms"), uuid(Profile03Json.text(p, "superseded_by_challenge_id")))
        }
        require((predecessor == null) == (proof.previousChallengeId == null))
        predecessor?.let { require(it.challengeId == proof.previousChallengeId && it.coreSha256 == proof.previousCoreSha256 &&
            it.successorId == core.challengeId && it.closedMs == core.issuedMs && it.closedMs >= checkNotNull(proof.previousExpiresMs)) }
        return Challenge(core, nonce, predecessor)
    }
    fun decodeStatus(raw: ByteArray, row: TypedSubmit03Record, proof: TypedNoSubmit03Proof, request: String, epoch: Long): Status {
        val f = fields(raw, "payload_profile_no_submit_status03", epoch, setOf("request_id", "proof_request_id", "closure_id", "message_id",
            "attempt_id", "submit_command_sha256", "closure_record_sha256", "status", "challenge", "receipt"))
        require(f["request_id"] == request); original(f, row, proof)
        val state = Profile03Json.text(f, "status"); require(state in setOf("not_found", "challenged", "superseded", "accepted"))
        if (state == "not_found") { require(f["challenge"] === Profile03Json.Null && f["receipt"] === Profile03Json.Null); return Status(state, null, null, null) }
        val nested = Profile03Json.nested(f, "challenge")
        require(nested.keys == setOf("proof_request_id", "closure_id", "challenge_id", "core", "nonce", "closed_predecessor"))
        val challenge = challenge(nested, row, proof)
        proof.coreB64url?.let { require(TypedSubmit03Record.unbase(it).contentEquals(challenge.core.bytes()) &&
            proof.nonceB64url == b64(challenge.nonce())) }
        if (state != "accepted") { require(f["receipt"] === Profile03Json.Null); return Status(state, challenge, null, null) }
        val receipt = Profile03Json.nested(f, "receipt")
        require(receipt.keys == setOf("challenge_id", "core_sha256", "signature_sha256", "accepted_ms", "disposition") &&
            receipt["challenge_id"] == challenge.core.challengeId && receipt["disposition"] == "closed_no_rearm" &&
            Profile03Json.binary(receipt, "core_sha256", 32, 32).contentEquals(challenge.core.sha256()))
        val signatureHash = TypedSubmit03Record.hex(Profile03Json.binary(receipt, "signature_sha256", 32, 32))
        // A server-only signature cannot fill a lost local provider result.
        require(proof.signatureB64url?.let { TypedSubmit03Record.hex(TypedSubmit03Command.sha(TypedSubmit03Record.unbase(it))) } == signatureHash)
        val accepted = Profile03Json.decimal(receipt, "accepted_ms")
        require(accepted in challenge.core.issuedMs until challenge.core.expiresMs)
        return Status(state, challenge, accepted, signatureHash)
    }
    fun decodeAck(raw: ByteArray, row: TypedSubmit03Record, proof: TypedNoSubmit03Proof, epoch: Long): Long {
        val f = fields(raw, "payload_profile_no_submit_ack03", epoch, setOf("proof_request_id", "closure_id", "challenge_id", "message_id",
            "attempt_id", "submit_command_sha256", "closure_record_sha256", "accepted_ms", "disposition"))
        original(f, row, proof)
        require(f["challenge_id"] == proof.challenge().core.challengeId && f["disposition"] == "closed_no_rearm")
        return Profile03Json.decimal(f, "accepted_ms").also { require(it in proof.challenge().core.issuedMs until proof.challenge().core.expiresMs) }
    }
    fun fields(raw: ByteArray, type: String, epoch: Long, extra: Set<String>): Map<String, Any> {
        require(epoch > 0); val f = Profile03Json.noSubmitObject(raw)
        require(f.keys == extra + setOf("v", "type", "connection_epoch") && f["v"] == Profile03Json.Integer(1) &&
            f["type"] == type && f["connection_epoch"] == Profile03Json.Integer(epoch)); return f
    }
    private fun original(f: Map<String, Any>, row: TypedSubmit03Record, proof: TypedNoSubmit03Proof) {
        proof.requireOriginal(row)
        require(f["proof_request_id"] == proof.requestId && f["closure_id"] == proof.closureId && f["message_id"] == row.messageId &&
            f["attempt_id"] == row.attemptId && Profile03Json.binary(f, "submit_command_sha256", 32, 32).contentEquals(row.command().commitment()) &&
            TypedSubmit03Record.hex(Profile03Json.binary(f, "closure_record_sha256", 32, 32)) == row.closureSha256)
    }
    internal fun uuid(value: String) = value.also { require(java.util.UUID.fromString(it).let { id -> id != java.util.UUID(0, 0) && id.toString() == it }) }
    private fun base(type: String, epoch: Long) = JSONObject().put("v", 1).put("type", type).put("connection_epoch", epoch)
    private fun emit(f: JSONObject) = f.toString().toByteArray(Charsets.UTF_8).also { Profile03Json.noSubmitObject(it) }
    private fun b64(raw: ByteArray) = TypedSubmit03Record.base(raw)
}
