// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID

/** Closed ordinary-authenticated control candidates. The actual socket owner must supply its
 * retained identity, original command, existing enrolled point and pending request correlation.
 * A decoded reply is not a fresh-clock, accepted-origin or provider-call capability. */
internal object ProtectionOriginWire {
    class Opening internal constructor(private val exact: Map<String, Any>) {
        val sourcePairingId get() = uuid(exact, "source_pairing_id")
        val nonce get() = binary(exact, "opening_nonce", 32)
        val enrolledPoint get() = binary(exact, "enrolled_point", 65)
        val createdMs get() = decimal(exact, "created_ms")
        fun bytes() = ProtectionOriginJson.render(exact)
        override fun toString() = "ProtectionOriginOpening(candidate)"
    }
    class Predecessor internal constructor(val proofRequestId: UUID, val attemptId: UUID,
        private val core: ByteArray, private val bundle: ByteArray?, val closedMs: Long) {
        fun coreSha256() = core.copyOf()
        fun bundleSha256() = bundle?.copyOf()
        override fun toString() = "ProtectionOriginPredecessor(candidate)"
    }
    class PreviousRequest(val attemptId: UUID, coreSha256: ByteArray, bundleSha256: ByteArray?) {
        private val core = coreSha256.copyOf().also { require(it.size == 32) }
        private val bundle = bundleSha256?.copyOf()?.also { require(it.size == 32) }
        fun coreSha256() = core.copyOf()
        fun bundleSha256() = bundle?.copyOf()
    }
    class Challenge internal constructor(val proofRequestId: UUID, val core: ProtectionOriginProof.Core,
        private val originalNonce: ByteArray, val predecessor: Predecessor?) {
        val attemptId get() = core.attemptId
        fun nonce() = originalNonce.copyOf()
        override fun toString() = "ProtectionOriginChallenge(candidate)"
    }
    class Receipt internal constructor(private val association: ByteArray, private val core: ByteArray,
        private val bundle: ByteArray, val acceptedMs: Long) {
        fun requireMatches(proof: ProtectionOriginProof.Bundle) {
            require(same(association, proof.core.association.sha256()) && same(core, proof.core.sha256()) &&
                same(bundle, proof.sha256()))
            proof.core.requireAcceptedTime(acceptedMs)
        }
        fun fields(): Map<String, Any> = linkedMapOf("association_sha256" to encode(association),
            "core_sha256" to encode(core), "bundle_sha256" to encode(bundle), "accepted_ms" to acceptedMs.toString())
        override fun toString() = "ProtectionOriginReceipt(candidate)"
    }
    sealed interface Reply
    class Opened(val opening: Opening) : Reply
    class ProofChallenge(val challenge: Challenge) : Reply
    class Accepted(val proofRequestId: UUID, val attemptId: UUID, val receipt: Receipt) : Reply
    class Status(val requestId: UUID, val proofRequestId: UUID?, val state: String,
        val opening: Opening?, val challenge: Challenge?, val receipt: Receipt?) : Reply

    fun open(command: ProtectionSetupCommand, epoch: Long) = request("protection_origin_open", command, epoch)
    fun status(command: ProtectionSetupCommand, epoch: Long, requestId: UUID, proofRequestId: UUID?): ByteArray =
        request("protection_origin_status_request", command, epoch, linkedMapOf(
            "request_id" to nonzero(requestId).toString(), "proof_request_id" to nullable(proofRequestId)))
    fun proofOpen(command: ProtectionSetupCommand, epoch: Long, proofRequestId: UUID,
        association: ProtectionOriginProof.Association, aesProbe: ByteArray, previous: PreviousRequest?): ByteArray {
        association.requireOriginal(command)
        require(aesProbe.size == 120)
        return request("protection_origin_proof_open", command, epoch, linkedMapOf(
            "proof_request_id" to nonzero(proofRequestId).toString(), "association" to encode(association.bytes()),
            "aes_probe" to encode(aesProbe.copyOf()), "previous_attempt_id" to nullable(previous?.attemptId),
            "previous_core_sha256" to nullable(previous?.coreSha256()),
            "previous_bundle_sha256" to nullable(previous?.bundleSha256())))
    }
    fun proof(command: ProtectionSetupCommand, epoch: Long, proofRequestId: UUID,
        bundle: ProtectionOriginProof.Bundle): ByteArray {
        bundle.core.association.requireOriginal(command)
        return request("protection_origin_proof", command, epoch, linkedMapOf(
            "proof_request_id" to nonzero(proofRequestId).toString(), "attempt_id" to bundle.core.attemptId.toString(),
            "bundle" to encode(bundle.bytes())))
    }
    private fun request(type: String, command: ProtectionSetupCommand, epoch: Long,
        extra: Map<String, Any> = emptyMap()): ByteArray {
        command.requireShape(); require(epoch > 0)
        return ProtectionOriginJson.render(linkedMapOf<String, Any>("v" to ProtectionOriginJson.Integer(1),
            "type" to type, "connection_epoch" to ProtectionOriginJson.Integer(epoch), "setup_id" to command.setupId,
            "opening_id" to command.openingId, "command_id" to command.commandId).also { it.putAll(extra) })
    }

    fun decode(input: ByteArray, command: ProtectionSetupCommand, actualEpoch: Long,
        actualEnrolledPoint: ByteArray, association: ProtectionOriginProof.Association? = null): Reply {
        command.requireShape(); require(actualEpoch > 0)
        val point = actualEnrolledPoint.copyOf()
        require(hex(ProtectionOriginProof.signingKeyId(point)) == command.enrolledSigningKeyId)
        val fields = ProtectionOriginJson.objectValue(input)
        require(fields["v"] == ProtectionOriginJson.Integer(1) &&
            fields["connection_epoch"] == ProtectionOriginJson.Integer(actualEpoch))
        require(text(fields, "setup_id") == command.setupId && text(fields, "opening_id") == command.openingId &&
            text(fields, "command_id") == command.commandId)
        return when (text(fields, "type")) {
            "protection_origin_opened" -> {
                closed(fields, common + "opening")
                Opened(opening(nested(fields, "opening"), command, point))
            }
            "protection_origin_proof_challenge" -> {
                closed(fields, common + setOf("proof_request_id", "attempt_id", "core", "nonce", "closed_predecessor"))
                ProofChallenge(challenge(fields.filterKeys { it !in common }, command, checkNotNull(association)))
            }
            "protection_origin_accepted" -> {
                closed(fields, common + setOf("proof_request_id", "attempt_id", "receipt"))
                Accepted(uuid(fields, "proof_request_id"), uuid(fields, "attempt_id"), receipt(nested(fields, "receipt")))
            }
            "protection_origin_status" -> {
                closed(fields, common + setOf("request_id", "proof_request_id", "status", "opening", "challenge", "receipt"))
                val request = uuid(fields, "request_id"); val proofRequest = nullableUuid(fields, "proof_request_id")
                val state = text(fields, "status")
                val open = optionalNested(fields, "opening")?.let { opening(it, command, point) }
                val challenged = optionalNested(fields, "challenge")?.let { challenge(it, command, checkNotNull(association)) }
                val accepted = optionalNested(fields, "receipt")?.let(::receipt)
                when (state) {
                    "not_found" -> require(open == null && challenged == null && accepted == null)
                    "opened" -> require(proofRequest == null && open != null && challenged == null && accepted == null)
                    "challenged", "superseded" -> require(proofRequest != null && open != null && challenged != null && accepted == null)
                    "accepted" -> require(proofRequest != null && open != null && challenged != null && accepted != null)
                    else -> error("Unsupported protection status")
                }
                require(challenged == null || challenged.proofRequestId == proofRequest)
                Status(request, proofRequest, state, open, challenged, accepted)
            }
            else -> error("Unsupported protection control reply")
        }
    }
    fun retainedOpening(input: ByteArray, command: ProtectionSetupCommand, actualEnrolledPoint: ByteArray): Opening =
        opening(ProtectionOriginJson.objectValue(input), command, actualEnrolledPoint.copyOf())
    fun retainedReceipt(input: ByteArray): Receipt = receipt(ProtectionOriginJson.objectValue(input))

    private fun opening(fields: Map<String, Any>, command: ProtectionSetupCommand, point: ByteArray): Opening {
        closed(fields, openingKeys)
        require(uuid(fields, "account_id").toString() == command.accountId &&
            uuid(fields, "device_id").toString() == command.deviceId)
        uuid(fields, "source_pairing_id")
        require(hex(binary(fields, "origin_digest", 32)) == command.originSha256 &&
            hex(binary(fields, "enrolled_key_id", 32)) == command.enrolledSigningKeyId &&
            same(binary(fields, "enrolled_key_id", 32), ProtectionOriginProof.signingKeyId(point)) &&
            same(binary(fields, "enrolled_point", 65), point))
        binary(fields, "opening_nonce", 32)
        val created = decimal(fields, "created_ms"); val paired = decimal(fields, "pairing_created_ms")
        val claimed = decimal(fields, "pairing_claimed_ms"); val approved = decimal(fields, "pairing_approved_ms")
        val expires = decimal(fields, "pairing_expires_ms")
        require(paired <= claimed && claimed <= approved && approved < expires && created >= approved)
        return Opening(openingKeys.associateWith { fields.getValue(it) })
    }
    private fun challenge(fields: Map<String, Any>, command: ProtectionSetupCommand,
        expected: ProtectionOriginProof.Association): Challenge {
        closed(fields, setOf("proof_request_id", "attempt_id", "core", "nonce", "closed_predecessor"))
        expected.requireOriginal(command)
        val core = ProtectionOriginProof.Core.decode(binary(fields, "core", 393))
        require(core.attemptId == uuid(fields, "attempt_id") && same(core.association.bytes(), expected.bytes()))
        val nonce = binary(fields, "nonce", 32); core.requireNonce(nonce)
        val previous = optionalNested(fields, "closed_predecessor")?.let {
            closed(it, setOf("proof_request_id", "attempt_id", "core_sha256", "bundle_sha256", "closed_ms"))
            Predecessor(uuid(it, "proof_request_id"), uuid(it, "attempt_id"), binary(it, "core_sha256", 32),
                nullableBinary(it, "bundle_sha256", 32), decimal(it, "closed_ms"))
        }
        require(previous == null || previous.closedMs == core.issuedMs)
        return Challenge(uuid(fields, "proof_request_id"), core, nonce, previous)
    }
    private fun receipt(fields: Map<String, Any>): Receipt {
        closed(fields, setOf("association_sha256", "core_sha256", "bundle_sha256", "accepted_ms"))
        return Receipt(binary(fields, "association_sha256", 32), binary(fields, "core_sha256", 32),
            binary(fields, "bundle_sha256", 32), decimal(fields, "accepted_ms"))
    }
    private val common = setOf("v", "type", "connection_epoch", "setup_id", "opening_id", "command_id")
    private val openingKeys = linkedSetOf("account_id", "device_id", "source_pairing_id", "origin_digest", "enrolled_point",
        "enrolled_key_id", "opening_nonce", "created_ms", "pairing_created_ms", "pairing_claimed_ms", "pairing_approved_ms", "pairing_expires_ms")
    private fun closed(fields: Map<String, Any>, keys: Set<String>) { require(fields.keys == keys) }
    private fun text(fields: Map<String, Any>, key: String) = fields[key] as? String ?: error("Protection text required")
    private fun decimal(fields: Map<String, Any>, key: String): Long = text(fields, key).let {
        require(it.matches(Regex("[1-9][0-9]{0,18}"))); it.toLong().also { n -> require(n > 0) }
    }
    private fun uuid(fields: Map<String, Any>, key: String) = UUID.fromString(text(fields, key)).also {
        require(it != UUID(0, 0) && it.toString() == text(fields, key))
    }
    private fun binary(fields: Map<String, Any>, key: String, width: Int) =
        SealedDispatch03Frames.decodeCanonical(text(fields, key), width, width)
    private fun nested(fields: Map<String, Any>, key: String): Map<String, Any> {
        val raw = fields[key] as? Map<*, *> ?: error("Protection object required")
        return raw.entries.associate { (k, v) -> (k as? String ?: error("Protection key")) to checkNotNull(v) }
    }
    private fun optionalNested(fields: Map<String, Any>, key: String) =
        if (fields[key] === ProtectionOriginJson.Null) null else nested(fields, key)
    private fun nullableUuid(fields: Map<String, Any>, key: String) =
        if (fields[key] === ProtectionOriginJson.Null) null else uuid(fields, key)
    private fun nullableBinary(fields: Map<String, Any>, key: String, width: Int) =
        if (fields[key] === ProtectionOriginJson.Null) null else binary(fields, key, width)
    private fun nullable(value: Any?): Any = when (value) {
        null -> ProtectionOriginJson.Null
        is UUID -> nonzero(value).toString()
        is ByteArray -> { require(value.size == 32); encode(value) }
        else -> error("Protection nullable type")
    }
    private fun nonzero(value: UUID) = value.also { require(it != UUID(0, 0)) }
    private fun encode(value: ByteArray) = Profile03ElectionEncoding.encode(value)
    private fun hex(value: ByteArray) = Draft02OutboundPreparation.hex(value)
    private fun same(a: ByteArray, b: ByteArray) = ProtectionOriginProof.same(a, b)
}
