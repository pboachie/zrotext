// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Unused encoding declarations. None of these values establishes OS truth or live authority. */
internal enum class LineActivationV2Purpose(val code: Int, private val prefix: String) {
    SMS(1, "ZTSMS"), SEALED(2, "ZTSE");
    fun deviceDomain() = "$prefix/line/device-confirm/v2\u0000".toByteArray(Charsets.US_ASCII)
    fun ownerDomain() = "$prefix/line/owner-approve/v2\u0000".toByteArray(Charsets.US_ASCII)
    fun proofType() = if (this == SMS) "sms_line_proof_v2" else "sealed_line_proof_v2"
}

internal enum class LineActivationV2Kind(val code: Int) { PHYSICAL(1), EMBEDDED(2) }

/** Tokens must eventually come from the real issuer; this constructor does not issue them. */
internal data class LineActivationV2Row(val kind: LineActivationV2Kind, val cardToken: UUID,
    val profileToken: UUID, val portIndex: Int, val slotIndex: Int) {
    init {
        require(cardToken != UUID(0, 0) && profileToken != UUID(0, 0) &&
            portIndex >= 0 && slotIndex >= 0)
    }
    override fun toString() = "LineActivationV2Row(declaration, redacted)"
}

/** Local-only canonical preimage. No raw card identifier, subscription map or capability factory. */
internal class LineActivationV2CompleteSet(val monitorLifetime: UUID, val observerEpoch: Long,
    val apiLevel: Int, rows: List<LineActivationV2Row>) {
    private val frozen: List<LineActivationV2Row>
    init {
        require(monitorLifetime != UUID(0, 0) && observerEpoch > 0 && apiLevel in 33..65535)
        val copy = rows.toList()
        require(copy.size in 1..256 && copy.map { it.profileToken }.toSet().size == copy.size &&
            copy.map { it.cardToken to it.portIndex }.toSet().size == copy.size)
        frozen = copy.sortedWith { left, right -> compareTokens(left.profileToken, right.profileToken) }
    }
    val count get() = frozen.size
    fun preimage(): ByteArray {
        val domain = "ZT/line/complete-set/v2\u0000".toByteArray(Charsets.US_ASCII)
        return ByteBuffer.allocate(domain.size + 28 + count * 41).put(domain)
            .putId(monitorLifetime).putLong(observerEpoch).putShort(apiLevel.toShort())
            .putShort(count.toShort()).also { out ->
                for (row in frozen) out.put(row.kind.code.toByte()).putId(row.cardToken)
                    .putId(row.profileToken).putInt(row.portIndex).putInt(row.slotIndex)
            }.array()
    }
    fun commitment() = MessageDigest.getInstance("SHA-256").digest(preimage())
    fun observation(selected: LineActivationV2Row, subscriptionId: Int,
        selectedLease: UUID): LineActivationV2Observation {
        require(selected in frozen && subscriptionId >= 0 && selectedLease != UUID(0, 0))
        val bytes = ByteBuffer.allocate(LineActivationV2Observation.BYTES)
            .putShort(apiLevel.toShort()).putShort(count.toShort()).putInt(subscriptionId)
            .put(selected.kind.code.toByte()).putId(selected.cardToken).putId(selected.profileToken)
            .putInt(selected.portIndex).putInt(selected.slotIndex).putId(monitorLifetime)
            .putLong(observerEpoch).putId(selectedLease).put(commitment()).array()
        return LineActivationV2Observation.decode(bytes)
    }
    override fun toString() = "LineActivationV2CompleteSet(declaration, redacted)"
    private fun compareTokens(left: UUID, right: UUID): Int {
        val most = java.lang.Long.compareUnsigned(left.mostSignificantBits, right.mostSignificantBits)
        return if (most != 0) most else
            java.lang.Long.compareUnsigned(left.leastSignificantBits, right.leastSignificantBits)
    }
}

/** A structurally valid fixed declaration; decoding does not prove membership or issuer freshness. */
internal class LineActivationV2Observation private constructor(bytes: ByteArray) {
    private val frozen = bytes.copyOf()
    fun bytes() = frozen.copyOf()
    override fun toString() = "LineActivationV2Observation(declaration, redacted)"
    companion object {
        const val BYTES = 121
        fun decode(bytes: ByteArray): LineActivationV2Observation {
            require(bytes.size == BYTES)
            val copy = bytes.copyOf()
            val input = ByteBuffer.wrap(copy)
            require((input.short.toInt() and 0xffff) in 33..65535 &&
                (input.short.toInt() and 0xffff) in 1..256 && input.int >= 0 &&
                (input.get().toInt() and 0xff) in 1..2)
            require(input.readId() != UUID(0, 0) && input.readId() != UUID(0, 0) &&
                input.int >= 0 && input.int >= 0 && input.readId() != UUID(0, 0) &&
                input.long > 0 && input.readId() != UUID(0, 0))
            // The final 32 bytes are a declaration digest, not proof of the concealed preimage.
            require(input.remaining() == 32)
            return LineActivationV2Observation(copy)
        }
    }
}

/** Statement fields only: no challenge issuance, expiry, acceptance or session authority. */
internal class LineActivationV2StatementFields(val accountId: UUID, val lineId: UUID,
    val deviceId: UUID, val generation: Long, val challengeId: UUID, nonce: ByteArray) {
    private val frozenNonce = nonce.copyOf()
    init {
        require(listOf(accountId, lineId, deviceId, challengeId).none { it == UUID(0, 0) } &&
            generation > 0 && frozenNonce.size == 32)
    }
    fun tuple() = ByteBuffer.allocate(104).putId(accountId).putId(lineId).putId(deviceId)
        .putLong(generation).putId(challengeId).put(frozenNonce).array()
    override fun toString() = "LineActivationV2StatementFields(declaration, redacted)"
}

/** Canonical construction only. No verification, signing, ACK or installed-capability API. */
internal object LineActivationV2Statements {
    fun device(purpose: LineActivationV2Purpose, fields: LineActivationV2StatementFields,
        observation: LineActivationV2Observation): ByteArray = purpose.deviceDomain() +
        byteArrayOf(2, purpose.code.toByte()) + fields.tuple() + observation.bytes()

    fun owner(purpose: LineActivationV2Purpose, deviceStatement: ByteArray,
        signatureDer: ByteArray): ByteArray {
        val statement = deviceStatement.copyOf()
        val signature = signatureDer.copyOf()
        requireDevice(purpose, statement)
        SealedLineActivationTranscript.requireCanonicalDer(signature)
        return purpose.ownerDomain() + statement + digest(signature)
    }
    fun proofDigest(purpose: LineActivationV2Purpose, deviceStatement: ByteArray,
        signatureDer: ByteArray): ByteArray {
        val statement = deviceStatement.copyOf()
        val signature = signatureDer.copyOf()
        requireDevice(purpose, statement)
        SealedLineActivationTranscript.requireCanonicalDer(signature)
        return digest(statement + signature)
    }
    private fun requireDevice(purpose: LineActivationV2Purpose, statement: ByteArray) {
        val domain = purpose.deviceDomain()
        require(statement.size == domain.size + 2 + 104 + LineActivationV2Observation.BYTES &&
            statement.copyOfRange(0, domain.size).contentEquals(domain) &&
            statement[domain.size] == 2.toByte() && statement[domain.size + 1] == purpose.code.toByte())
        val input = ByteBuffer.wrap(statement, domain.size + 2, 104)
        require(input.readId() != UUID(0, 0) && input.readId() != UUID(0, 0) &&
            input.readId() != UUID(0, 0) && input.long > 0 && input.readId() != UUID(0, 0))
        LineActivationV2Observation.decode(statement.copyOfRange(domain.size + 106, statement.size))
    }
    private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
}

private fun ByteBuffer.putId(id: UUID): ByteBuffer =
    putLong(id.mostSignificantBits).putLong(id.leastSignificantBits)
private fun ByteBuffer.readId() = UUID(long, long)
