// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.util.JsonReader
import android.util.JsonToken
import java.io.IOException
import java.io.StringReader
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Base64
import java.util.UUID

/** Unused raw decoder. These eight declarations never authenticate a stream or issue a capability. */
internal object LineActivationV2IncomingFrames {
    sealed class Frame {
        abstract val purpose: LineActivationV2Purpose
        final override fun toString() = "LineActivationV2IncomingFrame(redacted)"
    }

    sealed class Challenge(
        final override val purpose: LineActivationV2Purpose,
        val challengeId: UUID, val accountId: UUID, val lineId: UUID, val deviceId: UUID,
        val generation: Long, nonce: ByteArray, val expiresAtMs: Long
    ) : Frame() {
        private val nonceBytes = nonce.copyOf()
        fun nonce() = nonceBytes.copyOf()
    }
    class SmsChallenge internal constructor(
        challengeId: UUID, accountId: UUID, lineId: UUID, deviceId: UUID,
        generation: Long, nonce: ByteArray, expiresAtMs: Long
    ) : Challenge(LineActivationV2Purpose.SMS, challengeId, accountId, lineId, deviceId,
        generation, nonce, expiresAtMs)
    class SealedChallenge internal constructor(
        val connectionEpoch: Long, challengeId: UUID, accountId: UUID, lineId: UUID,
        deviceId: UUID, generation: Long, nonce: ByteArray, expiresAtMs: Long
    ) : Challenge(LineActivationV2Purpose.SEALED, challengeId, accountId, lineId, deviceId,
        generation, nonce, expiresAtMs)

    sealed class ProofAck(
        final override val purpose: LineActivationV2Purpose,
        val challengeId: UUID, val accepted: Boolean
    ) : Frame()
    class SmsProofAck internal constructor(challengeId: UUID, accepted: Boolean) :
        ProofAck(LineActivationV2Purpose.SMS, challengeId, accepted)
    class SealedProofAck internal constructor(
        val connectionEpoch: Long, challengeId: UUID, accepted: Boolean
    ) : ProofAck(LineActivationV2Purpose.SEALED, challengeId, accepted)

    sealed class Receipt(
        final override val purpose: LineActivationV2Purpose,
        val challengeId: UUID, val accountId: UUID, val lineId: UUID, val deviceId: UUID,
        val generation: Long, statementDigest: ByteArray, signatureDigest: ByteArray
    ) : Frame() {
        private val statementBytes = statementDigest.copyOf()
        private val signatureBytes = signatureDigest.copyOf()
        fun deviceStatementSha256() = statementBytes.copyOf()
        fun deviceSignatureSha256() = signatureBytes.copyOf()
    }
    class SmsActivated internal constructor(
        challengeId: UUID, accountId: UUID, lineId: UUID, deviceId: UUID, generation: Long,
        statementDigest: ByteArray, signatureDigest: ByteArray
    ) : Receipt(LineActivationV2Purpose.SMS, challengeId, accountId, lineId, deviceId,
        generation, statementDigest, signatureDigest)
    class SealedActivated internal constructor(
        val connectionEpoch: Long, challengeId: UUID, accountId: UUID, lineId: UUID,
        deviceId: UUID, generation: Long, statementDigest: ByteArray, signatureDigest: ByteArray
    ) : Receipt(LineActivationV2Purpose.SEALED, challengeId, accountId, lineId, deviceId,
        generation, statementDigest, signatureDigest)
    class SealedInstalled internal constructor(
        val connectionEpoch: Long, challengeId: UUID, accountId: UUID, lineId: UUID,
        deviceId: UUID, generation: Long, statementDigest: ByteArray, signatureDigest: ByteArray
    ) : Receipt(LineActivationV2Purpose.SEALED, challengeId, accountId, lineId, deviceId,
        generation, statementDigest, signatureDigest)
    class SealedInstallAck internal constructor(
        val connectionEpoch: Long, val challengeId: UUID, val accepted: Boolean
    ) : Frame() {
        override val purpose = LineActivationV2Purpose.SEALED
    }

    private val header = setOf("type", "v", "challenge_id")
    private val identity = header + setOf("account_id", "line_id", "device_id", "generation")
    private val challengeFields = identity + setOf("nonce", "expires_at_ms")
    private val proofAckFields = header + "accepted"
    private val receiptFields = identity + setOf("device_statement_sha256", "device_signature_sha256")
    private val allFields = challengeFields + proofAckFields + receiptFields + "connection_epoch"
    private val decimal = Regex("[1-9][0-9]*")
    private val uuidText = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val bytesText = Regex("[A-Za-z0-9_-]{43}")
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    /** expectedPurpose is a syntax namespace only; no session, challenge or receipt is trusted here. */
    fun parse(raw: ByteArray, expectedPurpose: LineActivationV2Purpose): Frame {
        require(raw.size in 1..4096)
        try {
            val frozen = raw.copyOf()
            val text = Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(frozen)).toString()
            require(!text.startsWith('\uFEFF'))
            requireLexemes(text)
            val values = JsonReader(StringReader(text)).use { reader ->
                reader.isLenient = false
                readObject(reader)
            }
            val type = values.string("type")
            val purpose = when (type) {
                "sms_line_challenge_v2", "sms_line_proof_ack_v2", "sms_line_activated_v2" ->
                    LineActivationV2Purpose.SMS
                "sealed_line_challenge_v2", "sealed_line_proof_ack_v2", "sealed_line_activated_v2",
                "sealed_line_installed_v2", "sealed_line_install_ack_v2" -> LineActivationV2Purpose.SEALED
                else -> throw IllegalArgumentException("Invalid v2 line frame")
            }
            require(purpose == expectedPurpose)
            val fields = when (type) {
                "sms_line_challenge_v2" -> challengeFields
                "sealed_line_challenge_v2" -> challengeFields + "connection_epoch"
                "sms_line_proof_ack_v2" -> proofAckFields
                "sealed_line_proof_ack_v2", "sealed_line_install_ack_v2" -> proofAckFields + "connection_epoch"
                "sms_line_activated_v2" -> receiptFields
                else -> receiptFields + "connection_epoch"
            }
            require(values.keys == fields)
            val challenge = values.uuid("challenge_id")
            return when (type) {
                "sms_line_challenge_v2" -> SmsChallenge(challenge, values.uuid("account_id"),
                    values.uuid("line_id"), values.uuid("device_id"), values.positive("generation"),
                    values.bytes32("nonce"), values.expiry(false))
                "sealed_line_challenge_v2" -> SealedChallenge(values.positive("connection_epoch"),
                    challenge, values.uuid("account_id"), values.uuid("line_id"), values.uuid("device_id"),
                    values.positive("generation"), values.bytes32("nonce").also { nonce ->
                        require(nonce.any { it != 0.toByte() })
                    }, values.expiry(true))
                "sms_line_proof_ack_v2" -> SmsProofAck(challenge, values.accepted())
                "sealed_line_proof_ack_v2" -> SealedProofAck(values.positive("connection_epoch"),
                    challenge, values.accepted())
                "sealed_line_install_ack_v2" -> SealedInstallAck(values.positive("connection_epoch"),
                    challenge, values.accepted())
                "sms_line_activated_v2" -> SmsActivated(challenge, values.uuid("account_id"),
                    values.uuid("line_id"), values.uuid("device_id"), values.positive("generation"),
                    values.bytes32("device_statement_sha256"), values.bytes32("device_signature_sha256"))
                "sealed_line_activated_v2" -> SealedActivated(values.positive("connection_epoch"),
                    challenge, values.uuid("account_id"), values.uuid("line_id"), values.uuid("device_id"),
                    values.positive("generation"), values.bytes32("device_statement_sha256"),
                    values.bytes32("device_signature_sha256"))
                else -> SealedInstalled(values.positive("connection_epoch"), challenge,
                    values.uuid("account_id"), values.uuid("line_id"), values.uuid("device_id"),
                    values.positive("generation"), values.bytes32("device_statement_sha256"),
                    values.bytes32("device_signature_sha256"))
            }
        } catch (_: IOException) {
            throw IllegalArgumentException("Invalid v2 line frame")
        } catch (_: IllegalStateException) {
            throw IllegalArgumentException("Invalid v2 line frame")
        } catch (_: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid v2 line frame")
        }
    }

    private fun readObject(reader: JsonReader): Map<String, Any> {
        require(reader.peek() == JsonToken.BEGIN_OBJECT)
        reader.beginObject()
        val values = linkedMapOf<String, Any>()
        while (reader.hasNext()) {
            val name = reader.nextName()
            // nextName unescapes keys: escaped duplicates are refused before any overwrite.
            require(name in allFields && name !in values)
            values[name] = when (name) {
                "v" -> {
                    require(reader.peek() == JsonToken.NUMBER && reader.nextString() == "2")
                    2L
                }
                "expires_at_ms" -> {
                    require(reader.peek() == JsonToken.NUMBER)
                    positiveDecimal(reader.nextString())
                }
                "accepted" -> {
                    require(reader.peek() == JsonToken.BOOLEAN)
                    reader.nextBoolean()
                }
                else -> {
                    require(reader.peek() == JsonToken.STRING)
                    reader.nextString()
                }
            }
        }
        reader.endObject()
        require(reader.peek() == JsonToken.END_DOCUMENT)
        return values
    }

    // JsonReader validates the grammar. This bounded lexical check prevents its permissive
    // escape/literal handling from normalizing malformed JSON into valid field values.
    private fun requireLexemes(text: String) {
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                c in " \t\r\n{}:," -> i++
                c == '"' -> {
                    i++
                    var closed = false
                    while (i < text.length) {
                        val part = text[i++]
                        if (part == '"') { closed = true; break }
                        require(part >= ' ')
                        if (part == '\\') {
                            require(i < text.length)
                            val escape = text[i++]
                            if (escape == 'u') {
                                require(i + 4 <= text.length &&
                                    text.substring(i, i + 4).all { it in "0123456789abcdefABCDEF" })
                                i += 4
                            } else require(escape in "\"\\/bfnrt")
                        }
                    }
                    require(closed)
                }
                else -> {
                    val start = i
                    while (i < text.length && text[i] !in " \t\r\n{}:,\"") i++
                    val literal = text.substring(start, i)
                    require(literal == "true" || literal == "false" || literal.matches(decimal))
                }
            }
        }
    }

    private fun positiveDecimal(value: String): Long {
        require(value.length in 1..19 && value.matches(decimal))
        return value.toLongOrNull()?.also { require(it > 0) }
            ?: throw IllegalArgumentException("Invalid v2 line frame")
    }
    private fun Map<String, Any>.string(key: String): String = get(key).let {
        require(it is String); it
    }
    private fun Map<String, Any>.positive(key: String) = positiveDecimal(string(key))
    private fun Map<String, Any>.uuid(key: String): UUID {
        val text = string(key)
        require(text.matches(uuidText))
        return UUID.fromString(text).also { require(it != UUID(0, 0) && it.toString() == text) }
    }
    private fun Map<String, Any>.bytes32(key: String): ByteArray {
        val text = string(key)
        require(text.matches(bytesText))
        return Base64.getUrlDecoder().decode(text).also {
            require(it.size == 32 && encoder.encodeToString(it) == text)
        }
    }
    private fun Map<String, Any>.accepted(): Boolean = get("accepted").let {
        require(it is Boolean); it
    }
    private fun Map<String, Any>.expiry(isSealed: Boolean): Long = get("expires_at_ms").let {
        require(it is Long && it > 0 && (!isSealed ||
            it <= Long.MAX_VALUE - SealedLineActivationTranscript.ACK_GRACE_MS)); it
    }
}
