// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64
import java.util.UUID

/** Local protected journal format, not an ACK or a device-stream wire protocol. */
internal data class ConversationCaptureScope(
    val accountId: String, val deviceId: String, val lineId: String, val bindingGeneration: Long,
    val peer: String, val intervalId: String, val receiptId: String, val initiatingSessionId: String,
    val disclosureDigest: String, val readerKeyId: String, val trustGeneration: Long,
    val activationVersion: Long, val activationDigest: String, val transcriptDigest: String
) {
    init {
        listOf(accountId, deviceId, lineId, intervalId, receiptId, initiatingSessionId).forEach {
            require(UUID.fromString(it).toString() == it && UUID.fromString(it) != UUID(0, 0))
        }
        require(bindingGeneration > 0 && trustGeneration > 0 && activationVersion > 0)
        require(Regex("\\+[1-9][0-9]{1,14}").matches(peer))
        listOf(disclosureDigest, readerKeyId, activationDigest, transcriptDigest).forEach {
            require(HEX.matches(it))
        }
    }

    override fun toString() = "ConversationCaptureScope(redacted)"

    fun encode(): String = encodeFields { out ->
        out.writeInt(1)
        listOf(accountId, deviceId, lineId, peer, intervalId, receiptId, initiatingSessionId,
            disclosureDigest, readerKeyId, activationDigest, transcriptDigest).forEach(out::writeUTF)
        out.writeLong(bindingGeneration)
        out.writeLong(trustGeneration)
        out.writeLong(activationVersion)
    }

    companion object {
        private val HEX = Regex("[0-9a-f]{64}")
        fun decode(encoded: String): ConversationCaptureScope = decodeFields(encoded) { input ->
            require(input.readInt() == 1)
            val f = List(11) { input.readUTF() }
            ConversationCaptureScope(f[0], f[1], f[2], input.readLong(), f[3], f[4], f[5], f[6],
                f[7], f[8], input.readLong(), input.readLong(), f[9], f[10])
        }
    }
}

internal data class ConversationCapturedBody(
    val scope: ConversationCaptureScope, val captureId: String, val firstObservedAtMs: Long,
    val firstObservedElapsedMs: Long, val body: String
) {
    override fun toString() = "ConversationCapturedBody(redacted)"
    fun encode(): String = encodeFields { out ->
        out.writeInt(1)
        out.writeUTF(scope.encode())
        out.writeUTF(captureId)
        out.writeLong(firstObservedAtMs)
        out.writeLong(firstObservedElapsedMs)
        out.writeUTF(body)
    }
    companion object {
        fun decode(encoded: String): ConversationCapturedBody = decodeFields(encoded) { input ->
            require(input.readInt() == 1)
            ConversationCapturedBody(ConversationCaptureScope.decode(input.readUTF()), input.readUTF(),
                input.readLong(), input.readLong(), input.readUTF())
        }
    }
}

private fun encodeFields(write: (DataOutputStream) -> Unit): String {
    val bytes = ByteArrayOutputStream()
    DataOutputStream(bytes).use(write)
    return Base64.getEncoder().encodeToString(bytes.toByteArray())
}

private fun <T> decodeFields(encoded: String, read: (DataInputStream) -> T): T {
    require(encoded.length <= 65536) { "Protected journal size" }
    val input = DataInputStream(ByteArrayInputStream(Base64.getDecoder().decode(encoded)))
    return input.use { read(it).also { _ -> require(it.available() == 0) { "Trailing journal bytes" } } }
}
