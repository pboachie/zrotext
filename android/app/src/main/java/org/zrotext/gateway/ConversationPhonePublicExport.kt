// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.io.OutputStream

/** Public-only ZTPK01 bridge. Neither this packet nor its comparison grants phone consent. */
internal class ConversationPhonePublicExport(
    account: String, device: String, line: String, generation: Long,
    readerPoint: ByteArray, signerPoint: ByteArray,
    private val requireBoundCurrent: () -> Unit,
    private val elapsedMs: () -> Long,
) {
    private val issued = elapsedMs()
    private val bytes: ByteArray
    val fingerprintHex: String
    init {
        require(generation > 0 && issued >= 0)
        val reader = readerPoint.copyOf(); val signer = signerPoint.copyOf()
        DevicePayloadKeyStore.decodePoint(reader); DevicePayloadKeyStore.decodePoint(signer)
        require(!MessageDigest.isEqual(reader, signer))
        bytes = ByteBuffer.allocate(223).put(byteArrayOf(90, 84, 80, 75, 1))
            .put(ConversationEnrollmentSession.uuid(account)).put(ConversationEnrollmentSession.uuid(device))
            .put(ConversationEnrollmentSession.uuid(line)).put(MessageDigest.getInstance("SHA-256").digest(signer))
            .putLong(generation).put(reader).put(signer).array()
        fingerprintHex = MessageDigest.getInstance("SHA-256").digest(
            "ZTSE/phone-keys/v1\u0000".toByteArray(Charsets.US_ASCII) + bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }
    fun publicBytes(): ByteArray = bytes.copyOf()
    fun requireCurrent() {
        val elapsed = elapsedMs() - issued
        check(elapsed >= 0 && elapsed < 300_000)
        requireBoundCurrent()
    }
    /** Caller supplies only the destination selected by the explicit public-file action. */
    fun write(requireForeground: () -> Unit, openDestination: () -> OutputStream) {
        requireForeground(); requireCurrent()
        openDestination().use { destination ->
            requireForeground(); requireCurrent(); destination.write(bytes); destination.flush()
        }
        requireForeground(); requireCurrent()
    }
    override fun toString() = "ConversationPhonePublicExport(public-only)"
}
