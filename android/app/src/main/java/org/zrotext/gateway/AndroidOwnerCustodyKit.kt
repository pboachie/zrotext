// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URI
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Independently entered identity. Never filled from an imported backup or proposal. */
internal data class AndroidOwnerCustodyIdentity(val account: UUID, val origin: String, val fingerprint: String) {
    init { validateAccountOrigin(account, origin); require(fingerprint.matches(Regex("[0-9a-f]{64}"))) }
    fun accountBytes(): ByteArray = ByteBuffer.allocate(16).putLong(account.mostSignificantBits).putLong(account.leastSignificantBits).array()
    fun fingerprintBytes(): ByteArray = fingerprint.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    companion object {
        fun validateAccountOrigin(account: UUID, origin: String) {
            require(account != UUID(0, 0))
            require(origin.toByteArray(Charsets.UTF_8).size in 1..512)
            val uri = URI(origin)
            require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.rawUserInfo == null &&
                uri.rawPath.isNullOrEmpty() && uri.rawQuery == null && uri.rawFragment == null)
            require(uri.port == -1 || uri.port in 1..65535 && uri.port != 443 && origin.endsWith(":${uri.port}"))
            require(uri.toASCIIString() == origin && uri.host == uri.host.lowercase())
        }
        fun parse(account: String, origin: String, fingerprint: String): AndroidOwnerCustodyIdentity {
            val uuid = UUID.fromString(account)
            require(uuid.toString() == account)
            return AndroidOwnerCustodyIdentity(uuid, origin, fingerprint)
        }
    }
}

/** Only root-material's encrypted root bundle and its public card enter this record. */
internal class AndroidOwnerCustodyKit(backup: ByteArray, card: ByteArray) {
    private val encrypted = backup.copyOf()
    private val public = card.copyOf()
    val identity: AndroidOwnerCustodyIdentity
    private val storedBundleId: ByteArray
    private val storedPin: ByteArray
    val bundleId get() = storedBundleId.copyOf()
    val pin get() = storedPin.copyOf()
    init {
        require(encrypted.size in 237..748 && public.size in 134..645)
        require(encrypted.copyOfRange(0, 6).contentEquals(byteArrayOf(90, 84, 82, 66, 1, 1)))
        require(public.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 82, 67, 1)))
        val originSize = ByteBuffer.wrap(encrypted, 78, 2).short.toInt() and 65535
        require(originSize in 1..512 && encrypted.size == 236 + originSize && public.size == 133 + originSize)
        require((ByteBuffer.wrap(public, 5, 2).short.toInt() and 65535) == originSize)
        val originBytes = encrypted.copyOfRange(80, 80 + originSize)
        require(originBytes.contentEquals(public.copyOfRange(7, 7 + originSize)))
        val origin = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(originBytes)).toString()
        require(ByteBuffer.wrap(encrypted, 38, 8).long == 1L && ByteBuffer.wrap(encrypted, 184 + originSize, 4).int == 48)
        storedPin = public.copyOfRange(7 + originSize, 101 + originSize)
        require(pin.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 82, 80, 2)) && pin[29] == 4.toByte())
        require(ByteBuffer.wrap(pin, 21, 8).long == 1L && pin.copyOfRange(5, 21).contentEquals(encrypted.copyOfRange(22, 38)))
        val accountBytes = ByteBuffer.wrap(pin, 5, 16)
        val account = UUID(accountBytes.long, accountBytes.long)
        val fingerprint = hash("ZTSE/root-pin/v2\u0000".toByteArray(Charsets.UTF_8) + pin)
        require(fingerprint.contentEquals(encrypted.copyOfRange(46, 78)))
        require(hash(encrypted).contentEquals(public.copyOfRange(101 + originSize, public.size)))
        storedBundleId = encrypted.copyOfRange(6, 22)
        require(bundleId.any { it != 0.toByte() })
        identity = AndroidOwnerCustodyIdentity(account, origin, hex(fingerprint))
    }
    fun backup() = encrypted.copyOf()
    fun card() = public.copyOf()
    fun matches(other: AndroidOwnerCustodyKit) = encrypted.contentEquals(other.encrypted) && public.contentEquals(other.public)
    fun encode(): ByteArray = ByteBuffer.allocate(8 + encrypted.size + public.size)
        .put(byteArrayOf(90, 84, 79, 75, 1)).putShort(encrypted.size.toShort()).put(0).put(encrypted).put(public).array()
    override fun toString() = "AndroidOwnerCustodyKit(encrypted)"
    companion object {
        const val MAX_RECORD = 8 + 748 + 645
        fun decode(bytes: ByteArray): AndroidOwnerCustodyKit {
            require(bytes.size in (8 + 237 + 134)..MAX_RECORD)
            require(bytes.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 79, 75, 1)) && bytes[7] == 0.toByte())
            val length = ByteBuffer.wrap(bytes, 5, 2).short.toInt() and 65535
            require(length in 237..748 && bytes.size - 8 - length in 134..645)
            return AndroidOwnerCustodyKit(bytes.copyOfRange(8, 8 + length), bytes.copyOfRange(8 + length, bytes.size))
        }
        fun hash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}

internal fun readAndroidOwnerCustodyFile(input: InputStream, maximum: Int): ByteArray {
    require(maximum in 1..20480)
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(minOf(1024, maximum + 1))
    while (true) {
        val count = input.read(buffer, 0, minOf(buffer.size, maximum - output.size() + 1))
        if (count == -1) break
        require(count > 0 && output.size() + count <= maximum)
        output.write(buffer, 0, count)
    }
    require(output.size() > 0)
    return output.toByteArray()
}

internal fun decodeAndroidOwnerRecoveryToken(text: String): ByteArray {
    require(text.length == 79 && Regex("ZTRK1-(?:[A-Z2-7]{4}-){13}[0-9A-F]{8}").matches(text))
    // Syntax only. Native verifies the context checksum and then authenticates the full AEAD.
    return text.toByteArray(Charsets.US_ASCII)
}
