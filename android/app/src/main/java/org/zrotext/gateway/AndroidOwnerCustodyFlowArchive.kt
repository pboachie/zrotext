// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import java.io.InputStream

/** Independent archive identity. The root and archive recovery secrets have different types. */
internal data class AndroidOwnerCustodyArchiveIdentity(val root: AndroidOwnerCustodyIdentity, val keyId: String, val point: String) {
    init {
        require(keyId.matches(Regex("[0-9a-f]{64}")) && keyId != "00".repeat(32))
        val bytes = AndroidOwnerCustodyFlowReview.unhex(point, 65); require(bytes[0] == 4.toByte())
        require(AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash("ZTSE/key/v1\u0000".toByteArray() + byteArrayOf(0, 16) + bytes)) == keyId)
    }
    fun keyBytes() = AndroidOwnerCustodyFlowReview.unhex(keyId, 32)
    fun pointBytes() = AndroidOwnerCustodyFlowReview.unhex(point, 65)
}

/** Ciphertext and public receipt only. Header/digest checking is not an AEAD recovery proof. */
internal class AndroidOwnerCustodyArchiveKit(backup: ByteArray, val identity: AndroidOwnerCustodyArchiveIdentity) {
    private val encrypted = backup.copyOf()
    val backupId: String
    val digest: String = AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(encrypted))
    init {
        require(encrypted.size in 334..845 && encrypted.copyOfRange(0, 6).contentEquals(byteArrayOf(90, 84, 65, 66, 1, 1)))
        val size = ByteBuffer.wrap(encrypted, 175, 2).short.toInt() and 65535
        require(size in 1..512 && encrypted.size == 333 + size)
        require(encrypted.copyOfRange(22, 38).contentEquals(identity.root.accountBytes()) && ByteBuffer.wrap(encrypted, 38, 8).long == 1L)
        require(encrypted.copyOfRange(46, 78).contentEquals(identity.root.fingerprintBytes()))
        require(encrypted.copyOfRange(78, 110).contentEquals(identity.keyBytes()) && encrypted.copyOfRange(110, 175).contentEquals(identity.pointBytes()))
        require(encrypted.copyOfRange(177, 177 + size).contentEquals(identity.root.origin.toByteArray(Charsets.UTF_8)))
        require(ByteBuffer.wrap(encrypted, 281 + size, 4).int == 48)
        val id = encrypted.copyOfRange(6, 22); require(id.any { it != 0.toByte() }); backupId = AndroidOwnerCustodyKit.hex(id)
    }
    fun backup() = encrypted.copyOf()
    fun receipt(): ByteArray = ("ZROtext archive receipt v1\nAccount hex: ${AndroidOwnerCustodyKit.hex(identity.root.accountBytes())}\nOrigin: ${identity.root.origin}\nRoot generation: 1\nRoot fingerprint: ${identity.root.fingerprint}\nArchive key ID: ${identity.keyId}\nArchive point SEC1: ${identity.point}\nArchive backup ID: $backupId\nEncrypted archive SHA256: $digest\n").toByteArray(Charsets.UTF_8)
    override fun toString() = "AndroidOwnerCustodyArchiveKit(encrypted)"
}

internal fun decodeAndroidOwnerArchiveRecovery(text: String): ByteArray {
    require(text.length == 44 && text.matches(Regex("[A-Za-z0-9+/]{43}=")))
    val bytes = Base64.getDecoder().decode(text)
    try { require(bytes.size == 32 && bytes.any { it != 0.toByte() } && Base64.getEncoder().encodeToString(bytes) == text); return bytes }
    catch (failure: Exception) { bytes.fill(0); throw failure }
}

/** Fixed private buffer, with no ByteArrayOutputStream accumulator or persisted secret copy. */
internal fun readAndroidOwnerArchiveRecoveryFile(input: InputStream): ByteArray {
    val secret = ByteArray(32)
    try {
        var at = 0
        while (at < secret.size) {
            val count = input.read(secret, at, secret.size - at)
            require(count > 0); at += count
        }
        require(input.read() == -1 && secret.any { it != 0.toByte() })
        return secret
    } catch (failure: Exception) { secret.fill(0); throw failure }
}
