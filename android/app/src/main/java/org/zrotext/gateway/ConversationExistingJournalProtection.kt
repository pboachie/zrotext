// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.KeyStore
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Uses the established inbound journal alias, but never generates or replaces its key. */
internal class ConversationExistingJournalProtection internal constructor(
    private val existingKey: () -> SecretKey
) : ConversationJournalProtection {
    enum class Reason { MISSING_KEY, KEY_UNAVAILABLE }
    class Failure(val reason: Reason) : IllegalStateException("Conversation journal protection unavailable")
    constructor() : this({
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        store.getKey(ALIAS, null) as? SecretKey ?: throw Failure(Reason.MISSING_KEY)
    })
    private fun key(): SecretKey = try {
        existingKey().also { check(it.algorithm == "AES") }
    } catch (failure: Failure) { throw failure }
      catch (_: Exception) { throw Failure(Reason.KEY_UNAVAILABLE) }
    fun requireAvailable() { key() }
    private fun aadBytes(aad: String): ByteArray {
        require(aad.length in 1..2048 && aad.all { it.code in 0..127 })
        return aad.toByteArray(Charsets.US_ASCII)
    }
    override fun seal(value: String, aad: String): InboundVault.Sealed {
        require(value.toByteArray(Charsets.UTF_8).size <= 131072)
        val associated = aadBytes(aad)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(associated)
        return InboundVault.Sealed(cipher.doFinal(value.toByteArray(Charsets.UTF_8)), cipher.iv)
    }
    override fun open(value: InboundVault.Sealed, aad: String): String {
        require(value.nonce.size == 12 && value.ciphertext.size in 16..131088)
        val associated = aadBytes(aad)
        val nonce = value.nonce.copyOf()
        val ciphertext = value.ciphertext.copyOf()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, nonce))
        cipher.updateAAD(associated)
        val clear = cipher.doFinal(ciphertext)
        return try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(clear)).toString()
        } finally { clear.fill(0) }
    }
    override fun toString() = "ConversationExistingJournalProtection(redacted)"
    companion object { internal const val ALIAS = "zt_m1_inbound_aes_v1" }
}
