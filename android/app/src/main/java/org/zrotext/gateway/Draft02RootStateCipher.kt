// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Existing-key codec only. Production custody checks belong to Draft02RootStorageKey. */
internal object Draft02RootStateCipher {
    private val MAGIC = byteArrayOf(0x5a, 0x54, 0x54, 0x45, 1)

    fun seal(key: SecretKey, aad: ByteArray, plaintext: ByteArray): ByteArray {
        require(plaintext.size <= Draft02TrustStore.MAX_BYTES - 33)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad)
        check(cipher.iv.size == 12)
        return MAGIC + cipher.iv + cipher.doFinal(plaintext)
    }

    fun open(key: SecretKey, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        if (ciphertext.size !in 33..Draft02TrustStore.MAX_BYTES || !ciphertext.copyOfRange(0, 5).contentEquals(MAGIC))
            throw Draft02TrustStore.Failure(Draft02TrustStore.Status.CORRUPT)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, ciphertext.copyOfRange(5, 17)))
        cipher.updateAAD(aad)
        return try { cipher.doFinal(ciphertext, 17, ciphertext.size - 17) }
        catch (_: AEADBadTagException) { throw Draft02TrustStore.Failure(Draft02TrustStore.Status.CORRUPT) }
    }
}
