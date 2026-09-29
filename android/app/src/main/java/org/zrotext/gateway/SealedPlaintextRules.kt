// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/**
 * Contract checks on sealed plaintext (sealed-v1, content constraints Q9).
 * The relay can never check these - it never sees plaintext - so the
 * receiving device enforces them immediately after the HPKE open, inside
 * the granted attempt, before any radio submit intent exists.
 */
internal object SealedPlaintextRules {
    /** Strict UTF-8 body of 1..32,768 bytes: no BOM, no NUL, no padding. */
    fun acceptBody(plaintext: ByteArray): Boolean {
        if (plaintext.isEmpty() || plaintext.size > MAX_BODY_BYTES) return false
        if (plaintext[0] == BOM_FIRST_BYTE && plaintext.size > 1 &&
            plaintext[1] == BOM_SECOND_BYTE
        ) return false
        val decoded = runCatching { String(plaintext, Charsets.UTF_8) }.getOrNull() ?: return false
        if (decoded.toByteArray(Charsets.UTF_8).size != plaintext.size) return false
        return NUL_CHAR !in decoded
    }

    const val MAX_BODY_BYTES = 32_768
    private const val BOM_FIRST_BYTE: Byte = 0xEF.toByte()
    private const val BOM_SECOND_BYTE: Byte = 0xBB.toByte()
    private val NUL_CHAR = '\u0000'
}
