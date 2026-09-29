// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/**
 * Contract checks on sealed plaintext (sealed-v1, content constraints Q9).
 * The relay can never check these - it never sees plaintext - so the
 * receiving device enforces them immediately after the HPKE open, inside
 * the granted attempt, before any radio submit intent exists.
 *
 * One rule, one implementation: this delegates to [Draft02Body.decodeText],
 * the decoder the granted preparation path actually runs, and clears the
 * decoded characters before returning.
 */
internal object SealedPlaintextRules {
    /** Strict UTF-8 body of 1..32,768 bytes: no BOM, no NUL, no padding. */
    fun acceptBody(plaintext: ByteArray): Boolean {
        val decoded = try {
            Draft02Body.decodeText(plaintext)
        } catch (_: Exception) {
            return false
        }
        decoded.fill('\u0000')
        return true
    }

    const val MAX_BODY_BYTES = 32_768
}
