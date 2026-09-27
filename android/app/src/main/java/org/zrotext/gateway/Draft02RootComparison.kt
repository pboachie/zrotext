// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.security.MessageDigest

/** Dormant comparison controller. Equal strings cannot prove independent human provenance. */
internal class Draft02RootComparison {
    private var pending: ByteArray? = null
    private var receipt: Receipt? = null

    class Display internal constructor(val accountHex: String, val fingerprintHex: String, val generation: Long)

    class Receipt private constructor(private val pin: ByteArray) {
        private var used = false
        private var cancelled = false
        @Synchronized internal fun consume(): ByteArray {
            check(!used && !cancelled) { "Comparison receipt unavailable" }
            used = true
            return pin.copyOf()
        }
        @Synchronized internal fun requireCurrent() { check(!cancelled) { "Comparison cancelled" } }
        @Synchronized internal fun cancel() { cancelled = true }
        companion object {
            internal fun compared(pin: ByteArray, fingerprint: ByteArray): Receipt {
                require(MessageDigest.isEqual(fingerprint(pin), fingerprint)) { "Fingerprint mismatch" }
                return Receipt(pin.copyOf())
            }
        }
    }

    /** A QR/import contains the pin only. A comparison value is supplied separately by the human. */
    @Synchronized fun begin(pin: ByteArray, expectedAccount: ByteArray): Display {
        cancel()
        val owned = validatePin(pin)
        require(expectedAccount.size == 16 && owned.copyOfRange(5, 21).contentEquals(expectedAccount)) { "Account mismatch" }
        pending = owned
        return Display(hex(expectedAccount), hex(fingerprint(owned)), 1)
    }

    /** Caller presents source/account warnings and obtains deliberate confirmation; there is no UI wiring. */
    @Synchronized fun confirm(fullFingerprint: String, independentlyCompared: Boolean): Receipt {
        val pin = pending ?: error("No comparison pending")
        pending = null
        require(independentlyCompared && fullFingerprint.length == 64 &&
            fullFingerprint.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) { "Full comparison required" }
        val bytes = ByteArray(32) { fullFingerprint.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        return Receipt.compared(pin, bytes).also { receipt = it }
    }

    /** Call on cancellation, backgrounding, or account/session/candidate change. */
    @Synchronized fun cancel() { pending = null; receipt?.cancel(); receipt = null }

    companion object {
        internal fun validatePin(pin: ByteArray): ByteArray {
            require(pin.size == 94) { "Root pin size" }
            val bytes = pin.copyOf()
            require(bytes.copyOfRange(0, 5).contentEquals(byteArrayOf(0x5a, 0x54, 0x52, 0x50, 2)) &&
                bytes.copyOfRange(5, 21).any { it != 0.toByte() } && ByteBuffer.wrap(bytes, 21, 8).long == 1L) { "Genesis pin" }
            DevicePayloadKeyStore.decodePoint(bytes.copyOfRange(29, 94))
            return bytes
        }
        internal fun fingerprint(pin: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256")
            .digest("ZTSE/root-pin/v2\u0000".toByteArray(Charsets.US_ASCII) + pin)
        private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
