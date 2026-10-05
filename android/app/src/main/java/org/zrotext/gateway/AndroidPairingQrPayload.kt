// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Base64
import java.util.UUID

/** One-use pairing claim inputs, never a URL to open or owner authentication. */
internal class AndroidPairingQrPayload private constructor(
    val origin: String, val pairingId: UUID, private var credential: CharArray?
) : AutoCloseable {
    @Synchronized fun takeClaimInputs(approved: () -> Boolean): AndroidPairingQrClaimInputs {
        val token = checkNotNull(credential) { "Pairing input closed" }
        credential = null
        return AndroidPairingQrClaimInputs(origin, pairingId.toString(), token, approved)
    }

    @Synchronized override fun close() { credential?.fill('\u0000'); credential = null }
    override fun toString() = "AndroidPairingQrPayload(redacted)"

    companion object {
        const val MAX_UTF8_BYTES = 512
        private val canonical = Regex("""\{"type":"zrotext-pairing","v":1,"origin":"([^"\\]*)","pairing_id":"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})","token":"(ztp_[A-Za-z0-9_-]{43})"\}""")

        fun parse(raw: String): AndroidPairingQrPayload {
            try {
                require(raw.length <= MAX_UTF8_BYTES && raw.toByteArray(Charsets.UTF_8).size <= MAX_UTF8_BYTES)
                require(raw.all { it.code in 0x20..0x7e })
                val fields = checkNotNull(canonical.matchEntire(raw)).groupValues
                val origin = canonicalOrigin(fields[1])
                val pairing = UUID.fromString(fields[2])
                require(pairing.toString() == fields[2] && pairing != UUID(0, 0))
                val encoded = fields[3].substring(4)
                val decoded = Base64.getUrlDecoder().decode(encoded)
                try { require(decoded.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == encoded) }
                finally { decoded.fill(0) }
                return AndroidPairingQrPayload(origin, pairing, fields[3].toCharArray())
            } catch (_: Exception) { throw IllegalArgumentException("Pairing QR payload refused") }
        }

        fun parse(raw: ByteArray): AndroidPairingQrPayload {
            try {
                require(raw.size <= MAX_UTF8_BYTES)
                val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString()
                return parse(text)
            } catch (_: Exception) { throw IllegalArgumentException("Pairing QR payload refused") }
        }

        fun manual(origin: String, pairingId: String, token: String): AndroidPairingQrPayload {
            require(origin.length <= MAX_UTF8_BYTES && pairingId.length == 36 && token.length == 47) { "Manual pairing input refused" }
            canonicalOrigin(origin)
            return parse("{\"type\":\"zrotext-pairing\",\"v\":1,\"origin\":\"$origin\",\"pairing_id\":\"$pairingId\",\"token\":\"$token\"}")
        }

        /** Require the exact normalized HTTPS origin the user knows independently. */
        fun canonicalOrigin(value: String): String {
            try {
                require(value.length in 1..MAX_UTF8_BYTES && value.all { it.code in 0x21..0x7e })
                val url = checkNotNull(value.toHttpUrlOrNull())
                require(url.scheme == "https" && url.port in 1..65535 && url.encodedPath == "/" && url.username.isEmpty() &&
                    url.password.isEmpty() && url.query == null && url.fragment == null &&
                    url.toString().removeSuffix("/") == value)
                return value
            } catch (_: Exception) { throw IllegalArgumentException("Canonical HTTPS server origin required") }
        }
    }
}

internal class AndroidPairingQrManualCredentials(val origin: String, val pairingId: String, val token: String) {
    override fun toString() = "AndroidPairingQrManualCredentials(redacted)"
}

/** The mutable held token is cleared on completion/cancel. SDK/HTTP Strings cannot be zeroized. */
internal class AndroidPairingQrClaimInputs internal constructor(
    private val origin: String, private val pairingId: String, private var credential: CharArray?,
    private val approved: () -> Boolean
) : AutoCloseable {
    fun <T> use(block: (String, String, String) -> T): T {
        check(approved()) { "Pairing input closed" }
        val token = synchronized(this) {
            val held = checkNotNull(credential) { "Pairing input closed" }
            try { String(held) } finally { held.fill('\u0000'); credential = null }
        }
        check(approved()) { "Pairing input closed" }
        return block(origin, pairingId, token)
    }
    @Synchronized override fun close() { credential?.fill('\u0000'); credential = null }
    override fun toString() = "AndroidPairingQrClaimInputs(redacted)"
}
