// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.net.URI
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import okhttp3.HttpUrl.Companion.toHttpUrl

/** Two explicit domains for ONE actual configured host/port. Canonicalizing public origin
 * names creates no authentication, original proof, current permission or effect capability. */
internal class Profile03Origins private constructor(val protocolOrigin: String, val routing: EvidenceIdentity) {
    private val digest = MessageDigest.getInstance("SHA-256").digest(protocolOrigin.toByteArray(Charsets.UTF_8))
    val protocolHash = Draft02OutboundPreparation.hex(digest)
    val routingHash get() = routing.originHash
    fun protocolDigest() = digest.copyOf()
    fun requireSession(session: SealedDispatchExecutor.Session) {
        require(session.accountId.toString() == routing.accountId && session.deviceId.toString() == routing.deviceId &&
            session.originHash == routingHash)
    }
    fun requireProtocol(received: ByteArray, session: SealedDispatchExecutor.Session) {
        requireSession(session)
        require(MessageDigest.isEqual(received, digest))
    }
    override fun toString() = "Profile03Origins(configured-protocol-and-routing)"

    companion object {
        fun fromStream(account: UUID, device: UUID, stream: String): Profile03Origins {
            require(account != UUID(0, 0) && device != UUID(0, 0))
            val source = URI(stream)
            require(source.scheme == "wss" && !source.host.isNullOrBlank() && source.rawUserInfo == null && source.rawFragment == null)
            val http = stream.replaceFirst("wss://", "https://").toHttpUrl()
            require(http.scheme == "https" && http.username.isEmpty() && http.password.isEmpty() &&
                http.host == source.host.lowercase(Locale.ROOT).removeSurrounding("[", "]") &&
                http.port == (if (source.port == -1) 443 else source.port))
            val origin = http.newBuilder().encodedPath("/").query(null).fragment(null).build().toString().removeSuffix("/")
            return Profile03Origins(origin, EvidenceIdentity.fromStream(account, device, stream))
        }

        /** Used by original-proof verification with its independently configured canonical
         * HTTPS origin. It derives only the matching old routing identity; no row is rewritten. */
        fun fromProtocol(account: UUID, device: UUID, origin: String): Profile03Origins {
            require(origin.startsWith("https://"))
            return fromStream(account, device, origin.replaceFirst("https://", "wss://")).also {
                require(it.protocolOrigin == origin)
            }
        }
    }
}
