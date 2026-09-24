// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.net.URI
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID

/** Local routing identity for journal evidence; the origin itself stays out of Room. */
data class EvidenceIdentity(val accountId: String, val deviceId: String,
                                     val originHash: String) {
    init {
        require(listOf(accountId, deviceId).all {
            runCatching { UUID.fromString(it).toString() == it }.getOrDefault(false)
        })
        require(originHash.matches(Regex("[0-9a-f]{64}")))
    }

    companion object {
        fun fromStream(accountId: UUID, deviceId: UUID, endpoint: String): EvidenceIdentity {
            val uri = URI(endpoint)
            require(uri.scheme == "wss" && !uri.host.isNullOrBlank())
            val port = if (uri.port == -1) 443 else uri.port
            require(port in 1..65535)
            val origin = "wss://${uri.host.lowercase(Locale.ROOT)}:$port"
            val hash = MessageDigest.getInstance("SHA-256")
                .digest(origin.toByteArray(Charsets.US_ASCII))
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            return EvidenceIdentity(accountId.toString(), deviceId.toString(), hash)
        }
    }
}
