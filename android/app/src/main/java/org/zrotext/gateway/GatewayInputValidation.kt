// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import okhttp3.Request
import java.net.URI
import java.util.UUID

/** The same input checks run before a UI launch and inside either service. */
internal object GatewayInputValidation {
    fun testEndpoint(value: String): Boolean = try {
        val uri = URI(value)
        uri.scheme == "wss" && !uri.host.isNullOrBlank() &&
            uri.rawUserInfo == null && uri.rawFragment == null &&
            Request.Builder().url(value).build().url.scheme == "https"
    } catch (_: IllegalArgumentException) {
        false
    } catch (_: java.net.URISyntaxException) {
        false
    }

    fun deviceId(value: String): UUID? = try {
        UUID.fromString(value).takeIf { it.toString() == value }
    } catch (_: IllegalArgumentException) {
        null
    }
}
