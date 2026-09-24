// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import java.net.URI
import java.util.UUID

/** Private, non-secret configuration for an explicitly opted-in heartbeat-only boot resume. */
internal object HeartbeatResumeStore {
    private const val PREFS = "heartbeat_boot_resume"
    private const val URL = "device_stream_url"
    private const val DEVICE_ID = "approved_device_id"

    data class Config(val url: String, val deviceId: UUID)

    fun save(context: Context, config: Config): Boolean {
        require(validUrl(config.url))
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(URL, config.url)
            .putString(DEVICE_ID, config.deviceId.toString())
            .commit()
    }

    fun read(context: Context): Config? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val url = prefs.getString(URL, null) ?: return null
        val id = prefs.getString(DEVICE_ID, null) ?: return null
        val deviceId = runCatching { UUID.fromString(id) }.getOrNull()
            ?.takeIf { it.toString() == id } ?: return null
        return Config(url, deviceId).takeIf { validUrl(it.url) }
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().commit()
    }

    fun validUrl(value: String): Boolean = try {
        val url = URI(value)
        url.scheme == "wss" && !url.host.isNullOrBlank() &&
            url.rawPath == "/v1/device-stream" && url.rawQuery == null &&
            url.rawFragment == null && url.rawUserInfo == null
    } catch (_: Exception) {
        false
    }
}
