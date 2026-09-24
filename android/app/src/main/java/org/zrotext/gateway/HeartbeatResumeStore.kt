// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.net.URI
import java.util.UUID

/** Private, non-secret configuration for an explicitly opted-in heartbeat-only boot resume. */
internal object HeartbeatResumeStore {
    private const val PREFS = "heartbeat_boot_resume"
    private const val URL = "device_stream_url"
    private const val DEVICE_ID = "approved_device_id"
    private const val OPTED_IN_AT = "opted_in_at_ms"
    private const val BOOT_COUNT = "boot_count"

    data class Config(val url: String, val deviceId: UUID,
        val optedInAtMs: Long = 0L, val bootCount: Int = -1)

    fun save(context: Context, config: Config): Boolean {
        require(validUrl(config.url))
        val bootCount = currentBootCount(context)
        if (bootCount < 0) return false
        val saved = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(URL, config.url)
            .putString(DEVICE_ID, config.deviceId.toString())
            .putLong(OPTED_IN_AT, System.currentTimeMillis())
            .putInt(BOOT_COUNT, bootCount)
            .commit()
        return saved
    }

    fun read(context: Context): Config? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val url = prefs.getString(URL, null) ?: return null
        val id = prefs.getString(DEVICE_ID, null) ?: return null
        val deviceId = runCatching { UUID.fromString(id) }.getOrNull()
            ?.takeIf { it.toString() == id } ?: return null
        val optedInAtMs = prefs.getLong(OPTED_IN_AT, 0L)
        val bootCount = prefs.getInt(BOOT_COUNT, -1)
        return Config(url, deviceId, optedInAtMs, bootCount)
            .takeIf { validUrl(it.url) && it.optedInAtMs > 0L && it.bootCount >= 0 }
    }

    fun clear(context: Context): Boolean {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    fun currentBootCount(context: Context): Int = Settings.Global.getInt(
        context.contentResolver, Settings.Global.BOOT_COUNT, -1)

    /** A system Task Manager Stop revokes a previous opt-in without an app callback. */
    fun eligibleAfterUserStop(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 33) return true
        val config = read(context) ?: return true
        val exits = runCatching {
            context.getSystemService(ActivityManager::class.java)
                ?.getHistoricalProcessExitReasons(null, 0, 0)
        }.getOrNull()
        if (exits == null || exits.any {
                it.reason == ApplicationExitInfo.REASON_USER_REQUESTED &&
                    it.timestamp >= config.optedInAtMs
            }) {
            clear(context)
            return false
        }
        return true
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
