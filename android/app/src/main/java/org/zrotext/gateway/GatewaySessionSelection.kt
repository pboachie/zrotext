// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

/** Change session modes only after the previous reboot opt-in is durably removed. */
internal object GatewaySessionSelection {
    fun startVisibleTestSession(context: Context, url: String, token: String): Boolean {
        if (!HeartbeatResumeStore.clear(context)) return false
        context.stopService(Intent(context, AuthenticatedGatewayService::class.java))
        val intent = Intent(context, GatewayService::class.java)
            .putExtra(GatewayService.EXTRA_URL, url)
            .putExtra(GatewayService.EXTRA_TOKEN, token)
        ContextCompat.startForegroundService(context, intent)
        return true
    }
}
