// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.ActivityManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat

/** A boot may resume only the owner's previously opted-in authenticated heartbeat. */
class HeartbeatBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        // Android 15+ also delivers BOOT_COMPLETED when a user opens an app
        // after force-stop. That is not a device reboot or consent to resume.
        if (Build.VERSION.SDK_INT >= 35) {
            val start = context.getSystemService(ActivityManager::class.java)
                .getHistoricalProcessStartReasons(1).firstOrNull()
            if (start?.wasForceStopped() != false) {
                HeartbeatResumeStore.clear(context)
                return
            }
        }
        if (HeartbeatResumeStore.read(context) == null) return
        try {
            ContextCompat.startForegroundService(context,
                Intent(context, AuthenticatedGatewayService::class.java)
                    .setAction(AuthenticatedGatewayService.ACTION_BOOT_RESUME))
        } catch (error: RuntimeException) {
            Log.w("ZTBoot", "Heartbeat resume unavailable after boot", error)
        }
    }
}
