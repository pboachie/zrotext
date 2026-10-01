// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

/** Android grants are observations, never authorization to start a pilot or send. */
internal data class GatewayAccessSnapshot(
    val sim: Boolean,
    val sending: Boolean,
    val receiving: Boolean,
    val notifications: Boolean
) {
    companion object {
        fun observe(context: Context): GatewayAccessSnapshot {
            fun granted(permission: String) = ContextCompat.checkSelfPermission(context, permission) ==
                PackageManager.PERMISSION_GRANTED
            return GatewayAccessSnapshot(
                granted(Manifest.permission.READ_PHONE_STATE),
                granted(Manifest.permission.SEND_SMS),
                granted(Manifest.permission.RECEIVE_SMS),
                NotificationManagerCompat.from(context).areNotificationsEnabled()
            )
        }
    }
}

@Composable
internal fun GatewayAccessSummary() {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    var access by remember(context) { mutableStateOf(GatewayAccessSnapshot.observe(context)) }
    DisposableEffect(context, owner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) access = GatewayAccessSnapshot.observe(context)
        }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer) }
    }
    fun grant(value: Boolean) = if (value) "Granted" else "Not granted"
    GatewaySectionTitle("Android access")
    Text("SIM information access: ${grant(access.sim)}")
    Text("SMS sending access: ${grant(access.sending)}")
    Text("SMS receiving access: ${grant(access.receiving)}")
    Text("App notifications: ${if (access.notifications) "Enabled" else "Disabled"}")
    Text("These are Android settings, not proof of a working SMS connection. Review each purpose in Setup; granting access alone does not start a test or send a message.")
}
