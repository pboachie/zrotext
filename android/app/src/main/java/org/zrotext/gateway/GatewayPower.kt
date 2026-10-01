// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

/** Read-only local observations, never a readiness or delivery claim. */
internal data class GatewayPowerObservation(val percentage: Int?, val charging: Boolean?) {
    val label: String get() {
        if (percentage == null && charging == null) return "Unavailable"
        val level = percentage?.let { "$it%" } ?: "Charge level unavailable"
        val state = when (charging) {
            true -> "Charging or full"
            false -> "Not charging"
            null -> "Charging state unavailable"
        }
        return "$level · $state"
    }

    companion object {
        fun unavailable() = GatewayPowerObservation(null, null)
        fun from(level: Int, scale: Int, status: Int, present: Boolean = true): GatewayPowerObservation {
            if (!present) return unavailable()
            val percentage = if (scale > 0 && level >= 0 && level <= scale)
                (level.toLong() * 100 / scale).toInt() else null
            val charging = when (status) {
                BatteryManager.BATTERY_STATUS_CHARGING, BatteryManager.BATTERY_STATUS_FULL -> true
                BatteryManager.BATTERY_STATUS_DISCHARGING, BatteryManager.BATTERY_STATUS_NOT_CHARGING -> false
                else -> null
            }
            return GatewayPowerObservation(percentage, charging)
        }
        fun from(intent: Intent?): GatewayPowerObservation {
            if (intent?.action != Intent.ACTION_BATTERY_CHANGED) return unavailable()
            return from(intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1),
                intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1),
                intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1),
                intent.getBooleanExtra(BatteryManager.EXTRA_PRESENT, true))
        }
    }
}

/** Only the resumed Home owns this receiver. No timer, permission or service. */
internal class GatewayPowerMonitor(private val context: Context,
    private val update: (GatewayPowerObservation) -> Unit) {
    private var observing = false
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (observing && intent?.action == Intent.ACTION_BATTERY_CHANGED)
                update(GatewayPowerObservation.from(intent))
        }
    }
    fun resume() {
        if (observing) return
        try {
            val current = ContextCompat.registerReceiver(context, receiver,
                IntentFilter(Intent.ACTION_BATTERY_CHANGED), ContextCompat.RECEIVER_NOT_EXPORTED)
            observing = true
            update(GatewayPowerObservation.from(current))
        } catch (_: SecurityException) {
            update(GatewayPowerObservation.unavailable())
        }
    }
    fun pause() {
        if (observing) {
            observing = false
            context.unregisterReceiver(receiver)
        }
        update(GatewayPowerObservation.unavailable())
    }
}

@Composable
internal fun rememberGatewayPower(): GatewayPowerObservation {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    var power by remember(context, owner) { mutableStateOf(GatewayPowerObservation.unavailable()) }
    DisposableEffect(context, owner) {
        val monitor = GatewayPowerMonitor(context) { power = it }
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME -> monitor.resume()
                Lifecycle.Event.ON_PAUSE, Lifecycle.Event.ON_STOP, Lifecycle.Event.ON_DESTROY -> monitor.pause()
                else -> Unit
            }
        }
        owner.lifecycle.addObserver(observer)
        if (owner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) monitor.resume()
        onDispose {
            owner.lifecycle.removeObserver(observer)
            monitor.pause()
        }
    }
    return power
}
