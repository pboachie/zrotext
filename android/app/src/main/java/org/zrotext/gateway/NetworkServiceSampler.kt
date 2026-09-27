// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.telephony.ServiceState
import android.telephony.SubscriptionManager
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import androidx.annotation.RequiresApi

/** One initial callback per eligible report; no persistent cached radio observation. */
internal class NetworkServiceSampler(
    private val context: Context,
    private val selectedId: () -> Int = {
        context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
            .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
    }
) {
    private val main = Handler(Looper.getMainLooper())
    private var cancelPending: (() -> Unit)? = null

    fun cancel() { main.post { cancelPending?.invoke(); cancelPending = null } }

    fun sample(isCurrent: () -> Boolean, result: (NetworkService) -> Unit) {
        main.post {
            cancelPending?.invoke()
            cancelPending = null
            if (!isCurrent()) return@post
            if (Build.VERSION.SDK_INT < 33) {
                result(NetworkService.UNAVAILABLE)
                return@post
            }
            observe(isCurrent, result)
        }
    }

    private fun selected(): Int? = try {
        if (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) null
        else {
            val chosen = selectedId()
            if (chosen < 0) null else context.getSystemService(SubscriptionManager::class.java)
                ?.activeSubscriptionInfoList?.firstOrNull { it.subscriptionId == chosen }?.subscriptionId
        }
    } catch (_: RuntimeException) { null }

    @RequiresApi(33)
    private fun observe(isCurrent: () -> Boolean, result: (NetworkService) -> Unit) {
        val subscription = selected()
        if (subscription == null) { result(NetworkService.UNAVAILABLE); return }
        val manager = context.getSystemService(TelephonyManager::class.java)?.createForSubscriptionId(subscription)
        if (manager == null) { result(NetworkService.UNAVAILABLE); return }
        val capture = NetworkServiceCapture(subscription, SystemClock.elapsedRealtime())
        var registered = false
        lateinit var listener: TelephonyCallback
        lateinit var timeout: Runnable
        val preferences = context.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
        var selectionChanged: SharedPreferences.OnSharedPreferenceChangeListener? = null
        fun cleanup() {
            main.removeCallbacks(timeout)
            selectionChanged?.let(preferences::unregisterOnSharedPreferenceChangeListener)
            if (registered) {
                registered = false
                try { manager.unregisterTelephonyCallback(listener) } catch (_: RuntimeException) { /* Platform gone. */ }
            }
            cancelPending = null
        }
        fun finish(value: NetworkService) {
            val observation = capture.complete(selected(), SystemClock.elapsedRealtime(), value)
            if (observation == null) return
            cleanup()
            if (isCurrent()) result(observation)
        }
        listener = object : TelephonyCallback(), TelephonyCallback.ServiceStateListener {
            override fun onServiceStateChanged(serviceState: ServiceState) {
                // Never retain/serialize the platform object, operator or cell information.
                finish(NetworkService.fromPlatform(serviceState.state))
            }
        }
        timeout = Runnable { finish(NetworkService.UNAVAILABLE) }
        cancelPending = { capture.cancel(); cleanup() }
        selectionChanged = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == "subscription_id" || key == null) finish(NetworkService.UNAVAILABLE)
        }
        preferences.registerOnSharedPreferenceChangeListener(selectionChanged)
        try {
            // The callback contract permits redacted service state without location access.
            // The getter has a different permission contract and is intentionally not used.
            registered = true
            manager.registerTelephonyCallback(TelephonyManager.INCLUDE_LOCATION_DATA_NONE,
                java.util.concurrent.Executor { command -> main.post(command) }, listener)
            main.postDelayed(timeout, NetworkServiceCapture.MAX_CAPTURE_MS)
        } catch (_: RuntimeException) { finish(NetworkService.UNAVAILABLE) }
    }
}
