// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.telephony.SubscriptionManager
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Real ordinary subscription, permission and explicit-selection callbacks, including supported
 * legacy physical-SIM enrollment. Registration and cleanup occur on main; no platform work is
 * performed by the RAM guard used under storage. A failed/late registration cannot leak a lease.
 */
internal class AndroidEnrollmentStorageLifetime private constructor(
    private val lifetime: EnrollmentStorageLifetime, private val permissionModes: () -> Unit, private val release: () -> Unit,
) : AutoCloseable {
    fun validateOutsideStorage(full: () -> Unit) = lifetime.validateOutsideStorage { permissionModes(); full(); permissionModes() }
    fun requireCurrent() = lifetime.requireCurrent()
    override fun close() { lifetime.close(); release() }
    companion object {
        @androidx.annotation.RequiresApi(31)
        fun open(context: Context): AndroidEnrollmentStorageLifetime {
            check(Looper.myLooper() != Looper.getMainLooper()) // Factory is an enrollment IO action.
            val app = checkNotNull(context.applicationContext)
            val lifetime = EnrollmentStorageLifetime()
            val closing = AtomicBoolean(false)
            val cleanup = AtomicReference<AutoCloseable?>(null)
            val registered = AtomicBoolean(false)
            val initialCallback = AtomicBoolean(false)
            val ready = CompletableFuture<Unit>()
            val main = Handler(Looper.getMainLooper())
            fun release() {
                closing.set(true); lifetime.close()
                val owned = cleanup.getAndSet(null) ?: return
                if (Looper.myLooper() == Looper.getMainLooper()) owned.close()
                else main.post { runCatching { owned.close() } }
            }
            check(main.post {
                if (closing.get()) return@post
                val manager = app.getSystemService(SubscriptionManager::class.java)
                if (manager == null) { ready.completeExceptionally(IllegalStateException("Subscription manager unavailable")); return@post }
                val preferences = app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
                val subscriptions = object : SubscriptionManager.OnSubscriptionsChangedListener() {
                    override fun onSubscriptionsChanged() {
                        lifetime.changed() // Withdraw old thread tickets at callback entry.
                        initialCallback.set(true)
                        if (registered.get() && !closing.get()) ready.complete(Unit)
                    }
                }
                val selection = SharedPreferences.OnSharedPreferenceChangeListener { _, key -> if (key == null || key == "subscription_id") lifetime.changed() }
                var subscriptionAdded = false
                var permissions: AutoCloseable? = null
                var selectionAdded = false
                val owned = AutoCloseable {
                    if (selectionAdded) runCatching { preferences.unregisterOnSharedPreferenceChangeListener(selection) }
                    runCatching { permissions?.close() }
                    if (subscriptionAdded) runCatching { manager.removeOnSubscriptionsChangedListener(subscriptions) }
                }
                try {
                    check(!closing.get())
                    subscriptionAdded = true
                    manager.addOnSubscriptionsChangedListener(java.util.concurrent.Executor { it.run() }, subscriptions)
                    permissions = AndroidEnrollmentAppOpsWatch.open(app, lifetime::changed)
                    selectionAdded = true
                    preferences.registerOnSharedPreferenceChangeListener(selection)
                    cleanup.set(owned)
                    registered.set(true)
                    if (closing.get()) cleanup.getAndSet(null)?.close()
                    else if (initialCallback.get()) ready.complete(Unit)
                } catch (failure: Exception) {
                    lifetime.close(); owned.close(); cleanup.compareAndSet(owned, null)
                    ready.completeExceptionally(failure)
                }
            })
            try {
                ready.get(2, TimeUnit.SECONDS) // Actual first subscription callback, never a synthetic current flag.
                check(!closing.get() && registered.get() && initialCallback.get())
                return AndroidEnrollmentStorageLifetime(lifetime, { AndroidEnrollmentAppOpsWatch.requireAllowed(app) }, ::release)
            } catch (failure: Exception) { release(); throw failure }
        }
    }
}
