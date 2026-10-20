// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.AppOpsManager
import android.content.Context
import android.os.Process
import java.util.concurrent.atomic.AtomicBoolean

/** Public own-UID app-operation callbacks, not hidden PackageManager permission listeners.
 * These only invalidate RAM tickets. Full runtime permissions/SIM/key checks still run outside
 * storage; neither a registration nor a mode callback supplies a current permission boolean.
 */
internal object AndroidEnrollmentAppOpsWatch {
    @androidx.annotation.RequiresApi(29)
    fun open(context: Context, changed: () -> Unit): AutoCloseable {
        val manager = checkNotNull(context.getSystemService(AppOpsManager::class.java))
        return watch(context.packageName, { operation, listener ->
            manager.startWatchingMode(operation, context.packageName, AppOpsManager.WATCH_FOREGROUND_CHANGES, listener)
        }, manager::stopWatchingMode, changed)
    }
    /** Actual own-UID RAW mode and runtime-permission reads, only OUTSIDE storage/Room/root
     * locks. DEFAULT delegates the ordinary permission check; ALLOWED cannot replace it. A raw
     * foreground-only mode is unsupported here because these reads do not prove a continuing
     * foreground-service/app-state entitlement. Non-raw reads can silently fold that mode into
     * ALLOWED and therefore cannot supply this background enrollment observation.
     */
    @androidx.annotation.RequiresApi(29)
    fun requireAllowed(context: Context) {
        val manager = checkNotNull(context.getSystemService(AppOpsManager::class.java))
        for ((operation, permission) in OPERATIONS.zip(PERMISSIONS)) {
            check(context.checkSelfPermission(permission) == android.content.pm.PackageManager.PERMISSION_GRANTED)
            // Public API29 own-UID raw read; API36 adds the attribution argument.
            @Suppress("DEPRECATION")
            val mode = if (android.os.Build.VERSION.SDK_INT >= 36)
                manager.checkOpRawNoThrow(operation, Process.myUid(), context.packageName, context.attributionTag)
                else manager.unsafeCheckOpRawNoThrow(operation, Process.myUid(), context.packageName)
            check(mode == AppOpsManager.MODE_ALLOWED || mode == AppOpsManager.MODE_DEFAULT)
            check(context.checkSelfPermission(permission) == android.content.pm.PackageManager.PERMISSION_GRANTED)
        }
    }
    internal fun watch(packageName: String, start: (String, AppOpsManager.OnOpChangedListener) -> Unit,
        stop: (AppOpsManager.OnOpChangedListener) -> Unit, changed: () -> Unit): AutoCloseable {
        val alive = AtomicBoolean(true)
        val listeners = ArrayList<AppOpsManager.OnOpChangedListener>()
        val cleanup = AutoCloseable {
            if (alive.getAndSet(false)) listeners.forEach { listener -> runCatching { stop(listener) } }
        }
        try {
            for (operation in OPERATIONS) {
                val listener = AppOpsManager.OnOpChangedListener { _, changedPackage ->
                    if (alive.get() && (changedPackage == null || changedPackage == packageName)) changed()
                }
                listeners.add(listener) // Partial registration is cleaned on every failed start.
                start(operation, listener)
            }
            return cleanup
        } catch (failure: Exception) { cleanup.close(); throw failure }
    }
    private val OPERATIONS = listOf(AppOpsManager.OPSTR_SEND_SMS, AppOpsManager.OPSTR_RECEIVE_SMS, AppOpsManager.OPSTR_READ_PHONE_STATE)
    private val PERMISSIONS = listOf(android.Manifest.permission.SEND_SMS, android.Manifest.permission.RECEIVE_SMS,
        android.Manifest.permission.READ_PHONE_STATE)
}
