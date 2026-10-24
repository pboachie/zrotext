// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.AppOpsManager
import android.content.ContextWrapper
import android.content.pm.PackageManager
import android.os.Process
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** Real public own-UID operations/permissions in the JVM framework; no physical-device claim. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class AndroidEnrollmentAppOpsWatchTest {
    private val app get() = RuntimeEnvironment.getApplication()
    private val operations = listOf(AppOpsManager.OPSTR_SEND_SMS, AppOpsManager.OPSTR_RECEIVE_SMS, AppOpsManager.OPSTR_READ_PHONE_STATE)
    private val permissions = listOf(android.Manifest.permission.SEND_SMS, android.Manifest.permission.RECEIVE_SMS,
        android.Manifest.permission.READ_PHONE_STATE)
    private fun grant(mode: Int = AppOpsManager.MODE_ALLOWED): AppOpsManager {
        shadowOf(app).grantPermissions(*permissions.toTypedArray())
        return checkNotNull(app.getSystemService(AppOpsManager::class.java)).also { ops ->
            operations.forEach { shadowOf(ops).setMode(it, Process.myUid(), app.packageName, mode) }
        }
    }
    @Test fun ownCallbackPermanentlyWithdrawsCapturedLifetimeEvenIfPermissionIsLaterRestored() {
        val ops = grant(); val lifetime = EnrollmentStorageLifetime()
        val watch = AndroidEnrollmentAppOpsWatch.open(app, lifetime::changed)
        try {
            assertThrows(Exception::class.java) { lifetime.requireCurrent() } // Registration is never an observation.
            lifetime.validateOutsideStorage { AndroidEnrollmentAppOpsWatch.requireAllowed(app) }; lifetime.requireCurrent()
            shadowOf(ops).setMode(AppOpsManager.OPSTR_SEND_SMS, Process.myUid(), app.packageName, AppOpsManager.MODE_IGNORED)
            shadowOf(android.os.Looper.getMainLooper()).idle()
            assertThrows(Exception::class.java) { lifetime.requireCurrent() }
            shadowOf(ops).setMode(AppOpsManager.OPSTR_SEND_SMS, Process.myUid(), app.packageName, AppOpsManager.MODE_ALLOWED)
            shadowOf(android.os.Looper.getMainLooper()).idle()
            assertThrows(Exception::class.java) { lifetime.validateOutsideStorage { AndroidEnrollmentAppOpsWatch.requireAllowed(app) } }
            // A new owned registration may independently observe the restored real state.
            val replacement = EnrollmentStorageLifetime()
            AndroidEnrollmentAppOpsWatch.open(app, replacement::changed).use {
                replacement.validateOutsideStorage { AndroidEnrollmentAppOpsWatch.requireAllowed(app) }; replacement.requireCurrent()
            }
            replacement.close()
        } finally { lifetime.close(); watch.close() }
    }
    @Test fun initialCallbacksDoNotMintTicketsAndClosedWatcherCannotWithdrawOrPublish() {
        val lifetime = EnrollmentStorageLifetime(); val callbacks = mutableListOf<AppOpsManager.OnOpChangedListener>()
        val removed = mutableListOf<AppOpsManager.OnOpChangedListener>()
        val watch = AndroidEnrollmentAppOpsWatch.watch("synthetic.package", { _, callback ->
            callbacks.add(callback); callback.onOpChanged(AppOpsManager.OPSTR_SEND_SMS, "synthetic.package")
        }, { removed.add(it) }, lifetime::changed)
        assertThrows(Exception::class.java) { lifetime.requireCurrent() }
        lifetime.validateOutsideStorage {}; lifetime.requireCurrent()
        watch.close(); watch.close(); assertEquals(3, removed.size)
        callbacks.forEach { it.onOpChanged(AppOpsManager.OPSTR_READ_PHONE_STATE, "synthetic.package") }
        lifetime.requireCurrent(); lifetime.close()
    }
    @Test fun withdrawalDuringInitialFullObservationCannotBeRevalidatedOnTheOldRegistration() {
        val lifetime = EnrollmentStorageLifetime()
        assertThrows(Exception::class.java) { lifetime.validateOutsideStorage { lifetime.changed() } }
        assertThrows(Exception::class.java) { lifetime.requireCurrent() }
        assertThrows(Exception::class.java) { lifetime.validateOutsideStorage {} }
        lifetime.close()
    }
    @Test fun partialRegistrationFailureRemovesAllPossiblyRegisteredCallbacksBeforeLateDelivery() {
        val lifetime = EnrollmentStorageLifetime(); val callbacks = mutableListOf<AppOpsManager.OnOpChangedListener>()
        val removed = mutableListOf<AppOpsManager.OnOpChangedListener>()
        assertThrows(Exception::class.java) {
            AndroidEnrollmentAppOpsWatch.watch("synthetic.package", { _, callback ->
                callbacks.add(callback); check(callbacks.size < 2)
            }, { removed.add(it) }, lifetime::changed)
        }
        assertEquals(2, removed.size)
        lifetime.validateOutsideStorage {}; callbacks.forEach { it.onOpChanged(null, null) }; lifetime.requireCurrent()
        lifetime.close()
    }
    @Test fun eachDefaultOperationDelegatesToTheActualGrantedRuntimePermission() {
        grant(AppOpsManager.MODE_DEFAULT)
        AndroidEnrollmentAppOpsWatch.requireAllowed(app)
        for (permission in permissions) {
            shadowOf(app).denyPermissions(permission)
            assertThrows(Exception::class.java) { AndroidEnrollmentAppOpsWatch.requireAllowed(app) }
            shadowOf(app).grantPermissions(permission)
            AndroidEnrollmentAppOpsWatch.requireAllowed(app)
        }
    }
    @Test fun allowedModeCannotReplaceRuntimePermissionOrFoldForegroundAndUnknownModesIntoAllowed() {
        val ops = grant()
        for (permission in permissions) {
            shadowOf(app).denyPermissions(permission)
            assertThrows(Exception::class.java) { AndroidEnrollmentAppOpsWatch.requireAllowed(app) }
            shadowOf(app).grantPermissions(permission)
        }
        for (operation in operations) for (mode in listOf(AppOpsManager.MODE_FOREGROUND, AppOpsManager.MODE_IGNORED,
            AppOpsManager.MODE_ERRORED, 23)) {
            shadowOf(ops).setMode(operation, Process.myUid(), app.packageName, mode)
            assertThrows(Exception::class.java) { AndroidEnrollmentAppOpsWatch.requireAllowed(app) }
            shadowOf(ops).setMode(operation, Process.myUid(), app.packageName, AppOpsManager.MODE_ALLOWED)
        }
    }
    @Test fun runtimePermissionLossAcrossTheRawModeReadRefusesTheObservation() {
        grant(); var reads = 0
        val changed = object : ContextWrapper(app) {
            override fun checkSelfPermission(permission: String): Int =
                if (++reads == 2) PackageManager.PERMISSION_DENIED else super.checkSelfPermission(permission)
        }
        assertThrows(Exception::class.java) { AndroidEnrollmentAppOpsWatch.requireAllowed(changed) }
        assertEquals(2, reads)
    }
}
