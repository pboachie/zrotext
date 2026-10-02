// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.provider.Settings
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
abstract class DevicePreconditionsObservationTest {
    @Test fun missingPhonePermissionIsUnavailableAndAirplaneModeIsNotAReadyClaim() {
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app).denyPermissions(Manifest.permission.READ_PHONE_STATE, Manifest.permission.SEND_SMS)
        app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
            .edit().putInt("subscription_id", 7).commit()
        Settings.Global.putInt(app.contentResolver, Settings.Global.AIRPLANE_MODE_ON, 1)
        val blocked = DevicePreconditions.observe(app)
        assertEquals(DevicePreconditions.SelectedSim.UNAVAILABLE, blocked.selectedSim)
        assertEquals(DevicePreconditions.SmsPermission.DENIED, blocked.smsPermission)
        assertEquals(DevicePreconditions.AirplaneMode.ENABLED, blocked.airplaneMode)
        shadowOf(app).grantPermissions(Manifest.permission.SEND_SMS)
        Settings.Global.putInt(app.contentResolver, Settings.Global.AIRPLANE_MODE_ON, 0)
        assertEquals(DevicePreconditions.SmsPermission.GRANTED, DevicePreconditions.observe(app).smsPermission)
        assertEquals(DevicePreconditions.AirplaneMode.DISABLED, DevicePreconditions.observe(app).airplaneMode)
    }

    @Test fun noSelectionAndMalformedAirplaneSettingRemainExplicit() {
        val app = RuntimeEnvironment.getApplication()
        app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE).edit().clear().commit()
        Settings.Global.putInt(app.contentResolver, Settings.Global.AIRPLANE_MODE_ON, 9)
        val status = DevicePreconditions.observe(app)
        assertEquals(DevicePreconditions.SelectedSim.NOT_SELECTED, status.selectedSim)
        assertEquals(DevicePreconditions.AirplaneMode.UNAVAILABLE, status.airplaneMode)
    }
}

// Each SDK keeps the identical observations in its own native-runtime worker.
@Config(sdk = [28])
class DevicePreconditionsObservationApi28Test : DevicePreconditionsObservationTest()

@Config(sdk = [35])
class DevicePreconditionsObservationApi35Test : DevicePreconditionsObservationTest()
