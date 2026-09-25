// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.telephony.SubscriptionManager
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/** Opt-in hardware pilot. This test can cause exactly one externally authorized SMS. */
@RunWith(AndroidJUnit4::class)
class LocalAuthorizedOneSendDeviceTest {
    @Test fun startOneConsentedSyntheticSendAndHoldForCallbacks() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires explicit one-send authorization", args.getString("m1AuthorizedOneSend") == "true")
        val deviceId = args.getString("m1DeviceId")
        val recipient = args.getString("m1ControlledRecipient")
        assumeTrue("requires private device and recipient", !deviceId.isNullOrBlank() && !recipient.isNullOrBlank())
        UUID.fromString(deviceId)
        assertTrue(recipient!!.matches(Regex("^\\+[1-9][0-9]{1,14}$")))
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("debug pilot only", app.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        for (permission in listOf(Manifest.permission.READ_PHONE_STATE, Manifest.permission.SEND_SMS)) {
            assertTrue("pilot permission missing: $permission",
                ContextCompat.checkSelfPermission(app, permission) == PackageManager.PERMISSION_GRANTED)
        }
        val active = app.getSystemService(SubscriptionManager::class.java)
            .activeSubscriptionInfoList.orEmpty()
        assertTrue("exactly one active SIM is required", active.size == 1)
        val subscriptionId = active.single().subscriptionId
        assertTrue(subscriptionId >= 0 && app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE)
            .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID) == subscriptionId)
        val oneUse = app.getSharedPreferences("alpha_pilot", Context.MODE_PRIVATE)
        assertTrue("the one-send pilot was already consumed", !oneUse.getBoolean("attempt_used", false))

        val start = Intent(app, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://localhost:8443/v1/device-stream")
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, deviceId)
            .putExtra(AuthenticatedGatewayService.EXTRA_ALPHA_RECIPIENT, recipient)
            .putExtra(AuthenticatedGatewayService.EXTRA_ALPHA_SUBSCRIPTION_ID, subscriptionId)
        try {
            ContextCompat.startForegroundService(app, start)
            val grantDeadline = System.currentTimeMillis() + 120_000L
            while (System.currentTimeMillis() < grantDeadline && !oneUse.getBoolean("attempt_used", false)) {
                Thread.sleep(500)
            }
            assertTrue("no synthetic grant consumed; ${AuthenticatedGatewayStatus.value}",
                oneUse.getBoolean("attempt_used", false))
            // Keep the foreground socket alive while sent/delivery callbacks enter Room and
            // the outbox is acknowledged by the writer. This wait never starts another send.
            Thread.sleep(120_000L)
        } finally {
            app.stopService(Intent(app, AuthenticatedGatewayService::class.java))
        }
    }
}
