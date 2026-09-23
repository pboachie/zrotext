// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.telephony.SubscriptionManager
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opt-in preflight only. It selects one active SIM but never arms or calls the radio. */
@RunWith(AndroidJUnit4::class)
class M1LocalRadioPreflightDeviceTest {
    @Test fun selectExactlyOneConsentedActiveSimForPrivatePilot() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("requires private pilot preflight", args.getString("m1RadioPreflight") == "true")
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        for (permission in listOf(Manifest.permission.READ_PHONE_STATE, Manifest.permission.SEND_SMS)) {
            assertTrue("pilot permission missing: $permission",
                ContextCompat.checkSelfPermission(app, permission) == PackageManager.PERMISSION_GRANTED)
        }
        val subscriptions = app.getSystemService(SubscriptionManager::class.java)
            .activeSubscriptionInfoList.orEmpty()
        assertTrue("exactly one active SIM is required", subscriptions.size == 1)
        val subscriptionId = subscriptions.single().subscriptionId
        assertTrue(subscriptionId >= 0)
        assertFalse("one-send pilot was already consumed",
            app.getSharedPreferences("alpha_pilot", Context.MODE_PRIVATE).getBoolean("attempt_used", false))
        assertTrue(app.getSharedPreferences("gateway_selection", Context.MODE_PRIVATE).edit()
            .putInt("subscription_id", subscriptionId).commit())
    }
}
