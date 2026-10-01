// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.Lifecycle
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class GatewayAccessSummaryTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @After fun clearGrants() {
        shadowOf(RuntimeEnvironment.getApplication()).denyPermissions(
            Manifest.permission.READ_PHONE_STATE, Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS)
    }

    @Test fun independentAndroidGrantsDoNotAuthorizeActions() {
        val app = shadowOf(RuntimeEnvironment.getApplication())
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        app.denyPermissions(Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS)
        app.grantPermissions(Manifest.permission.READ_PHONE_STATE)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("Android access").performScrollTo().performClick()
        compose.onNodeWithText("SIM information access: Granted").assertExists()
        compose.onNodeWithText("SMS sending access: Not granted").assertExists()
        compose.onNodeWithText("SMS receiving access: Not granted").assertExists()
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun returningFromSettingsReflectsGrantAndRevocation() {
        val app = shadowOf(RuntimeEnvironment.getApplication())
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        app.grantPermissions(Manifest.permission.SEND_SMS)
        app.denyPermissions(Manifest.permission.RECEIVE_SMS)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("Android access").performScrollTo().performClick()
        compose.onNodeWithText("SMS sending access: Granted").assertExists()
        compose.onNodeWithText("SMS receiving access: Not granted").assertExists()
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        app.denyPermissions(Manifest.permission.SEND_SMS)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("SMS sending access: Not granted").assertExists()
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun appNotificationSettingReflectsAndroidBlockWithoutChannelGuarantee() {
        val manager = compose.activity.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        shadowOf(manager).setNotificationsEnabled(false)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("Android access").performScrollTo().performClick()
        compose.onNodeWithText("App notifications: Disabled").assertExists()
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        shadowOf(manager).setNotificationsEnabled(true)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("App notifications: Enabled").assertExists()
    }
}
