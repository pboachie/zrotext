// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.os.BatteryManager
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import org.junit.Assert.*
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
class GatewayHomePowerLifecycleTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    private fun receiverCount() = shadowOf(RuntimeEnvironment.getApplication()).registeredReceivers.count {
        it.intentFilter.hasAction(Intent.ACTION_BATTERY_CHANGED) &&
            it.broadcastReceiver.javaClass.name.contains("GatewayPowerMonitor")
    }
    @Test fun leavingHomeAndPausingRemoveTheReceiverAndResumeObservesAgain() {
        compose.runOnIdle { assertEquals(1, receiverCount()) }
        compose.openGatewayPage("Setup")
        compose.runOnIdle { assertEquals(0, receiverCount()) }
        compose.openGatewayPage("Home")
        compose.runOnIdle { assertEquals(1, receiverCount()) }
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        assertEquals(0, receiverCount())
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.runOnIdle {
            assertEquals(1, receiverCount())
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }
    @Test fun batteryChangesReachTheReadOnlyHomeWithoutConnectionOrPermissionActions() {
        compose.runOnIdle {
            RuntimeEnvironment.getApplication().sendBroadcast(Intent(Intent.ACTION_BATTERY_CHANGED)
                .putExtra(BatteryManager.EXTRA_LEVEL, 80)
                .putExtra(BatteryManager.EXTRA_SCALE, 100)
                .putExtra(BatteryManager.EXTRA_STATUS, BatteryManager.BATTERY_STATUS_CHARGING))
        }
        compose.onNodeWithText("80% · Charging or full").assertExists()
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }
    @Test fun recreationKeepsOneObserverAndDoesNotStartGatewayActions() {
        compose.activityRule.scenario.recreate()
        compose.onNodeWithText("Gateway home").assertExists()
        compose.runOnIdle {
            assertEquals(1, receiverCount())
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }
}
