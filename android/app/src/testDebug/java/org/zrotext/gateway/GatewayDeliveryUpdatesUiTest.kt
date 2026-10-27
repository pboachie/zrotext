// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class GatewayDeliveryUpdatesUiTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    @Test fun deliverySyncIsAnExplicitDetailsActionAndNavigationStartsNoWork() {
        var calls = 0
        compose.runOnIdle { compose.activity.setContent { GatewayTheme { Column {
            GatewayHome("Paused", "Paused", 0, "Not selected", "Not paired", onSetup = {}, onConnection = {},
                onPause = {}, deliveryUpdateStatus = "Unconfirmed delivery updates stay saved.",
                onSyncDeliveryUpdates = { calls++ })
        } } } }
        assertEquals(0, calls)
        compose.openGatewayMessages()
        compose.onNodeWithText("Unconfirmed delivery updates stay saved.").assertExists()
        assertEquals(0, calls)
        compose.onNodeWithText("Sync delivery updates").performScrollTo().performClick()
        compose.runOnIdle {
            assertEquals(1, calls)
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }
}
