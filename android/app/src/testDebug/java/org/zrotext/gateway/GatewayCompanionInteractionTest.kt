// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.semantics.SemanticsProperties
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** The Compose rule advances frames and isolates lifecycle state between interactions. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class GatewayCompanionInteractionTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Before fun resetStatus() = compose.runOnIdle {
        AuthenticatedGatewayStatus.value = "Paused"
        AuthenticatedGatewayStatus.heartbeats = 0
        GatewayStatus.value = "Paused"
    }

    @After fun resetAfterTest() {
        compose.runOnIdle {
            AuthenticatedGatewayStatus.value = "Paused"
            AuthenticatedGatewayStatus.heartbeats = 0
        }
        RuntimeEnvironment.setFontScale(1f)
    }

    @Test fun compactNavigationKeepsNamedSelectedActionsAndVisibleTouchTargets() {
        val density = compose.activity.resources.displayMetrics.density
        GatewayPage.entries.forEach { destination ->
            val node = compose.onNode(hasText(destination.label) and hasClickAction())
                .assertIsDisplayed().fetchSemanticsNode()
            assertEquals(destination == GatewayPage.HOME, node.config[SemanticsProperties.Selected])
            assertEquals(if (destination == GatewayPage.HOME) "Current screen" else "Open screen",
                node.config[SemanticsProperties.StateDescription])
            assertTrue("${destination.label} must retain a visible 48 dp touch target", node.size.height / density >= 48f)
            assertTrue("${destination.label} must retain a visible 48 dp width", node.size.width / density >= 48f)
            assertTrue("Compact navigation must leave room for Home status", node.size.height / density <= 52f)
        }
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test
    @Config(qualifiers = "w320dp-h640dp")
    fun narrowNavigationReflowsWithoutBreakingNamesOrTouchTargets() {
        val density = compose.activity.resources.displayMetrics.density
        val actions = GatewayPage.entries.associateWith { destination ->
            compose.onNode(hasText(destination.label) and hasClickAction())
                .assertIsDisplayed().fetchSemanticsNode()
        }
        actions.forEach { (destination, node) ->
            assertTrue("${destination.label} must keep a 48 dp target", node.size.height / density >= 48f)
            assertTrue("${destination.label} must keep its name on one line", node.size.height / density <= 52f)
            assertTrue("Narrow navigation must provide room for complete names", node.size.width / density >= 130f)
            assertEquals(destination == GatewayPage.HOME, node.config[SemanticsProperties.Selected])
        }
        assertEquals(actions.getValue(GatewayPage.HOME).boundsInRoot.top,
            actions.getValue(GatewayPage.SETUP).boundsInRoot.top, 0f)
        assertTrue(actions.getValue(GatewayPage.HOME).boundsInRoot.bottom <=
            actions.getValue(GatewayPage.CONNECTION).boundsInRoot.top)
        assertEquals(actions.getValue(GatewayPage.CONNECTION).boundsInRoot.top,
            actions.getValue(GatewayPage.TOOLS).boundsInRoot.top, 0f)
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun homeShowsRealStateAndNavigationKeepsPilotActionsSeparate() {
        compose.onNodeWithText("Gateway home").assertExists()
        compose.onNodeWithText("Arm one test SMS").assertDoesNotExist()
        compose.onNodeWithText("Pause stops connections. SMS receiving access can still process messages locally; revoke it in Android app settings to stop local processing.").assertExists()
        compose.runOnIdle {
            AuthenticatedGatewayStatus.value = "Waiting for network"
            AuthenticatedGatewayStatus.heartbeats = 7
        }
        compose.onNodeWithText("Device status: Waiting for network").assertExists()
        compose.onNodeWithText("Heartbeat acknowledgments this session: 7").assertExists()
        compose.onNodeWithText("Setup").performClick()
        compose.onNodeWithText("3. Pair this phone").assertExists()
        compose.onNodeWithText("Arm one test SMS").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals("Waiting for network", AuthenticatedGatewayStatus.value)
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun navigationRetainsMaskedPairingInputAndBackReturnsHome() {
        compose.onNodeWithText("Setup").performClick()
        compose.onNodeWithText("3. Pair this phone").performScrollTo().performClick()
        compose.onNodeWithText("One-use pairing token").performScrollTo().performTextInput("synthetic-token")
        val maskedBefore = compose.onNodeWithText("One-use pairing token").fetchSemanticsNode()
            .config[SemanticsProperties.EditableText].text
        assertNotEquals("A password field must mask the token", "synthetic-token", maskedBefore)
        compose.onNodeWithText("Connection").performScrollTo().performClick()
        compose.onNodeWithText("Authenticated device heartbeat").assertExists()
        compose.onNodeWithText("Setup").performClick()
        val field = compose.onNodeWithText("One-use pairing token").fetchSemanticsNode()
        assertTrue(field.config.contains(SemanticsProperties.Password))
        assertEquals(maskedBefore, field.config[SemanticsProperties.EditableText].text)
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithText("3. Pair this phone").assertExists()
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithText("Gateway home").assertExists()
        compose.runOnIdle { assertEquals("Paused", AuthenticatedGatewayStatus.value) }
    }

    @Test fun invalidPilotCredentialsShowFeedbackOnTools() {
        compose.onNodeWithText("Tools").performClick()
        compose.onNodeWithText("Start inbound metadata pilot").performScrollTo().performClick()
        compose.onNodeWithText("Pilot status: Set a WSS device stream and approved device ID").assertExists()
    }

    @Test fun detailsWidgetCanBeOpenedAndClosedWithoutStartingPilots() {
        compose.onNodeWithText("Phone details").performScrollTo().performClick()
        compose.onNodeWithText("Pairing in this session: Not paired").assertExists()
        compose.onNodeWithText("Test connection: Paused").assertExists()
        compose.onNodeWithText("Close widget").performScrollTo().performClick()
        compose.onNodeWithText("Close widget").assertDoesNotExist()
        compose.onNodeWithText("Gateway home").assertExists()
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun receivingDisclosureHasReachableStackedChoicesAtLargeTextAndCanBeDeclined() {
        RuntimeEnvironment.setFontScale(2f)
        compose.activityRule.scenario.recreate()
        compose.onNodeWithText("Setup").performClick()
        compose.onNodeWithText("1. Review access").performScrollTo().performClick()
        compose.onNodeWithText("Review SMS receiving access").performScrollTo().performClick()
        compose.onNodeWithText(GatewayPermissionPurpose.RECEIVE.disclosure).assertExists()
        compose.onNodeWithText("Agree and continue").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Not now").performScrollTo().assertIsDisplayed()
        // Compare both choices in the same scroll frame, not before/after scrolling.
        val agree = compose.onNodeWithText("Agree and continue").fetchSemanticsNode().boundsInRoot
        val decline = compose.onNodeWithText("Not now").fetchSemanticsNode().boundsInRoot
        assertTrue("Consent choices must not overlap", agree.bottom <= decline.top)
        compose.onNodeWithText("Not now").performClick()
        compose.onNodeWithText("Agree and continue").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals("Paused", AuthenticatedGatewayStatus.value)
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }
}
