// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.text.TextLayoutResult
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

    @Test fun compactNavigationKeepsNamedSelectedActionsAndVisibleTouchTargets() = checkScreenMenu()

    @Test
    @Config(qualifiers = "w320dp-h640dp")
    fun narrowNavigationKeepsCompleteNamesAndTouchTargets() = checkScreenMenu()

    private fun checkScreenMenu() {
        val density = compose.activity.resources.displayMetrics.density
        compose.onNode(hasText("Controls") and hasClickAction()).assertIsDisplayed().performClick()
        GatewayPage.entries.forEach { destination ->
            val node = compose.onNode(hasText(destination.label) and hasClickAction())
                .assertIsDisplayed().fetchSemanticsNode()
            assertEquals(destination == GatewayPage.HOME, node.config[SemanticsProperties.Selected])
            assertEquals(if (destination == GatewayPage.HOME) "Current screen" else "Open screen",
                node.config[SemanticsProperties.StateDescription])
            assertTrue("${destination.label} retains a 48 dp target", node.size.height / density >= 48f)
            assertTrue("${destination.label} retains a 48 dp width", node.size.width / density >= 48f)
        }
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
        compose.onNodeWithText("Quick controls").performScrollTo().performClick()
        compose.onNodeWithText("Phone details").performScrollTo().performClick()
        compose.onNodeWithText("Heartbeat acknowledgments this session: 7").assertExists()
        compose.onNodeWithText("Close widget").performScrollTo().performClick()
        compose.openGatewayPage("Setup")
        compose.onNodeWithText("3. Pair this phone").assertExists()
        compose.onNodeWithText("Arm one test SMS").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals("Waiting for network", AuthenticatedGatewayStatus.value)
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun navigationRetainsMaskedPairingInputAndBackReturnsHome() {
        compose.openGatewayPage("Setup")
        compose.onNodeWithText("3. Pair this phone").performScrollTo().performClick()
        compose.onNodeWithText("One-use pairing token").performScrollTo().performTextInput("synthetic-token")
        val maskedBefore = compose.onNodeWithText("One-use pairing token").fetchSemanticsNode()
            .config[SemanticsProperties.EditableText].text
        assertNotEquals("A password field must mask the token", "synthetic-token", maskedBefore)
        compose.openGatewayPage("Connection")
        compose.onNodeWithText("Authenticated device heartbeat").assertExists()
        compose.openGatewayPage("Setup")
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
        compose.openGatewayPage("Tools")
        compose.onNodeWithText("Start inbound metadata pilot").performScrollTo().performClick()
        compose.onNodeWithText("Pilot status: Set a WSS device stream and approved device ID").assertExists()
    }

    @Test fun detailsWidgetCanBeOpenedAndClosedWithoutStartingPilots() {
        compose.onNodeWithText("Quick controls").performScrollTo().performClick()
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

    @Test fun quickControlsRetainEveryNamedActionAndDoNotStartServicesWhenOpened() {
        val density = compose.activity.resources.displayMetrics.density
        compose.onNodeWithText("Quick controls").performScrollTo().performClick()
        listOf("Connection controls", "Set up this phone", "Android access", "Phone details").forEach { label ->
            val node = compose.onNode(hasText(label) and hasClickAction()).performScrollTo()
                .assertIsDisplayed().fetchSemanticsNode()
            assertTrue("$label keeps a 48 dp height", node.size.height / density >= 48f)
            assertTrue("$label keeps a 48 dp width", node.size.width / density >= 48f)
        }
        compose.runOnIdle {
            assertEquals("Paused", AuthenticatedGatewayStatus.value)
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
        compose.onNodeWithText("Android access").performScrollTo().performClick()
        compose.onNodeWithText("Pause stops connections. To stop permission-enabled local SMS processing, revoke SMS receiving access in Android app settings.").assertExists()
        compose.onNodeWithText("Close widget").performScrollTo().performClick()
        compose.onNodeWithText("Quick controls").performScrollTo().performClick()
        compose.onNodeWithText("Connection controls").performScrollTo().performClick()
        compose.onNodeWithText("Authenticated device heartbeat").assertExists()
        compose.openGatewayPage("Home")
        compose.onNodeWithText("Quick controls").performScrollTo().performClick()
        compose.onNodeWithText("Set up this phone").performScrollTo().performClick()
        compose.onNodeWithText("3. Pair this phone").assertExists()
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test
    @Config(qualifiers = "w320dp-h640dp")
    fun largeTextMessageDetailsKeepsItsCompleteNameAndFullWidthTarget() {
        RuntimeEnvironment.setFontScale(2f)
        compose.activityRule.scenario.recreate()
        val target = compose.onNodeWithTag("home-message-details").performScrollTo()
            .assertIsDisplayed().fetchSemanticsNode()
        val density = compose.activity.resources.displayMetrics.density
        assertEquals("Large-text details use the full 288 dp content width", 288f, target.size.width / density, 1f)
        assertTrue("The visible target remains at least 48 dp", target.size.height / density >= 48f)
        compose.onNodeWithText("Message details", useUnmergedTree = true)
            .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { action ->
                val layouts = mutableListOf<TextLayoutResult>()
                assertTrue(action(layouts))
                assertEquals("The full action name fits without fragmented words", 1, layouts.single().lineCount)
            }
        compose.onNodeWithTag("home-message-details").performClick()
        compose.onNodeWithText("Message counts are unavailable on this phone. An authorized summary reader is not connected.")
            .performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Close widget").performScrollTo().assertIsDisplayed().performClick()
        compose.runOnIdle {
            assertNull(shadowOf(compose.activity).lastRequestedPermission)
            assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
        }
    }

    @Test fun receivingDisclosureHasReachableStackedChoicesAtLargeTextAndCanBeDeclined() {
        RuntimeEnvironment.setFontScale(2f)
        compose.activityRule.scenario.recreate()
        compose.openGatewayPage("Setup")
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
