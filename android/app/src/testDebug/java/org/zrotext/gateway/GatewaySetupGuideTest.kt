// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.ui.semantics.SemanticsProperties
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
class GatewaySetupGuideTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    private fun setup() { compose.openGatewayPage("Setup") }
    private fun noAction() = compose.runOnIdle {
        assertNull(shadowOf(compose.activity).lastRequestedPermission)
        assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
    }

    @Test fun guideNavigationAndBackDoNotAuthorizeAnything() {
        setup()
        compose.onNodeWithText("Continue setup").assertExists()
        compose.onNodeWithText("Review Android access").performScrollTo().performClick()
        compose.onNodeWithText("Review access").assertExists()
        compose.onNodeWithText("Back to SIM selection").performScrollTo().performClick()
        compose.onNodeWithText("Choose a SIM").assertExists()
        compose.onNodeWithText("Next: connection").performScrollTo().performClick()
        compose.onNodeWithText("Connect this phone").assertExists()
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithText("Review Android access").assertExists()
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        compose.onNodeWithText("Gateway home").assertExists()
        noAction()
    }

    @Test fun pairingCanBeReachedWithoutSmsGrantOrSimSelection() {
        setup()
        compose.onNodeWithText("Continue setup").performScrollTo().performClick()
        compose.onNodeWithText("One-use pairing token").assertDoesNotExist()
        compose.onNodeWithText("Pairing status: Ready to scan").assertExists()
        compose.onNodeWithText("Use existing manual pairing").performScrollTo().performClick()
        compose.onNodeWithText("One-use pairing token").assertExists()
        noAction()
    }

    @Test fun recreationKeepsGuideStepButDoesNotPersistPairingSecret() {
        setup()
        compose.onNodeWithText("Continue setup").performScrollTo().performClick()
        compose.onNodeWithText("Use existing manual pairing").performScrollTo().performClick()
        compose.onNodeWithText("One-use pairing token").performScrollTo().performTextInput("synthetic-token")
        compose.activityRule.scenario.recreate()
        compose.onNodeWithText("Device pairing").assertExists()
        compose.onNodeWithText("One-use pairing token").assertDoesNotExist()
        compose.onNodeWithText("Use existing manual pairing").performScrollTo().performClick()
        val token = compose.onNodeWithText("One-use pairing token").fetchSemanticsNode()
        assertTrue(token.config.contains(SemanticsProperties.Password))
        assertEquals("", token.config[SemanticsProperties.EditableText].text)
        noAction()
    }

    @Test fun connectionShortcutOnlyOpensExistingControls() {
        setup()
        compose.onNodeWithText("Advanced connection controls").performScrollTo().performClick()
        compose.onNodeWithText("Authenticated device heartbeat").assertExists()
        noAction()
    }

    @Test fun decliningAccessLeavesTheAccessStepAndChoiceAvailable() {
        setup()
        compose.onNodeWithText("Review Android access").performScrollTo().performClick()
        compose.onNodeWithText("Choose SIM permissions").performScrollTo().performClick()
        compose.onNodeWithText(GatewayPermissionPurpose.SIM.disclosure).assertExists()
        compose.onNodeWithText("Not now").performScrollTo().performClick()
        compose.onNodeWithText("Review access").assertExists()
        compose.onNodeWithText("Choose SIM permissions").assertExists()
        noAction()
    }
}
