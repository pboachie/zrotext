// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
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
import java.util.Base64
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class GatewaySummaryUiTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    private val device = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val token = "ztk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
    private fun connection() { compose.onNode(hasText("Connection") and hasClickAction()).performScrollTo().performClick() }
    private fun configure() {
        connection()
        compose.onNodeWithText("Summary HTTPS origin").performScrollTo().performTextInput("https://example.test")
        compose.onNodeWithText("Summary device UUID").performScrollTo().performTextInput(device)
        compose.onNodeWithText("Separate messages-read API key").performScrollTo().performTextInput(token)
    }
    private fun noEffects() = compose.runOnIdle {
        assertNull(shadowOf(compose.activity).lastRequestedPermission)
        assertTrue(shadowOf(compose.activity).allStartedServices.isEmpty())
    }
    @Test fun navigationAndInvalidDeviceRealmDoNotReadOrStartServices() {
        connection()
        compose.onNodeWithText("Summary HTTPS origin").performScrollTo().performTextInput("https://example.test")
        compose.onNodeWithText("Summary device UUID").performScrollTo().performTextInput(device)
        compose.onNodeWithText("Separate messages-read API key").performScrollTo().performTextInput("ztd_" + token.removePrefix("ztk_"))
        compose.onNodeWithText("Read summary on Home").performScrollTo().performClick()
        compose.onNodeWithText("Enter an HTTPS origin and a separate messages-read API key for this device.").assertExists()
        compose.onNodeWithText("Gateway home").assertDoesNotExist()
        noEffects()
    }
    @Test fun keyIsMaskedAndOriginChangeClearsItBeforeAnotherScopeCanRead() {
        configure()
        val field = compose.onNodeWithText("Separate messages-read API key").fetchSemanticsNode()
        assertTrue(field.config.contains(SemanticsProperties.Password))
        assertNotEquals(token, field.config[SemanticsProperties.EditableText].text)
        compose.onNodeWithText("Summary HTTPS origin").performScrollTo().performTextReplacement("https://other.example.test")
        assertEquals("", compose.onNodeWithText("Separate messages-read API key").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        noEffects()
    }
    @Test fun backgroundingAndRecreationCannotRestoreReaderKey() {
        configure()
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        assertEquals("", compose.onNodeWithText("Separate messages-read API key").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        compose.onNodeWithText("Separate messages-read API key").performScrollTo().performTextInput(token)
        compose.activityRule.scenario.recreate()
        compose.onNode(hasText("Connection") and hasClickAction()).performScrollTo().performClick()
        assertEquals("", compose.onNodeWithText("Separate messages-read API key").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
        noEffects()
    }
    @Test fun realZeroCappedAndHistoricalCountsRenderAsReadOnlyObservations() {
        val snapshot = GatewaySummarySnapshot(UUID.fromString(device), 0, 86_400_000, 1_000,
            GatewaySummaryCount(0, false), GatewaySummaryCount(1_000, true), GatewaySummaryCount(1, false))
        val view = mutableStateOf(GatewaySummaryState.View(GatewaySummaryState.Phase.FRESH, snapshot))
        compose.runOnIdle {
            compose.activity.setContent { GatewayTheme { Column {
                GatewayHome("Paused", "Paused", 0, "Not selected", "Not paired", summary = view.value,
                    summaryStatus = "Synthetic checked metadata", onSetup = {}, onConnection = {}, onPause = {})
            } } }
        }
        compose.onNodeWithTag("home-observation-Submitted today").assertTextEquals("Submitted today 0")
        compose.onNodeWithTag("home-observation-In queue").assertTextEquals("In queue 1000+ (capped)")
        compose.onNodeWithTag("home-observation-Awaiting receipt").assertTextContains("1")
        assertFalse(compose.onNodeWithTag("home-observation-In queue").fetchSemanticsNode().config.contains(SemanticsActions.OnClick))
        compose.runOnIdle { view.value = GatewaySummaryState.View(GatewaySummaryState.Phase.LOADING, snapshot) }
        compose.onNodeWithTag("home-observation-In queue").assertTextEquals("In queue 1000+ (capped) (refreshing)")
        compose.runOnIdle { view.value = GatewaySummaryState.View(GatewaySummaryState.Phase.STALE, snapshot) }
        compose.onNodeWithTag("home-observation-In queue").assertTextEquals("In queue 1000+ (capped) (stale)")
        compose.runOnIdle { view.value = GatewaySummaryState.View(GatewaySummaryState.Phase.UNAVAILABLE, null) }
        compose.onNodeWithTag("home-observation-Submitted today").assertTextEquals("Submitted today Unavailable")
        noEffects()
    }
    @Test fun largeTextReaderControlsAndClearActionRemainReachable() {
        RuntimeEnvironment.setFontScale(2f)
        try {
            compose.activityRule.scenario.recreate()
            configure()
            compose.onNodeWithText("Clear summary reader").performScrollTo().assertIsDisplayed().performClick()
            assertEquals("", compose.onNodeWithText("Separate messages-read API key").fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
            noEffects()
        } finally { RuntimeEnvironment.setFontScale(1f) }
    }
}
