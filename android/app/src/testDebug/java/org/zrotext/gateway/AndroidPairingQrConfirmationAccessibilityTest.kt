// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.setContent
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger

/** Real QR review semantics with synthetic scan input; no scanner SDK, pairing host or camera. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class AndroidPairingQrConfirmationAccessibilityTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    private val approval = "I recognize this server and approve sending this pairing claim."
    private val checkbox = SemanticsMatcher.expectValue(SemanticsProperties.Role, Role.Checkbox)
    private var origin = "https://owner.invalid"
    private var callback: ((AndroidPairingQrScanResult) -> Unit)? = null
    private var scanner: AndroidPairingQrScanner? = null
    private val claims = AtomicInteger()
    private val verified = AtomicInteger()
    private val unknown = AtomicInteger()
    private val token = "ztp_" + Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })

    private fun mount() {
        val source = AndroidPairingQrScanSource { callback = it }
        compose.runOnIdle { compose.activity.setContent {
            GatewayTheme {
                AndroidPairingQrScannerPane(
                    knownOrigin = { origin },
                    claimAndProve = { selected, id, claimToken ->
                        assertEquals("https://owner.invalid", selected)
                        assertEquals("11111111-1111-4111-8111-111111111111", id)
                        assertEquals(token, claimToken)
                        claims.incrementAndGet()
                        error("Synthetic unknown outcome")
                    },
                    onVerified = { verified.incrementAndGet() }, onManual = {},
                    onUnknown = { unknown.incrementAndGet() }, source = source,
                    onScannerReady = { scanner = it },
                    modifier = Modifier.verticalScroll(rememberScrollState())
                )
            }
        } }
    }

    private fun click(text: String) {
        val node = compose.onNodeWithText(text)
        if (!node.isDisplayed()) node.performScrollTo()
        node.performClick()
    }

    private fun review() {
        click("Scan pairing QR")
        compose.runOnIdle {
            checkNotNull(callback)(AndroidPairingQrScanResult.Scanned(
                """{"type":"zrotext-pairing","v":1,"origin":"https://owner.invalid","pairing_id":"11111111-1111-4111-8111-111111111111","token":"$token"}"""
            ))
        }
        compose.onNodeWithText("Selected HTTPS server: https://owner.invalid").assertExists()
        compose.onNodeWithText("Scanned HTTPS server: https://owner.invalid").assertExists()
        compose.runOnIdle { assertEquals(AndroidPairingQrScanner.Phase.REVIEW, checkNotNull(scanner).snapshot().phase) }
    }

    private fun confirmation() = compose.onNode(hasText(approval) and checkbox and isToggleable())

    private fun noEffects() {
        assertEquals(0, claims.get())
        assertEquals(0, verified.get())
        assertEquals(0, unknown.get())
    }

    private fun assertNoChildClick(node: SemanticsNode) {
        node.children.forEach {
            assertFalse("Child must not duplicate the parent toggle", it.config.contains(SemanticsActions.OnClick))
            assertNoChildClick(it)
        }
    }

    @Test fun reviewHasOneNamedToggleAndEachClickChangesConfirmationOnce() {
        mount(); review()
        compose.onAllNodes(hasText(approval) and checkbox and isToggleable()).assertCountEquals(1)
        compose.onAllNodes(checkbox and hasClickAction(), useUnmergedTree = true).assertCountEquals(1)
        compose.onAllNodes(isToggleable(), useUnmergedTree = true).assertCountEquals(1)
        val action = compose.onNode(checkbox and hasClickAction(), useUnmergedTree = true).fetchSemanticsNode()
        assertNoChildClick(action)
        confirmation().performScrollTo().assertHeightIsAtLeast(48.dp).assertIsOff()
        compose.onNodeWithText("Claim this pairing ticket").assertIsNotEnabled()
        confirmation().performClick().assertIsOn()
        compose.onNodeWithText("Claim this pairing ticket").assertIsEnabled()
        noEffects()
        confirmation().performClick().assertIsOff()
        compose.onNodeWithText("Claim this pairing ticket").assertIsNotEnabled()
        noEffects()
    }

    @Test fun namedConfirmationStillRequiresSeparateOneUseClaimAction() {
        mount(); review()
        confirmation().performScrollTo().performClick().assertIsOn()
        noEffects()
        click("Claim this pairing ticket")
        compose.waitUntil(5000) { claims.get() == 1 && unknown.get() == 1 }
        compose.onNodeWithText("Claim this pairing ticket").assertDoesNotExist()
        compose.onNodeWithText("Scan pairing QR").assertIsNotEnabled()
        assertEquals(1, claims.get())
        assertEquals(0, verified.get())
    }

    @Test fun freshScanAndLifecycleResumeRequireFreshUncheckedConfirmation() {
        mount(); review()
        confirmation().performScrollTo().performClick().assertIsOn()
        click("Clear scanned pairing")
        confirmation().assertDoesNotExist()
        review()
        confirmation().assertIsOff()
        compose.onNodeWithText("Claim this pairing ticket").assertIsNotEnabled()
        confirmation().performScrollTo().performClick().assertIsOn()
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        confirmation().assertDoesNotExist()
        review()
        confirmation().assertIsOff()
        compose.onNodeWithText("Claim this pairing ticket").assertIsNotEnabled()
        noEffects()
    }

    @Test fun changedIndependentOriginRefusesClaimEvenAfterNamedConfirmation() {
        mount(); review()
        confirmation().performScrollTo().performClick().assertIsOn()
        val displayedClaim = compose.onNodeWithText("Claim this pairing ticket")
            .fetchSemanticsNode().config[SemanticsActions.OnClick].action!!
        // Exercise the already displayed action; the coordinator must resample its origin.
        compose.runOnIdle { origin = "https://other.invalid"; assertTrue(displayedClaim()) }
        compose.runOnIdle { assertEquals(AndroidPairingQrScanner.Phase.IDLE, checkNotNull(scanner).snapshot().phase) }
        noEffects()
        // The pane samples the coordinator every second; advance virtual time, not the production timer.
        compose.mainClock.advanceTimeBy(1_000)
        compose.waitForIdle()
        confirmation().assertDoesNotExist()
        compose.onNodeWithText("Claim this pairing ticket").assertDoesNotExist()
        noEffects()
    }
}
