// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.setContent
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
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

    private fun noEffects() {
        assertEquals(0, claims.get()); assertEquals(0, verified.get()); assertEquals(0, unknown.get())
    }

    @Test fun reviewHasOneNamedDecisionWithoutDuplicateCheckbox() {
        mount(); review()
        compose.onAllNodes(isToggleable(), useUnmergedTree = true).assertCountEquals(0)
        compose.onNodeWithText("Use this trusted server and pair").performScrollTo()
            .assertHeightIsAtLeast(48.dp).assertIsEnabled()
        noEffects()
        click("Use this trusted server and pair")
        compose.waitUntil(5000) { claims.get() == 1 && unknown.get() == 1 }
        compose.onNodeWithText("Use this trusted server and pair").assertDoesNotExist()
        compose.onNodeWithText("Scan pairing QR").assertIsNotEnabled()
        assertEquals(1, claims.get())
    }

    @Test fun cancelledReviewCanBeScannedAgainWithoutSendingAClaim() {
        mount(); review(); click("Clear scanned pairing")
        compose.onNodeWithText("Use this trusted server and pair").assertDoesNotExist()
        review(); noEffects()
    }

    @Test fun leavingReviewClearsTicketAndResumeNeverClaimsAutomatically() {
        mount(); review()
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("Use this trusted server and pair").assertDoesNotExist()
        review(); noEffects()
    }

    @Test fun changedIndependentOriginRefusesEvenPreviouslyVisibleDecision() {
        mount(); review()
        compose.runOnIdle { origin = "https://different.invalid" }
        click("Use this trusted server and pair")
        noEffects()
        compose.runOnIdle { assertEquals(AndroidPairingQrScanner.Phase.IDLE, checkNotNull(scanner).snapshot().phase) }
    }
}
