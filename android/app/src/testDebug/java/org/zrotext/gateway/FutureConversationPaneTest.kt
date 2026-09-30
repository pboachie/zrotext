// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.setContent
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.material3.Text
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w320dp-h480dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class FutureConversationPaneTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    private val interval = UUID.randomUUID().toString()
    private val line = UUID.randomUUID().toString()
    private val request = UUID.randomUUID().toString()
    private fun review(budget: Long = 60000) = ConversationPhoneReview(request, interval, line, 1,
        "+12", ConversationActivationCodec.DISCLOSURE, "conversation-content-v1",
        Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray()), budget)
    private fun reviewing(version: Long = 1, budget: Long = 60000) = ConversationPresentationSnapshot(
        version, ConversationPresentationPhase.AWAITING_PHONE_REVIEW, review = review(budget))
    private fun active(version: Long = 1, budget: Long = 60000) = ConversationPresentationSnapshot(
        version, ConversationPresentationPhase.CONFIRMED_ACTIVE, interval, line, 1, budget, true)
    private fun mount(port: FakePort, label: String? = "Test line", large: Boolean = false,
                      dismiss: () -> Unit = {}) {
        compose.runOnIdle { compose.activity.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, if (large) 2f else 1f)) {
                GatewayTheme { FutureConversationPane(port, { _, _ -> label }, onDismiss = dismiss) }
            }
        } }
        compose.waitForIdle()
    }
    private fun click(text: String) = compose.onNodeWithText(text).performScrollTo().performClick()
    private fun emit(port: FakePort, state: ConversationPresentationSnapshot) {
        compose.runOnIdle { port.emit(state) }; compose.waitForIdle()
    }

    @Test fun mountingAndNavigationNeverApproveOrStop() {
        val port = FakePort(reviewing()); mount(port)
        assertTrue(port.actions.isEmpty()); assertEquals(0, port.refreshes)
        compose.onNodeWithText(ConversationActivationCodec.DISCLOSURE).assertExists()
    }
    @Test fun agreementBindsExactRequestAndVersionAndCannotDoubleSubmit() {
        val port = FakePort(reviewing(7)); mount(port)
        click("Agree and continue")
        compose.onNodeWithText("Agree and continue").assertIsNotEnabled()
        assertEquals(listOf("approve:$request:7"), port.actions)
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertDoesNotExist()
    }
    @Test fun declinePreservesOtherCapabilitiesAndHidesPeer() {
        val port = FakePort(reviewing()); var dismissed = 0; mount(port, dismiss = { dismissed++ })
        click("Not now")
        assertEquals(listOf("decline:$request:1"), port.actions); assertEquals(1, dismissed)
        compose.onNodeWithText("Conversation with: +12").assertDoesNotExist()
    }
    @Test fun backDeclinesWithoutApproval() {
        val port = FakePort(reviewing()); mount(port)
        compose.runOnIdle { compose.activity.onBackPressedDispatcher.onBackPressed() }
        assertEquals(listOf("decline:$request:1"), port.actions)
    }
    @Test fun unverifiedLineCannotBeApproved() {
        val port = FakePort(reviewing()); mount(port, label = null)
        compose.onNodeWithText("Agree and continue").assertIsNotEnabled()
        click("Not now"); assertTrue(port.actions.single().startsWith("decline:"))
    }
    @Test fun pendingAndRecoveryNeverClaimActive() {
        val port = FakePort(ConversationPresentationSnapshot(1, ConversationPresentationPhase.PREPARING)); mount(port)
        compose.onNodeWithText("Content transfer: Preparing — capture is not confirmed").assertExists()
        emit(port, ConversationPresentationSnapshot(2, ConversationPresentationPhase.RECOVERING))
        compose.onNodeWithText("Content transfer: Verifying — capture is not confirmed").assertExists()
        compose.onNodeWithText("After a restart, a new interval and fresh phone approval are required.").assertExists()
        assertTrue(port.actions.isEmpty())
    }
    @Test fun stopRequiresDomainConfirmationBeforeClosed() {
        val port = FakePort(active(4)); mount(port); click("Stop content transfer")
        assertEquals(listOf("stop:$interval:4"), port.actions)
        compose.onNodeWithText("Content transfer: Interval closed").assertDoesNotExist()
        emit(port, ConversationPresentationSnapshot(5, ConversationPresentationPhase.PAUSING,
            intervalId = interval, close = ConversationCloseOutcome.IN_PROGRESS))
        compose.onNodeWithText("Content transfer: Stopping").assertExists()
        emit(port, ConversationPresentationSnapshot(6, ConversationPresentationPhase.DURABLY_CLOSED,
            intervalId = interval, close = ConversationCloseOutcome.DURABLY_CLOSED))
        compose.onNodeWithText("Content transfer: Interval closed").assertExists()
        compose.onNodeWithText("Stop content transfer").assertDoesNotExist()
    }
    @Test fun closureFailureIsNotDurableClosureOrErasure() {
        val port = FakePort(ConversationPresentationSnapshot(1, ConversationPresentationPhase.FAILURE,
            close = ConversationCloseOutcome.DISABLED_CLOSURE_FAILED)); mount(port)
        compose.onNodeWithText("Content transfer: Capture disabled here; closure unconfirmed").assertExists()
        compose.onNodeWithText("Content transfer: Interval closed").assertDoesNotExist()
        compose.onNodeWithText("Stop content transfer").assertDoesNotExist()
    }
    @Test fun olderSnapshotCannotReplaceCurrentObservation() {
        val port = FakePort(active(2)); mount(port); emit(port, reviewing(1))
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertExists()
        compose.onNodeWithText("Conversation with: +12").assertDoesNotExist()
    }
    @Test fun expiryDoesNotRenewApprovalOrTriggerAnyAction() {
        val port = FakePort(reviewing(budget = 100)); mount(port)
        compose.mainClock.autoAdvance = false
        compose.runOnIdle { org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofMillis(1000)) }
        org.robolectric.Shadows.shadowOf(android.os.Looper.getMainLooper()).idleFor(java.time.Duration.ofMillis(1000))
        compose.mainClock.advanceTimeBy(1000); compose.waitForIdle()
        compose.onNodeWithText("Content transfer: Confirmation expired").assertExists()
        compose.onNodeWithText("Agree and continue").assertDoesNotExist()
        assertTrue(port.actions.isEmpty())
    }
    @Test fun duplicateVersionCannotRenewLease() {
        val port = FakePort(active(budget = 100)); mount(port)
        compose.mainClock.autoAdvance = false
        emit(port, active(budget = 60000)); compose.runOnIdle { org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofMillis(1000)) }
        org.robolectric.Shadows.shadowOf(android.os.Looper.getMainLooper()).idleFor(java.time.Duration.ofMillis(1000))
        compose.mainClock.advanceTimeBy(1000); compose.waitForIdle()
        compose.onNodeWithText("Content transfer: Confirmation expired").assertExists()
    }
    @Test fun delayedDeliveryCannotExtendApprovalLease() {
        val port = FakePort(ConversationPresentationSnapshot(1, ConversationPresentationPhase.OFF)); mount(port)
        compose.runOnIdle {
            port.emit(reviewing(2, 100))
            org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofMillis(1000))
        }
        compose.waitForIdle()
        compose.onNodeWithText("Content transfer: Confirmation expired").assertExists()
        compose.onNodeWithText("Agree and continue").assertDoesNotExist()
        assertTrue(port.actions.isEmpty())
    }
    @Test fun actionBoundaryRejectsExpiryBeforeTimerDelivery() {
        val port = FakePort(reviewing()); mount(port)
        val action = compose.onNodeWithText("Agree and continue").fetchSemanticsNode()
            .config[androidx.compose.ui.semantics.SemanticsActions.OnClick].action!!
        compose.runOnIdle {
            org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofMillis(61000))
            action.invoke()
        }
        compose.waitForIdle(); assertTrue(port.actions.isEmpty())
    }
    @Test fun disposeClosesObserverAndRejectsLateDelivery() {
        val port = FakePort(reviewing()); mount(port); val late = port.listener!!
        compose.runOnIdle { compose.activity.setContent { Text("Other screen") } }
        compose.waitForIdle(); assertEquals(1, port.closes)
        compose.runOnIdle { late(active(2)) }; compose.waitForIdle()
        compose.onNodeWithText("Other screen").assertExists(); assertTrue(port.actions.isEmpty())
    }
    @Test fun backgroundUnsubscribesAndDoesNotRestoreReplayedApproval() {
        val port = FakePort(active()); mount(port)
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        assertEquals(1, port.closes)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED); compose.waitForIdle()
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertDoesNotExist()
        emit(port, ConversationPresentationSnapshot(2, ConversationPresentationPhase.RECOVERING))
        compose.onNodeWithText("Content transfer: Verifying — capture is not confirmed").assertExists()
    }
    @Test fun callbackFailureDoesNotExposeRawErrorOrAllowAutomaticRetry() {
        val port = FakePort(reviewing()); port.throwAction = true; mount(port); click("Agree and continue")
        compose.onNodeWithText("Agree and continue").assertIsNotEnabled()
        compose.onNodeWithText("private details").assertDoesNotExist()
        click("Refresh status"); assertEquals(1, port.refreshes); assertEquals(1, port.actions.size)
    }
    @Test fun twoHundredPercentChoicesAreStackedNamedAndLarge() {
        val port = FakePort(reviewing()); mount(port, large = true)
        val agree = compose.onNodeWithText("Agree and continue")
        val decline = compose.onNodeWithText("Not now")
        val a = agree.getUnclippedBoundsInRoot(); val b = decline.getUnclippedBoundsInRoot()
        assertTrue((a.bottom - a.top) >= 48.dp && (b.bottom - b.top) >= 48.dp); assertTrue(a.bottom <= b.top)
        agree.performScrollTo().assertIsDisplayed(); decline.performScrollTo().assertIsDisplayed()
        val peer = compose.onNodeWithText("Conversation with: +12").fetchSemanticsNode()
        assertFalse(peer.config.contains(SemanticsProperties.LiveRegion))
        assertEquals(LiveRegionMode.Polite, compose.onNodeWithText("Content transfer: Awaiting phone approval")
            .fetchSemanticsNode().config[SemanticsProperties.LiveRegion])
    }

    private class FakePort(var value: ConversationPresentationSnapshot) : ConversationPresentationPort {
        var listener: ((ConversationPresentationSnapshot) -> Unit)? = null
        val actions = mutableListOf<String>()
        var refreshes = 0; var closes = 0; var throwAction = false
        override fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable {
            this.listener = listener; listener(value)
            return AutoCloseable { closes++; this.listener = null }
        }
        fun emit(next: ConversationPresentationSnapshot) { value = next; listener?.invoke(next) }
        override fun refresh() { refreshes++ }
        private fun action(value: String) { actions += value; if (throwAction) error("private details") }
        override fun approvePhoneReview(requestId: String, observedVersion: Long) = action("approve:$requestId:$observedVersion")
        override fun declinePhoneReview(requestId: String, observedVersion: Long) = action("decline:$requestId:$observedVersion")
        override fun requestStop(intervalId: String, observedVersion: Long) = action("stop:$intervalId:$observedVersion")
    }
}
