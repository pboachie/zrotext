// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.net.Uri
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import androidx.compose.ui.unit.dp
import android.content.res.Configuration
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.UUID

/** Actual MainActivity navigation with synthetic presentation ports; no service or radio. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28, 34], qualifiers = "w320dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ConversationMainEntryTest {
    @get:Rule(order = 0) val receiverPermission = ConversationReceiverPermissionRule()
    @get:Rule(order = 1) val compose = createAndroidComposeRule<MainActivity>()
    private val line = UUID.randomUUID().toString()
    private val interval = UUID.randomUUID().toString()
    private val request = UUID.randomUUID().toString()
    private val ports = mutableListOf<Port>()
    private val handles = mutableListOf<Handle>()
    private fun click(text: String) {
        val node = compose.onNodeWithText(text)
        if (!node.isDisplayed()) node.performScrollTo()
        node.performClick()
    }
    private fun open() {
        if (ports.isEmpty()) compose.onNode(hasText("Connection") and hasClickAction()).performClick()
        click("Open conversation review")
    }
    private fun installFixture(closeFailure: Boolean = false, verifiedLabel: String? = "Fixture line") {
        compose.runOnIdle {
            compose.activity.conversationSetupEnabled = true
            compose.activity.conversationHandleFactory = { _, ready ->
                val port = Port(); ports += port
                Handle({ ready(port) }, closeFailure).also { handles += it }
            }
        }
        open()
        compose.runOnIdle {
            compose.activity.acceptConversationSetupFile(Uri.EMPTY)
            field("conversationSelectedLine", line to 1L)
            field("conversationVerifiedLineLabel", verifiedLabel)
        }
        click("Review selected conversation"); compose.waitForIdle()
    }
    private fun field(name: String, value: Any?) {
        MainActivity::class.java.getDeclaredField(name).apply { isAccessible = true }.set(compose.activity, value)
    }
    private fun emit(state: ConversationPresentationSnapshot) {
        compose.runOnIdle { ports.last().emit(state) }; compose.waitForIdle()
    }

    @Test fun ordinaryEntryIsVisibleButDisabledWithoutOpeningAnyConversationJournal() {
        open()
        compose.onNodeWithText("Conversation setup is not enabled in this build.").assertIsDisplayed()
        compose.onNodeWithText("Select conversation setup file").assertIsNotEnabled()
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        click("Close conversation review")
        compose.onNodeWithText("Open conversation review").assertExists()
    }
    @Test fun consentIsExplicitAndDeclineClosesThenReopenCreatesFreshController() {
        installFixture()
        compose.onNodeWithText(ConversationActivationCodec.DISCLOSURE).assertExists()
        assertTrue(ports[0].actions.isEmpty())
        click("Not now"); assertEquals(listOf("decline:$request:1"), ports[0].actions)
        assertEquals(1, handles[0].closes)
        click("Open conversation review")
        compose.runOnIdle {
            compose.activity.acceptConversationSetupFile(Uri.EMPTY)
            field("conversationSelectedLine", line to 1L); field("conversationVerifiedLineLabel", "Fixture line")
        }
        click("Review selected conversation")
        assertEquals(2, handles.size); assertTrue(ports[1].actions.isEmpty())
    }
    @Test fun mismatchedLineCannotEnableAgreement() {
        installFixture(verifiedLabel = null)
        compose.onNodeWithText("Phone line: Unverified").assertExists()
        compose.onNodeWithText("Agree and continue").assertIsNotEnabled()
        click("Not now"); assertEquals(1, ports[0].actions.size)
    }
    @Test fun approvalAndStopRemainPendingUntilActualPortObservation() {
        installFixture(); click("Agree and continue")
        assertEquals(listOf("approve:$request:1"), ports[0].actions)
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertDoesNotExist()
        emit(ConversationPresentationSnapshot(2, ConversationPresentationPhase.PREPARING))
        compose.onNodeWithText("Content transfer: Preparing \u2014 capture is not confirmed").assertExists()
        emit(ConversationPresentationSnapshot(3, ConversationPresentationPhase.CONFIRMED_ACTIVE, interval, line, 1, 60000, true))
        click("Stop content transfer"); assertEquals("stop:$interval:3", ports[0].actions.last())
        compose.onNodeWithText("Content transfer: Interval closed").assertDoesNotExist()
        emit(ConversationPresentationSnapshot(4, ConversationPresentationPhase.DURABLY_CLOSED,
            intervalId = interval, close = ConversationCloseOutcome.DURABLY_CLOSED))
        compose.onNodeWithText("Content transfer: Interval closed").assertExists()
    }
    @Test fun backgroundClosesOwnedHandleAndDoesNotRestoreReviewOnResume() {
        installFixture()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        assertEquals(1, handles[0].closes)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED); compose.waitForIdle()
        compose.onNodeWithText("Conversation review").assertDoesNotExist()
        compose.onNodeWithText("Agree and continue").assertDoesNotExist()
        assertTrue(ports[0].actions.isEmpty())
    }
    @Test fun explicitCloseFailureCannotBeDiscardedByReopening() {
        installFixture(closeFailure = true); click("Close conversation review")
        click("Open conversation review")
        compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
        compose.onNodeWithText("Review closure could not be completed. Content transfer is not confirmed.").assertExists()
        assertEquals(1, handles.size)
    }
    @Test fun cancellingPublicFileSelectionCannotStartSetup() {
        var created = 0
        compose.runOnIdle {
            compose.activity.conversationSetupEnabled = true
            compose.activity.conversationHandleFactory = { _, _ -> created++; Handle({}, false) }
        }
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(null) }
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
        assertEquals(0, created)
    }
    @Test fun callbackAfterBackgroundCannotRestoreConsentOrAuthority() {
        lateinit var late: (ConversationPresentationPort) -> Unit
        val handle = Handle({}, false)
        compose.runOnIdle {
            compose.activity.conversationSetupEnabled = true
            compose.activity.conversationHandleFactory = { _, ready -> late = ready; handle }
        }
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Review selected conversation")
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.runOnIdle { late(Port()) }; compose.waitForIdle()
        assertEquals(1, handle.closes)
        compose.onNodeWithText("Agree and continue").assertDoesNotExist()
        compose.onNodeWithText("Conversation review").assertDoesNotExist()
    }
    @Test fun largeTextConsentChoicesAndCloseRemainReachableAndStacked() {
        compose.runOnIdle {
            val config = Configuration(compose.activity.resources.configuration).apply { fontScale = 2f }
            compose.activity.resources.updateConfiguration(config, compose.activity.resources.displayMetrics)
            compose.activity.window.decorView.dispatchConfigurationChanged(config)
        }
        installFixture()
        val agree = compose.onNodeWithText("Agree and continue")
        val decline = compose.onNodeWithText("Not now")
        agree.performScrollTo().assertIsDisplayed()
        val a = agree.getUnclippedBoundsInRoot(); val b = decline.getUnclippedBoundsInRoot()
        assertTrue(a.bottom <= b.top)
        assertTrue(a.bottom - a.top >= 48.dp && b.bottom - b.top >= 48.dp)
        decline.performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Close conversation review").assertIsDisplayed()
    }
    @Test @Config(qualifiers = "w640dp-h320dp-land")
    fun landscapeEntryKeepsCloseReachableWithReleasedResizeMode() {
        assertEquals(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE,
            compose.activity.window.attributes.softInputMode and android.view.WindowManager.LayoutParams.SOFT_INPUT_MASK_ADJUST)
        open()
        compose.onNodeWithText("Close conversation review").assertIsDisplayed()
        click("Close conversation review")
        compose.onNodeWithText("Open conversation review").assertExists()
    }

    private class Handle(val ready: () -> Unit, val failure: Boolean) : ConversationSetupEntrySession.Handle {
        var closes = 0
        override fun begin(): Boolean { ready(); return true }
        override fun close() { closes++; if (failure) error("private details") }
    }
    private inner class Port : ConversationPresentationPort {
        val actions = mutableListOf<String>()
        private var listener: ((ConversationPresentationSnapshot) -> Unit)? = null
        private var state = ConversationPresentationSnapshot(1, ConversationPresentationPhase.AWAITING_PHONE_REVIEW,
            review = ConversationPhoneReview(request, interval, line, 1, "+12", ConversationActivationCodec.DISCLOSURE,
                "conversation-content-v1", Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray()), 60000))
        override fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable {
            this.listener = listener; listener(state); return AutoCloseable { this.listener = null }
        }
        fun emit(value: ConversationPresentationSnapshot) { state = value; listener?.invoke(value) }
        override fun refresh() = Unit
        override fun approvePhoneReview(requestId: String, observedVersion: Long) { actions += "approve:$requestId:$observedVersion" }
        override fun declinePhoneReview(requestId: String, observedVersion: Long) { actions += "decline:$requestId:$observedVersion" }
        override fun requestStop(intervalId: String, observedVersion: Long) { actions += "stop:$intervalId:$observedVersion" }
    }
}
