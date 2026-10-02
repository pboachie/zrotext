// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.net.Uri
import android.content.Intent
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import androidx.compose.ui.unit.dp
import android.content.res.Configuration
import org.junit.Assert.*
import org.junit.Rule
import org.junit.rules.ExternalResource
import org.junit.rules.RuleChain
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Actual MainActivity navigation with synthetic presentation ports; no service or radio. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28, 34], qualifiers = "w320dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ConversationMainEntryTest {
    val compose = createAndroidComposeRule<MainActivity>()
    @get:Rule val rules: RuleChain = RuleChain.outerRule(object : ExternalResource() {
        override fun before() {
            // Android grants this merged AndroidX signature permission at installation.
            // Robolectric needs the grant before MainActivity registers Home's receiver.
            val app = org.robolectric.RuntimeEnvironment.getApplication()
            org.robolectric.Shadows.shadowOf(app)
                .grantPermissions("${app.packageName}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
        }
    }).around(compose)
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
        click("Enable review for this session"); click("Review selected conversation"); compose.waitForIdle()
    }
    private fun field(name: String, value: Any?) {
        MainActivity::class.java.getDeclaredField(name).apply { isAccessible = true }.set(compose.activity, value)
    }
    private fun emit(state: ConversationPresentationSnapshot) {
        compose.runOnIdle { ports.last().emit(state) }; compose.waitForIdle()
    }

    @Test fun ordinaryEntryIsVisibleButDisabledWithoutOpeningAnyConversationJournal() {
        open()
        compose.onNodeWithText("Review is off for this session.").assertIsDisplayed()
        compose.onNodeWithText("Select conversation setup file").assertIsEnabled()
        compose.onNodeWithText("Enable review for this session").assertIsNotEnabled()
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        click("Close conversation review")
        compose.onNodeWithText("Open conversation review").assertExists()
    }
    @Test fun selectingPublicCandidateAndOptingInDoNotOpenSetupOrGrantPhoneApproval() {
        var created = 0
        compose.runOnIdle { compose.activity.conversationHandleFactory = { _, _ -> created++; Handle({}, false) } }
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
        assertFalse(compose.activity.conversationSetupEnabled)
        click("Enable review for this session")
        compose.onNodeWithText("Review selected conversation").assertIsEnabled()
        assertEquals(0, created)
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        click("Close conversation review"); assertFalse(compose.activity.conversationSetupEnabled)
        click("Open conversation review")
        compose.onNodeWithText("Enable review for this session").assertIsNotEnabled()
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
    }
    @Test fun ordinaryOptInActuallyCallsProviderAndRejectsMissingAuthenticatedCustodyWithoutPublishing() {
        val uri = Uri.parse("content://fixture.invalid/public-setup")
        org.robolectric.Shadows.shadowOf(compose.activity.contentResolver)
            .registerInputStream(uri, java.io.ByteArrayInputStream(byteArrayOf(1)))
        // No handle factory or presentation port is replaced: this executes the ordinary provider path.
        assertNull(compose.activity.conversationHandleFactory)
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(uri) }
        click("Enable review for this session"); click("Review selected conversation")
        compose.waitUntil(5000) {
            compose.onAllNodesWithText("The selected conversation could not be verified. Check pairing, the selected line and the setup file.")
                .fetchSemanticsNodes().isNotEmpty()
        }
        assertFalse(compose.activity.conversationSetupEnabled)
        compose.onNodeWithText("Agree and continue").assertDoesNotExist()
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertDoesNotExist()
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
    }
    @Test fun pickerReturnRequiresFreshOptInAndCannotCarryForegroundApproval() {
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session")
        compose.runOnIdle { field("conversationPickEpoch", fieldValue("conversationUiEpoch")) }
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        assertFalse(compose.activity.conversationSetupEnabled)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY); field("conversationPickEpoch", null) }
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
        click("Enable review for this session")
        compose.onNodeWithText("Review selected conversation").assertIsEnabled()
    }
    @Test fun candidateReplacementAndCancellationRequireFreshOptInWithoutBackground() {
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session"); assertTrue(compose.activity.conversationSetupEnabled)
        compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.parse("content://fixture.invalid/replacement")) }
        assertFalse(compose.activity.conversationSetupEnabled)
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
        click("Enable review for this session")
        compose.runOnIdle { compose.activity.acceptConversationSetupFile(null) }
        assertFalse(compose.activity.conversationSetupEnabled)
        compose.onNodeWithText("Enable review for this session").assertIsNotEnabled()
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
    }
    private fun fieldValue(name: String): Any? = MainActivity::class.java.getDeclaredField(name)
        .apply { isAccessible = true }.get(compose.activity)
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
        click("Enable review for this session"); click("Review selected conversation")
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
        assertFalse(compose.activity.conversationSetupEnabled)
        compose.onNodeWithText("Content transfer: Interval closed").assertDoesNotExist()
        emit(ConversationPresentationSnapshot(4, ConversationPresentationPhase.DURABLY_CLOSED,
            intervalId = interval, close = ConversationCloseOutcome.DURABLY_CLOSED))
        compose.onNodeWithText("Content transfer: Interval closed").assertExists()
    }
    @Test fun backgroundClosesOwnedHandleAndDoesNotRestoreReviewOnResume() {
        installFixture()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        assertEquals(1, handles[0].closes)
        assertFalse(compose.activity.conversationSetupEnabled)
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
    @Test fun pausedVisibleReviewRevokesOptInAndClosesItsSetupBeforeStop() {
        installFixture()
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        assertFalse(compose.activity.conversationSetupEnabled)
        assertEquals(1, handles[0].closes)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitForIdle()
        compose.onNodeWithText("Conversation review").assertDoesNotExist()
        click("Open conversation review")
        compose.onNodeWithText("Review selected conversation").assertIsNotEnabled()
    }
    @Test fun cancellingPublicFileSelectionCannotStartSetup() {
        var created = 0
        compose.runOnIdle {
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
            compose.activity.conversationHandleFactory = { _, ready -> late = ready; handle }
        }
        open(); compose.runOnIdle { compose.activity.acceptConversationSetupFile(Uri.EMPTY) }
        click("Enable review for this session"); click("Review selected conversation")
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
    private fun activeReplyFixture() {
        installFixture(); click("Agree and continue")
        emit(ConversationPresentationSnapshot(2, ConversationPresentationPhase.CONFIRMED_ACTIVE, interval, line, 1, 60000, true))
        compose.onNodeWithText("Import public reply authority").assertIsEnabled()
        compose.onNodeWithText("Select reply authority file").assertDoesNotExist()
    }
    @Test fun foregroundPasteRequiresExplicitActionAndPassesExactCandidateWithoutClosingReview() {
        activeReplyFixture()
        val calls = AtomicInteger(); val actual = AtomicReference<Pair<ByteArray, ByteArray>>()
        compose.runOnIdle { compose.activity.conversationReplyInstaller = { bytes, signer, complete ->
            actual.set(bytes to signer); calls.incrementAndGet(); complete(true)
        } }
        val (text, expected, signer) = conversationReplyTextFixture()
        click("Import public reply authority")
        compose.onNodeWithText("Public reply authority (base64)").performTextInput(text)
        assertEquals(0, calls.get())
        click("Verify pasted reply authority")
        compose.waitUntil(5000) { calls.get() == 1 }
        compose.waitUntil(5000) { compose.onAllNodesWithText("Reply authority verified for the current interval. This action did not send a message.").fetchSemanticsNodes().isNotEmpty() }
        assertArrayEquals(expected, actual.get().first); assertArrayEquals(signer, actual.get().second)
        assertEquals(0, handles[0].closes)
        assertEquals(listOf("approve:$request:1"), ports[0].actions)
    }
    @Test fun cancellingForegroundPasteDoesNotApplyOrRemountTheConsentPane() {
        activeReplyFixture(); val subscriptions = ports[0].subscriptions
        val calls = AtomicInteger()
        compose.runOnIdle { compose.activity.conversationReplyInstaller = { _, _, _ -> calls.incrementAndGet() } }
        click("Import public reply authority")
        compose.onNodeWithText("Public reply authority (base64)").performTextInput(conversationReplyTextFixture().first)
        click("Cancel reply import"); assertEquals(0, calls.get()); assertEquals(0, handles[0].closes)
        assertEquals(subscriptions, ports[0].subscriptions)
        click("Import public reply authority")
        compose.onNodeWithText("Verify pasted reply authority").assertIsNotEnabled()
    }
    @Test fun externalPickerBackgroundStopsActiveReviewAndCannotResumePendingImport() {
        activeReplyFixture(); val calls = AtomicInteger()
        compose.runOnIdle { compose.activity.conversationReplyInstaller = { _, _, _ -> calls.incrementAndGet() } }
        click("Import public reply authority")
        compose.onNodeWithText("Public reply authority (base64)").performTextInput(conversationReplyTextFixture().first)
        compose.runOnIdle { compose.activity.startActivity(Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/octet-stream")) }
        // Robolectric dispatches the lifecycle Android delivers when an external picker backgrounds the phone UI.
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED); compose.waitForIdle()
        assertEquals(1, handles[0].closes); assertEquals(0, calls.get())
        compose.onNodeWithText("Verify pasted reply authority").assertDoesNotExist()
        compose.onNodeWithText("Conversation review").assertDoesNotExist()
    }
    @Test fun completionAfterBackgroundCannotClaimVerifiedReplyAuthority() {
        activeReplyFixture(); val completion = AtomicReference<((Boolean) -> Unit)>()
        compose.runOnIdle { compose.activity.conversationReplyInstaller = { _, _, complete -> completion.set(complete) } }
        click("Import public reply authority")
        compose.onNodeWithText("Public reply authority (base64)").performTextInput(conversationReplyTextFixture().first)
        click("Verify pasted reply authority"); compose.waitUntil(5000) { completion.get() != null }
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.runOnIdle { completion.get()(true) }; compose.waitForIdle()
        compose.onNodeWithText("Reply authority verified for the current interval. This action did not send a message.").assertDoesNotExist()
        assertEquals(1, handles[0].closes)
    }
    @Test fun queuedImportRejectsOriginalLeaseExpiryBeforeTimerDelivery() {
        activeReplyFixture(); val calls = AtomicInteger()
        val worker = MainActivity::class.java.getDeclaredField("conversationWorker").apply { isAccessible = true }
            .get(compose.activity) as ExecutorService
        val started = CountDownLatch(1); val release = CountDownLatch(1); val drained = CountDownLatch(1)
        compose.runOnIdle { compose.activity.conversationReplyInstaller = { _, _, _ -> calls.incrementAndGet() } }
        click("Import public reply authority")
        compose.onNodeWithText("Public reply authority (base64)").performTextInput(conversationReplyTextFixture().first)
        worker.execute { started.countDown(); release.await(5, TimeUnit.SECONDS) }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        try {
            click("Verify pasted reply authority")
            compose.runOnIdle {
                // Do not deliver a UI expiry timer before the queued worker checks the original deadline.
                org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofMillis(61000))
                release.countDown(); worker.execute { drained.countDown() }
                assertTrue(drained.await(5, TimeUnit.SECONDS)); assertEquals(0, calls.get())
            }
        } finally { release.countDown() }
        compose.waitForIdle()
        compose.onNodeWithText("Reply authority verified for the current interval. This action did not send a message.").assertDoesNotExist()
    }
    @Test fun newerActiveObservationInvalidatesPendingImportAndItsCompletion() {
        activeReplyFixture(); val completion = AtomicReference<((Boolean) -> Unit)>()
        compose.runOnIdle { compose.activity.conversationReplyInstaller = { _, _, complete -> completion.set(complete) } }
        click("Import public reply authority")
        compose.onNodeWithText("Public reply authority (base64)").performTextInput(conversationReplyTextFixture().first)
        click("Verify pasted reply authority"); compose.waitUntil(5000) { completion.get() != null }
        emit(ConversationPresentationSnapshot(3, ConversationPresentationPhase.CONFIRMED_ACTIVE, interval, line, 1, 60000, true))
        compose.runOnIdle { completion.get()(true) }; compose.waitForIdle()
        compose.onNodeWithText("Reply authority verified for the current interval. This action did not send a message.").assertDoesNotExist()
        assertEquals(0, handles[0].closes)
        click("Import public reply authority")
        compose.onNodeWithText("Verify pasted reply authority").assertIsNotEnabled()
    }
    @Test fun completionCannotClaimVerifiedAfterOriginalDeadlineBeforeTimerDelivery() {
        activeReplyFixture(); val completion = AtomicReference<((Boolean) -> Unit)>()
        compose.runOnIdle { compose.activity.conversationReplyInstaller = { _, _, complete -> completion.set(complete) } }
        click("Import public reply authority")
        compose.onNodeWithText("Public reply authority (base64)").performTextInput(conversationReplyTextFixture().first)
        click("Verify pasted reply authority"); compose.waitUntil(5000) { completion.get() != null }
        compose.runOnIdle {
            org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofMillis(61000))
            completion.get()(true)
        }
        compose.waitForIdle()
        compose.onNodeWithText("Reply authority verified for the current interval. This action did not send a message.").assertDoesNotExist()
    }

    private class Handle(val ready: () -> Unit, val failure: Boolean) : ConversationSetupEntrySession.Handle {
        var closes = 0
        override fun begin(): Boolean { ready(); return true }
        override fun close() { closes++; if (failure) error("private details") }
    }
    private inner class Port : ConversationPresentationPort {
        val actions = mutableListOf<String>()
        private val listeners = mutableListOf<(ConversationPresentationSnapshot) -> Unit>()
        var subscriptions = 0
        private var state = ConversationPresentationSnapshot(1, ConversationPresentationPhase.AWAITING_PHONE_REVIEW,
            review = ConversationPhoneReview(request, interval, line, 1, "+12", ConversationActivationCodec.DISCLOSURE,
                "conversation-content-v1", Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray()), 60000))
        override fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable {
            subscriptions++; listeners += listener; listener(state); return AutoCloseable { listeners.remove(listener) }
        }
        fun emit(value: ConversationPresentationSnapshot) { state = value; listeners.toList().forEach { it(value) } }
        override fun refresh() = Unit
        override fun approvePhoneReview(requestId: String, observedVersion: Long) { actions += "approve:$requestId:$observedVersion" }
        override fun declinePhoneReview(requestId: String, observedVersion: Long) { actions += "decline:$requestId:$observedVersion" }
        override fun requestStop(intervalId: String, observedVersion: Long) { actions += "stop:$intervalId:$observedVersion" }
    }
}
