// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import android.graphics.Bitmap
import java.io.File
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
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

/** Synthetic presentation journeys only: no service, receiver, browser transport or SMS mount. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28, 34], qualifiers = "w320dp-h480dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class FutureConversationFixtureJourneyTest {
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
    private val interval = UUID.randomUUID().toString()
    private val line = UUID.randomUUID().toString()
    private val request = UUID.randomUUID().toString()
    private fun review(version: Long, requestId: String = request) = ConversationPresentationSnapshot(
        version, ConversationPresentationPhase.AWAITING_PHONE_REVIEW,
        review = ConversationPhoneReview(requestId, interval, line, 1, "+12",
            ConversationActivationCodec.DISCLOSURE, "conversation-content-v1",
            Draft02OutboundPreparation.hash(ConversationActivationCodec.DISCLOSURE.toByteArray()), 60000))
    private fun mount(port: FixturePort) {
        compose.runOnIdle { compose.activity.setContent {
            GatewayTheme {
                Column(Modifier.fillMaxSize()) {
                    Text("Synthetic test - no carrier SMS")
                    Box(Modifier.weight(1f)) {
                        FutureConversationPane(port, { id, generation ->
                            if (id == line && generation == 1L) "Fixture phone line" else null
                        })
                    }
                }
            }
        } }
        compose.waitForIdle()
    }
    private fun emit(port: FixturePort, next: ConversationPresentationSnapshot) {
        compose.runOnIdle { port.emit(next) }; compose.waitForIdle()
    }
    private fun click(label: String) = compose.onNodeWithText(label).performScrollTo().performClick()

    private fun preview(name: String) {
        val directory = System.getProperty("zrotext.fixture.preview.dir") ?: return
        val target = File(directory).also { check(it.isDirectory) }
        val bitmap = compose.onRoot().captureToImage().asAndroidBitmap()
        File(target, "synthetic-phone-$name.png").outputStream().use {
            check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it))
        }
    }

    @Test fun phoneAgreementDoesNotImplyInstallAndStopWaitsForDurableClosure() {
        val port = FixturePort(review(1)); mount(port)
        assertTrue(port.actions.isEmpty())
        preview("approval")
        click("Agree and continue")
        assertEquals(listOf("approve:$request:1"), port.actions)
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertDoesNotExist()
        emit(port, ConversationPresentationSnapshot(2, ConversationPresentationPhase.PREPARING))
        compose.onNodeWithText("Content transfer: Preparing — capture is not confirmed").assertExists()
        compose.onNodeWithText("Stop content transfer").assertDoesNotExist()
        preview("pending-install")
        emit(port, ConversationPresentationSnapshot(3, ConversationPresentationPhase.CONFIRMED_ACTIVE,
            interval, line, 1, 60000, true))
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertExists()
        preview("confirmed-interval")
        click("Stop content transfer")
        assertEquals("stop:$interval:3", port.actions.last())
        compose.onNodeWithText("Content transfer: Interval closed").assertDoesNotExist()
        emit(port, ConversationPresentationSnapshot(4, ConversationPresentationPhase.PAUSING,
            intervalId = interval, close = ConversationCloseOutcome.IN_PROGRESS))
        compose.onNodeWithText("Content transfer: Stopping").assertExists()
        emit(port, ConversationPresentationSnapshot(5, ConversationPresentationPhase.DURABLY_CLOSED,
            intervalId = interval, close = ConversationCloseOutcome.DURABLY_CLOSED))
        compose.onNodeWithText("Content transfer: Interval closed").assertExists()
        compose.onNodeWithText("New capture and transfer are stopped. Retained encrypted content is deleted separately.").assertExists()
        assertEquals(2, port.actions.size)
        preview("durably-closed")
    }

    @Test fun recoveryRequiresFreshReviewAndDeclineCannotReactivate() {
        val port = FixturePort(ConversationPresentationSnapshot(1, ConversationPresentationPhase.OFF)); mount(port)
        emit(port, ConversationPresentationSnapshot(2, ConversationPresentationPhase.RECOVERING))
        compose.onNodeWithText("Content transfer: Verifying — capture is not confirmed").assertExists()
        compose.onNodeWithText("After a restart, a new interval and fresh phone approval are required.").assertExists()
        compose.onNodeWithText("Agree and continue").assertDoesNotExist()
        val fresh = UUID.randomUUID().toString()
        emit(port, review(3, fresh)); click("Not now")
        assertEquals(listOf("decline:$fresh:3"), port.actions)
        compose.onNodeWithText("Conversation with: +12").assertDoesNotExist()
        compose.onNodeWithText("Content transfer: Confirmed for this interval").assertDoesNotExist()
        click("Refresh status"); assertEquals(1, port.refreshes)
        assertEquals(1, port.actions.size)
    }

    @Test fun failedDurableStopNeverClaimsClosureAndRefreshCannotApprove() {
        val port = FixturePort(ConversationPresentationSnapshot(1, ConversationPresentationPhase.FAILURE,
            close = ConversationCloseOutcome.DISABLED_CLOSURE_FAILED,
            stopReason = ConversationStopReason.USER_STOP)); mount(port)
        compose.onNodeWithText("Content transfer: Capture disabled here; closure unconfirmed").assertExists()
        compose.onNodeWithText("Content transfer: Interval closed").assertDoesNotExist()
        compose.onNodeWithText("Agree and continue").assertDoesNotExist()
        compose.onNodeWithText("Stop content transfer").assertDoesNotExist()
        click("Refresh status"); assertEquals(1, port.refreshes); assertTrue(port.actions.isEmpty())
    }

    private class FixturePort(var state: ConversationPresentationSnapshot) : ConversationPresentationPort {
        private var listener: ((ConversationPresentationSnapshot) -> Unit)? = null
        val actions = mutableListOf<String>()
        var refreshes = 0
        override fun observe(listener: (ConversationPresentationSnapshot) -> Unit): AutoCloseable {
            this.listener = listener; listener(state)
            return AutoCloseable { this.listener = null }
        }
        fun emit(next: ConversationPresentationSnapshot) { state = next; listener?.invoke(next) }
        override fun refresh() { refreshes++ }
        override fun approvePhoneReview(requestId: String, observedVersion: Long) { actions += "approve:$requestId:$observedVersion" }
        override fun declinePhoneReview(requestId: String, observedVersion: Long) { actions += "decline:$requestId:$observedVersion" }
        override fun requestStop(intervalId: String, observedVersion: Long) { actions += "stop:$intervalId:$observedVersion" }
    }
}
