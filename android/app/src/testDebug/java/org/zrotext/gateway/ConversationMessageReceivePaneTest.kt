// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ConversationMessageReceivePaneTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val reference = "00000000-0000-0000-0000-000000000004"

    @Test fun unavailableAuthorityDisablesReceiveEvenWithCompleteReference() {
        var receives = 0
        withPane {
            ConversationMessageReceivePane(reference, false, ConversationMessageReceiveController.Outcome.IDLE,
                {}, { receives++ }, {})
        }.use {
            compose.onNodeWithText("Message reference").assertIsNotEnabled()
            compose.onNodeWithText("Receive and verify message").assertIsNotEnabled()
            assertEquals(0, receives)
            val guidance = compose.onNodeWithText("The current conversation must be approved and active.").fetchSemanticsNode()
            assertFalse(guidance.config.contains(SemanticsProperties.LiveRegion))
        }
    }
    @Test fun busyReceiveExposesAccessibleCancellationAndAnnouncesRealOutcome() {
        var cancels = 0
        withPane {
            ConversationMessageReceivePane(reference, true, ConversationMessageReceiveController.Outcome.RECEIVING,
                {}, { error("Busy action must not receive") }, { cancels++ })
        }.use { density ->
            compose.onNodeWithText("Receive and verify message").assertIsNotEnabled()
            val cancel = compose.onNodeWithText("Cancel message review")
            val node = cancel.fetchSemanticsNode()
            assertTrue(node.size.width / density.value >= 48f)
            assertTrue(node.size.height / density.value >= 48f)
            cancel.performClick(); assertEquals(1, cancels)
            val status = compose.onNodeWithText("Receiving and verifying the confirmed message…").fetchSemanticsNode()
            assertEquals(LiveRegionMode.Polite, status.config[SemanticsProperties.LiveRegion])
        }
    }
    private class Host(val value: Float, val destroy: () -> Unit) : AutoCloseable {
        override fun close() = destroy()
    }
    private fun withPane(content: @androidx.compose.runtime.Composable () -> Unit): Host {
        val activity = Robolectric.buildActivity(ComponentActivity::class.java).setup().visible()
        activity.get().setContent(content = content)
        compose.waitForIdle()
        return Host(activity.get().resources.displayMetrics.density) { activity.pause().stop().destroy() }
    }
}
