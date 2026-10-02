// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.runtime.State
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Ordinary-package entry rejection on an isolated emulator. No mock port, key, session or radio. */
@RunWith(AndroidJUnit4::class)
class ConversationEntryOptInDeviceTest {
    @Test fun explicitOptInReachesOrdinarySetupAndRejectsMissingCustodyWithoutApproval() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        assumeTrue(InstrumentationRegistry.getArguments().getString("entryOptInIsolatedEmulator") == "true")
        assumeTrue(Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context = instrumentation.targetContext
        val activity = instrumentation.startActivitySync(Intent(context, MainActivity::class.java)
            .putExtra("gateway_screen", "CONNECTION").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as MainActivity
        val candidate = File.createTempFile("public-setup-", ".bin", context.cacheDir)
        fun accessibilityNodes(): List<AccessibilityNodeInfo> {
            val root = instrumentation.uiAutomation.rootInActiveWindow ?: return emptyList()
            val nodes = mutableListOf<AccessibilityNodeInfo>()
            fun visit(current: AccessibilityNodeInfo) {
                nodes.add(current)
                for (index in 0 until current.childCount) current.getChild(index)?.let(::visit)
            }
            visit(root)
            return nodes
        }
        fun matchingText(label: String): List<AccessibilityNodeInfo> =
            accessibilityNodes().filter { it.text?.toString() == label }
        fun node(label: String): AccessibilityNodeInfo? {
            for (textNode in matchingText(label)) {
                // Compose exposes button text as a non-clickable child of the action node.
                var action: AccessibilityNodeInfo? = textNode
                while (action != null) {
                    if (action.isClickable) return action
                    action = action.parent
                }
            }
            return null
        }
        instrumentation.waitForIdleSync()
        fun awaitVisible(
            label: String,
            enabled: Boolean? = null,
            find: () -> AccessibilityNodeInfo?,
        ): AccessibilityNodeInfo {
            val deadline = SystemClock.elapsedRealtime() + 5000
            var direction = AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
            var scrollAttempts = 0
            var lastScroll = 0L
            var result = find()
            while ((result == null || !result.isVisibleToUser ||
                    (enabled != null && result.isEnabled != enabled)) &&
                SystemClock.elapsedRealtime() < deadline) {
                // Offscreen Compose nodes are omitted from the accessibility viewport.
                // Search the real scroll container in both directions; never click coordinates.
                if ((result == null || !result.isVisibleToUser) && scrollAttempts < 20 &&
                    SystemClock.elapsedRealtime() - lastScroll >= 200) {
                    val scroller = accessibilityNodes().firstOrNull { it.isScrollable && it.isVisibleToUser }
                    if (scroller != null) {
                        if (!scroller.performAction(direction)) direction =
                            if (direction == AccessibilityNodeInfo.ACTION_SCROLL_FORWARD)
                                AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD else AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
                        scrollAttempts++
                        lastScroll = SystemClock.elapsedRealtime()
                    }
                }
                Thread.sleep(25)
                result = find()
            }
            val visible = checkNotNull(result) { "Missing control: $label" }
            assertTrue("Control is not visible: $label", visible.isVisibleToUser)
            return visible
        }
        fun awaitNode(label: String, enabled: Boolean): AccessibilityNodeInfo =
            awaitVisible(label, enabled) { node(label) }
        fun click(label: String) {
            val action = awaitNode(label, enabled = true)
            assertTrue("Control is not enabled: $label", action.isEnabled)
            assertTrue("Control did not accept click: $label", action.performAction(AccessibilityNodeInfo.ACTION_CLICK))
            instrumentation.waitForIdleSync()
        }
        fun assertNoConversationAuthority() {
            // Viewport checks alone cannot exclude an offscreen pane. Read the actual
            // activity's state without replacing its factory, port or controller.
            instrumentation.runOnMainSync {
                val port = MainActivity::class.java.getDeclaredField("conversationPort\$delegate")
                    .apply { isAccessible = true }.get(activity) as State<*>
                val controller = MainActivity::class.java.getDeclaredField("conversationController")
                    .apply { isAccessible = true }.get(activity)
                assertNull("A rejected setup must not mount a presentation port", port.value)
                assertNull("A rejected setup must not install a controller", controller)
            }
            assertTrue(matchingText("Agree and continue").isEmpty())
            assertTrue(matchingText("Content transfer: Confirmed for this interval").isEmpty())
        }
        try {
            click("Open conversation review")
            assertFalse(activity.conversationSetupEnabled)
            assertFalse(awaitNode("Enable review for this session", enabled = false).isEnabled)
            candidate.writeBytes(byteArrayOf(1))
            // Simulate the public picker result only; the actual provider/controller entry is unchanged.
            instrumentation.runOnMainSync { activity.acceptConversationSetupFile(Uri.fromFile(candidate)) }
            instrumentation.waitForIdleSync()
            click("Enable review for this session")
            assertTrue(activity.conversationSetupEnabled)
            assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(context.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
            assertNull(activity.conversationHandleFactory)
            click("Review selected conversation")
            val deadline = SystemClock.elapsedRealtime() + 5000
            while (activity.conversationSetupEnabled && SystemClock.elapsedRealtime() < deadline) Thread.sleep(25)
            assertFalse(activity.conversationSetupEnabled)
            val rejection = "The selected conversation could not be verified. Check pairing, the selected line and the setup file."
            awaitVisible(rejection) { matchingText(rejection).firstOrNull() }
            assertTrue(matchingText(rejection).isNotEmpty())
            assertNoConversationAuthority()
            assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(context.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
            val dialogWindowId = checkNotNull(instrumentation.uiAutomation.rootInActiveWindow).windowId
            click("Close conversation review")
            // Dialog dismissal outlives Compose's idle callback. Wait for its window to
            // leave before resolving the underlying page's fresh action node.
            val dismissalDeadline = SystemClock.elapsedRealtime() + 5000
            var pageWindow = instrumentation.uiAutomation.rootInActiveWindow
            while ((pageWindow == null || pageWindow.windowId == dialogWindowId) &&
                SystemClock.elapsedRealtime() < dismissalDeadline) {
                Thread.sleep(25)
                pageWindow = instrumentation.uiAutomation.rootInActiveWindow
            }
            pageWindow = checkNotNull(pageWindow) { "Missing page after conversation dismissal" }
            assertNotEquals("Conversation dialog did not dismiss", dialogWindowId, pageWindow.windowId)
            assertTrue("Conversation close control remains mounted", matchingText("Close conversation review").isEmpty())
            click("Open conversation review")
            assertFalse(awaitNode("Enable review for this session", enabled = false).isEnabled)
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
            check(candidate.delete())
        }
    }
}
