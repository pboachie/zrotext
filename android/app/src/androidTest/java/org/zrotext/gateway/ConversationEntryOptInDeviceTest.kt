// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
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
        fun matchingText(label: String): List<AccessibilityNodeInfo> {
            val root = instrumentation.uiAutomation.rootInActiveWindow ?: return emptyList()
            val matches = mutableListOf<AccessibilityNodeInfo>()
            fun visit(current: AccessibilityNodeInfo) {
                if (current.text?.toString() == label) matches.add(current)
                for (index in 0 until current.childCount) current.getChild(index)?.let(::visit)
            }
            visit(root)
            return matches
        }
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
        fun scrollToControl(label: String): Boolean {
            val direction = if (label == "Open conversation review") AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
                else AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
            val root = instrumentation.uiAutomation.rootInActiveWindow ?: return false
            fun scroll(current: AccessibilityNodeInfo): Boolean {
                if (current.isScrollable && current.performAction(direction)) return true
                for (index in 0 until current.childCount) {
                    if (current.getChild(index)?.let(::scroll) == true) return true
                }
                return false
            }
            return scroll(root)
        }
        instrumentation.waitForIdleSync()
        fun awaitNode(label: String, enabled: Boolean): AccessibilityNodeInfo {
            val deadline = SystemClock.elapsedRealtime() + 5000
            var action = node(label)
            var scrolls = 0
            while ((action == null || action.isEnabled != enabled) && SystemClock.elapsedRealtime() < deadline) {
                // File-selection status can shrink the real scroll viewport. Discover the
                // exact control through accessibility scrolling, without changing app state.
                if (action == null && label in setOf("Open conversation review", "Enable review for this session", "Review selected conversation") &&
                    scrolls < 6 && scrollToControl(label)) {
                    scrolls++
                    instrumentation.waitForIdleSync()
                    Thread.sleep(250) // Allow the accessibility scroll animation to expose its new nodes.
                }
                Thread.sleep(25)
                action = node(label)
            }
            return checkNotNull(action) { "Missing control: $label" }
        }
        fun click(label: String) {
            val action = awaitNode(label, enabled = true)
            assertTrue("Control is not enabled: $label", action.isEnabled)
            assertTrue("Control did not accept click: $label", action.performAction(AccessibilityNodeInfo.ACTION_CLICK))
            instrumentation.waitForIdleSync()
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
            val renderedDeadline = SystemClock.elapsedRealtime() + 5000
            while (matchingText(rejection).isEmpty() && SystemClock.elapsedRealtime() < renderedDeadline) Thread.sleep(25)
            assertTrue(matchingText(rejection).isNotEmpty())
            assertTrue(matchingText("Agree and continue").isEmpty())
            assertTrue(matchingText("Content transfer: Confirmed for this interval").isEmpty())
            assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(context.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
            click("Close conversation review")
            click("Open conversation review")
            assertFalse(awaitNode("Enable review for this session", enabled = false).isEnabled)
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
            check(candidate.delete())
        }
    }
}
