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
        instrumentation.waitForIdleSync()
        fun click(label: String) {
            val deadline = SystemClock.elapsedRealtime() + 5000
            while (node(label) == null && SystemClock.elapsedRealtime() < deadline) Thread.sleep(25)
            val action = checkNotNull(node(label)) { "Missing action: $label" }
            assertTrue(action.isEnabled); assertTrue(action.performAction(AccessibilityNodeInfo.ACTION_CLICK))
            instrumentation.waitForIdleSync()
        }
        try {
            click("Open conversation review")
            assertFalse(activity.conversationSetupEnabled)
            assertFalse(checkNotNull(node("Enable review for this session")).isEnabled)
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
            assertTrue(matchingText("The selected conversation could not be verified. Check pairing, the selected line and the setup file.").isNotEmpty())
            assertTrue(matchingText("Agree and continue").isEmpty())
            assertTrue(matchingText("Content transfer: Confirmed for this interval").isEmpty())
            assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(context.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
            click("Close conversation review")
            click("Open conversation review")
            assertFalse(checkNotNull(node("Enable review for this session")).isEnabled)
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
            check(candidate.delete())
        }
    }
}
