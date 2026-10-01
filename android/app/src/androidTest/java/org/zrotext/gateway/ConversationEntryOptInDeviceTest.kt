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
        fun node(label: String): AccessibilityNodeInfo? = instrumentation.uiAutomation.rootInActiveWindow
            ?.findAccessibilityNodeInfosByText(label)?.firstOrNull { it.text?.toString() == label && it.isClickable }
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
            val root = checkNotNull(instrumentation.uiAutomation.rootInActiveWindow)
            assertTrue(root.findAccessibilityNodeInfosByText("The selected conversation could not be verified.").isNotEmpty())
            assertTrue(root.findAccessibilityNodeInfosByText("Agree and continue").isEmpty())
            assertTrue(root.findAccessibilityNodeInfosByText("Content transfer: Confirmed").isEmpty())
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
