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
import java.security.KeyStore
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real no-host controls on a disposable emulator; never creates a key, host or radio operation. */
@RunWith(AndroidJUnit4::class)
class EnrollmentConsentBoundaryDeviceTest {
    @Test fun enrollmentAndIndependentChoicesRefuseWithoutCreatingAuthority() {
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
        fun keyInventory(): Set<String> = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .aliases().toList().toSet()
        fun fileInventory(): Map<String, String> {
            val roots = listOf(context.filesDir, context.noBackupFilesDir, context.getDatabasePath("inventory").parentFile!!)
            return roots.flatMapIndexed { index, root ->
                if (!root.exists()) emptyList() else root.walkTopDown().filter { it.isFile }.map { file ->
                    "$index/${file.relativeTo(root).path}" to MessageDigest.getInstance("SHA-256")
                        .digest(file.readBytes()).joinToString("") { "%02x".format(it) }
                }.toList()
            }.toMap()
        }
        fun assertChoicesOff() = instrumentation.runOnMainSync {
            assertFalse(activity.conversationSetupEnabled)
            assertFalse(activity.conversationRepliesEnabled)
        }
        fun awaitText(label: String) = awaitVisible(label) { matchingText(label).firstOrNull() }
        fun closeEnrollment() {
            val oldWindow = checkNotNull(instrumentation.uiAutomation.rootInActiveWindow).windowId
            click("Close enrollment and return to review")
            val deadline = SystemClock.elapsedRealtime() + 5000
            var window = instrumentation.uiAutomation.rootInActiveWindow
            while ((window == null || window.windowId == oldWindow) && SystemClock.elapsedRealtime() < deadline) {
                Thread.sleep(25); window = instrumentation.uiAutomation.rootInActiveWindow
            }
            assertNotEquals(oldWindow, checkNotNull(window).windowId)
            assertTrue(matchingText("Close enrollment and return to review").isEmpty())
        }
        try {
            assertNull("This isolated rejection fixture must have no authenticated host",
                ConversationSocketComposition.currentAuthenticatedIdentity())
            click("Open conversation review")
            assertChoicesOff()
            val keysBefore = keyInventory()
            val filesBefore = fileInventory()
            click("Enroll conversation keys and compared root")
            awaitNode("Enroll hardware reader and journal protection", enabled = true)
            closeEnrollment()
            assertEquals("Opening and closing enrollment must not create keys", keysBefore, keyInventory())
            assertEquals("Opening and closing enrollment must not alter retained files", filesBefore, fileInventory())
            click("Enroll conversation keys and compared root")
            click("Enroll hardware reader and journal protection")
            awaitText("Enrollment refused. Check the current paired connection, selected approved line, hardware eligibility and independent root comparison. Existing protected state may require recovery.")
            assertEquals("Unauthenticated enrollment must refuse before key creation", keysBefore, keyInventory())
            assertNoConversationAuthority()
            closeEnrollment()
            candidate.writeBytes(byteArrayOf(1))
            instrumentation.runOnMainSync { activity.acceptConversationSetupFile(Uri.fromFile(candidate)) }
            click("Enable review for this session")
            instrumentation.runOnMainSync {
                assertTrue(activity.conversationSetupEnabled)
                assertFalse("Review choice must not authorize replies", activity.conversationRepliesEnabled)
            }
            click("Allow approved replies for this session")
            instrumentation.runOnMainSync { assertTrue(activity.conversationRepliesEnabled) }
            instrumentation.runOnMainSync { activity.acceptConversationSetupFile(Uri.fromFile(candidate)) }
            assertChoicesOff()
            click("Enable review for this session")
            click("Review selected conversation")
            awaitText("The selected conversation could not be verified. Check pairing, the selected line and the setup file.")
            assertChoicesOff()
            assertNoConversationAuthority()
            assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(context.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
            assertEquals(keysBefore, keyInventory())
            instrumentation.runOnMainSync { activity.acceptConversationSetupFile(Uri.fromFile(candidate)) }
            click("Enable review for this session")
            click("Allow approved replies for this session")
            instrumentation.runOnMainSync {
                assertTrue(activity.conversationSetupEnabled)
                assertTrue(activity.conversationRepliesEnabled)
                instrumentation.callActivityOnPause(activity)
            }
            assertChoicesOff()
            assertNoConversationAuthority()
            assertEquals(keysBefore, keyInventory())
            assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(context.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
            check(candidate.delete())
        }
    }
}
