// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.net.Uri
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.Lifecycle
import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExternalResource
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** Synthetic public packet only: tests the actual destination/lifecycle bridge, not hardware enrollment. */
@RunWith(RobolectricTestRunner::class) @Config(sdk = [34], qualifiers = "w320dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class ConversationPublicExportEntryTest {
    private val compose = createAndroidComposeRule<MainActivity>()
    @get:Rule val rules: RuleChain = RuleChain.outerRule(object : ExternalResource() {
        override fun before() {
            val app = org.robolectric.RuntimeEnvironment.getApplication()
            org.robolectric.Shadows.shadowOf(app).grantPermissions("${app.packageName}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
        }
    }).around(compose)
    private fun packet() = ConversationPhonePublicExport("01010101-0101-0101-0101-010101010101",
        "02020202-0202-0202-0202-020202020202", "03030303-0303-0303-0303-030303030303", 7,
        hex("047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"),
        hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"), {}, android.os.SystemClock::elapsedRealtime)
    private fun pending(value: ConversationPhonePublicExport) = compose.runOnIdle {
        MainActivity::class.java.getDeclaredField("pendingConversationPhoneExport").apply { isAccessible = true }.set(compose.activity, value)
    }
    private fun output() = File(compose.activity.cacheDir, "synthetic-public-export.bin").also { it.delete() }
    private fun choicesOff() = compose.runOnIdle {
        assertFalse(compose.activity.conversationSetupEnabled)
        assertFalse(compose.activity.conversationRepliesEnabled)
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
        assertFalse(compose.activity.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
    }
    @Test fun returningFromDestinationPickerSavesOnlyPublicPacketAndShowsExactFingerprintWithoutConsent() {
        val public = packet(); val file = output(); pending(public)
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        compose.activity.acceptConversationPublicExportDestination(Uri.fromFile(file))
        assertFalse(file.exists())
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.waitUntil(10000) { file.exists() && file.length() == 223L }
        compose.waitUntil(10000) { compose.onAllNodesWithText(public.fingerprintHex, substring = true).fetchSemanticsNodes().isNotEmpty() }
        assertArrayEquals(public.publicBytes(), file.readBytes()); choicesOff(); assertTrue(file.delete())
    }
    @Test fun cancellingDestinationPickerDiscardsPendingPublicPacketAndIgnoresLateResult() {
        val file = output(); pending(packet())
        compose.runOnIdle {
            compose.activity.acceptConversationPublicExportDestination(null)
            compose.activity.acceptConversationPublicExportDestination(Uri.fromFile(file))
        }
        assertFalse(file.exists()); choicesOff()
    }
    @Test fun explicitClosureFencesDeferredDestinationAndDestructionIgnoresLateResult() {
        val file = output(); pending(packet())
        compose.activityRule.scenario.moveToState(Lifecycle.State.STARTED)
        compose.activity.acceptConversationPublicExportDestination(Uri.fromFile(file))
        MainActivity::class.java.getDeclaredMethod("closeConversationEntry", Boolean::class.javaPrimitiveType)
            .apply { isAccessible = true }.invoke(compose.activity, false)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        assertFalse(file.exists()); choicesOff()
        pending(packet()); val activity = compose.activity
        compose.activityRule.scenario.moveToState(Lifecycle.State.DESTROYED)
        activity.acceptConversationPublicExportDestination(Uri.fromFile(file))
        assertFalse(file.exists())
    }
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
