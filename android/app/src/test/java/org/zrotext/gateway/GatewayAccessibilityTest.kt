// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.Manifest
import android.view.accessibility.AccessibilityManager
import android.os.Looper
import android.telephony.SubscriptionManager
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.runtime.snapshots.Snapshot
import androidx.compose.ui.node.RootForTest
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import org.robolectric.shadows.ShadowSubscriptionManager.SubscriptionInfoBuilder
import java.time.Duration

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w360dp-h640dp")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@OptIn(ExperimentalComposeUiApi::class)
open class GatewayAccessibilityTest : GatewayAccessibilityChecks() {
    protected open val testFontScale = 2f
    override fun onScreen(page: String, check: (RootForTest) -> Unit) {
        RuntimeEnvironment.setFontScale(testFontScale)
        val app = RuntimeEnvironment.getApplication()
        shadowOf(app.getSystemService(AccessibilityManager::class.java)).setEnabled(true)
        shadowOf(app).grantPermissions(Manifest.permission.READ_PHONE_STATE)
        shadowOf(app.getSystemService(SubscriptionManager::class.java)).setActiveSubscriptionInfos(
            SubscriptionInfoBuilder.newBuilder().setId(1).setSimSlotIndex(0)
                .setDisplayName("Test SIM").buildSubscriptionInfo())
        val controller = Robolectric.buildActivity(MainActivity::class.java, Intent(app, MainActivity::class.java)
            .putExtra("gateway_screen", page.substringBefore('/'))
            .putExtra("gateway_setup_step", page.substringAfter('/', "OVERVIEW"))).setup().visible()
        try {
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300))
            val root = requireNotNull(findRoot(controller.get().window.decorView))
            root.forceAccessibilityForTesting(true)
            controller.get().window.decorView.requestLayout()
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300))
            root.measureAndLayoutForTest()
            check(root)
        } finally {
            controller.pause().stop().destroy()
            RuntimeEnvironment.setFontScale(1f)
        }
    }

    @Test fun choosingASimUpdatesItsSelectedStateAndDescription() = onScreen("SETUP/SIM") { root ->
        fun choice() = nodes(root).single { text(it) == "SIM 1: Test SIM" }
        assertFalse(choice().config[SemanticsProperties.Selected])
        assertEquals("Not selected", choice().config[SemanticsProperties.StateDescription])
        assertTrue(requireNotNull(choice().config[SemanticsActions.OnClick].action).invoke())
        // Direct semantics actions run outside a platform frame. Deliver their
        // pending snapshot changes before advancing the Robolectric UI clock.
        Snapshot.sendApplyNotifications()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300))
        root.measureAndLayoutForTest()
        assertTrue(choice().config[SemanticsProperties.Selected])
        assertEquals("Selected SIM", choice().config[SemanticsProperties.StateDescription])
    }
}

class GatewayDefaultScaleAccessibilityTest : GatewayAccessibilityTest() {
    override val testFontScale = 1f
}
