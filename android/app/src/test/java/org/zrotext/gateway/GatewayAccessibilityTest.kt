// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.Manifest
import android.content.pm.ApplicationInfo
import android.view.accessibility.AccessibilityManager
import android.os.Looper
import android.view.View
import android.telephony.SubscriptionManager
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.runtime.snapshots.Snapshot
import androidx.compose.ui.node.RootForTest
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import org.junit.Assert.*
import org.junit.Test
import org.junit.Rule
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
    @get:Rule val compose = createEmptyComposeRule()
    protected open val testFontScale = 2f
    protected open val testLayoutDirection: Int? = null
    override val primaryMetricsSideBySide = false
    override fun onScreen(page: String, revealStatus: Boolean, revealObservations: Boolean,
        revealManualPairing: Boolean, check: (RootForTest) -> Unit) {
        RuntimeEnvironment.setFontScale(testFontScale)
        val app = RuntimeEnvironment.getApplication()
        val originalApplicationFlags = app.applicationInfo.flags
        if (testLayoutDirection == View.LAYOUT_DIRECTION_RTL) {
            app.applicationInfo.flags = originalApplicationFlags or ApplicationInfo.FLAG_SUPPORTS_RTL
        }
        shadowOf(app.getSystemService(AccessibilityManager::class.java)).setEnabled(true)
        shadowOf(app).grantPermissions(Manifest.permission.READ_PHONE_STATE)
        shadowOf(app.getSystemService(SubscriptionManager::class.java)).setActiveSubscriptionInfos(
            SubscriptionInfoBuilder.newBuilder().setId(1).setSimSlotIndex(0)
                .setDisplayName("Test SIM").buildSubscriptionInfo())
        val controller = Robolectric.buildActivity(MainActivity::class.java, Intent(app, MainActivity::class.java)
            .putExtra("gateway_screen", page.substringBefore('/'))
                .putExtra("gateway_setup_step", page.substringAfter('/', "OVERVIEW"))).setup().visible()
        try {
            testLayoutDirection?.let { controller.get().window.decorView.layoutDirection = it }
            Snapshot.sendApplyNotifications()
            compose.mainClock.advanceTimeBy(300)
            compose.waitForIdle()
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300))
            val root = requireNotNull(findRoot(controller.get().window.decorView))
            root.forceAccessibilityForTesting(true)
            controller.get().window.decorView.requestLayout()
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300))
            root.measureAndLayoutForTest()
            if (revealManualPairing) {
                val manual = nodes(root).single { text(it) == "Use existing manual pairing" }
                assertTrue(requireNotNull(manual.config[SemanticsActions.OnClick].action).invoke())
                Snapshot.sendApplyNotifications()
                compose.mainClock.advanceTimeBy(300)
                compose.waitForIdle()
                shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300))
                root.measureAndLayoutForTest()
                assertNull(shadowOf(controller.get()).lastRequestedPermission)
                assertTrue(shadowOf(app).allStartedServices.isEmpty())
            }
            testLayoutDirection?.let {
                assertEquals("The fixture must actually render its requested layout direction", it,
                    (root as ViewRootForTest).view.layoutDirection)
            }
            if (revealStatus || revealObservations) {
                fun targetIsVisible() = if (revealObservations) homeObservationsAreVisible(root) else homeStatusIsVisible(root)
                for (attempt in 0 until 20) {
                    if (targetIsVisible()) break
                    scrollTowardHomeStatus(root)
                    Snapshot.sendApplyNotifications()
                    compose.mainClock.advanceTimeBy(300)
                    compose.waitForIdle()
                    shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(300))
                    root.measureAndLayoutForTest()
                }
                assertTrue("Home observations or status must become visible after actual scrolling; " +
                    nodes(root).filter { it.config.contains(SemanticsProperties.LiveRegion) ||
                        it.config.getOrNull(SemanticsProperties.TestTag)?.startsWith("home-observation-") == true }
                        .map { "${text(it)} bounds=${it.boundsInRoot} position=${it.positionInRoot} size=${it.size}" }, targetIsVisible())
            }
            check(root)
        } finally {
            controller.pause().stop().destroy()
            app.applicationInfo.flags = originalApplicationFlags
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
    override val primaryMetricsSideBySide = true
}

@Config(sdk = [34], qualifiers = "w320dp-h640dp")
class GatewayCompactAccessibilityTest : GatewayAccessibilityTest() {
    override val testFontScale = 1f
}

@Config(sdk = [34], qualifiers = "ldrtl-w360dp-h640dp")
class GatewayRtlAccessibilityTest : GatewayAccessibilityTest() {
    override val testFontScale = 1f
    override val primaryMetricsSideBySide = true
    override val testLayoutDirection = View.LAYOUT_DIRECTION_RTL
}
