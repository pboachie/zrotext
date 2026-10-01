// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.view.View
import android.view.ViewGroup
import android.view.accessibility.AccessibilityManager
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** The Compose clock drives real scroll frames instead of a static viewport. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], qualifiers = "w640dp-h360dp-land")
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@OptIn(ExperimentalComposeUiApi::class)
open class GatewayLandscapeAccessibilityTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()
    protected open val fontScale = 2f

    @Before fun prepare() {
        RuntimeEnvironment.setFontScale(fontScale)
        shadowOf(RuntimeEnvironment.getApplication().getSystemService(AccessibilityManager::class.java))
            .setEnabled(true)
        compose.runOnIdle { AuthenticatedGatewayStatus.value = "Paused" }
        compose.activityRule.scenario.recreate()
        compose.waitForIdle()
    }

    @After fun restore() { RuntimeEnvironment.setFontScale(1f) }

    @Test fun scrollingRevealsTheActualPlatformStatusAtCurrentTextScale() {
        val heading = compose.onNodeWithText("ZROtext").fetchSemanticsNode()
        compose.runOnIdle {
            val root = requireNotNull(findRoot(compose.activity.window.decorView))
            root.forceAccessibilityForTesting(true)
            assertTrue(requireNotNull(requireNotNull(root.view.accessibilityNodeProvider)
                .createAccessibilityNodeInfo(heading.id)).isHeading)
        }
        val status = compose.onNodeWithText("Device status: Paused")
            .performScrollTo().assertIsDisplayed().fetchSemanticsNode()
        assertEquals(LiveRegionMode.Polite, status.config[SemanticsProperties.LiveRegion])
        compose.runOnIdle {
            val root = requireNotNull(findRoot(compose.activity.window.decorView))
            val info = requireNotNull(requireNotNull(root.view.accessibilityNodeProvider)
                .createAccessibilityNodeInfo(status.id))
            assertTrue("The revealed platform status must be visible", info.isVisibleToUser)
            assertEquals(View.ACCESSIBILITY_LIVE_REGION_POLITE, info.liveRegion)
        }
    }

    @Test fun pauseAndItsLocalProcessingDisclosureStayReachable() {
        val pause = compose.onNodeWithText("Pause connections")
            .performScrollTo().assertIsDisplayed().fetchSemanticsNode()
        compose.runOnIdle {
            val root = requireNotNull(findRoot(compose.activity.window.decorView))
            assertTrue(pause.size.width / root.density.density >= 48f)
            assertTrue(pause.size.height / root.density.density >= 48f)
        }
        compose.onNodeWithText("Pause stops connections. SMS receiving access can still process messages locally; revoke it in Android app settings to stop local processing.")
            .performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Arm one test SMS").assertDoesNotExist()
    }

    private fun findRoot(view: View): ViewRootForTest? {
        if (view is ViewRootForTest) return view
        if (view is ViewGroup) for (index in 0 until view.childCount) {
            findRoot(view.getChildAt(index))?.let { return it }
        }
        return null
    }
}

class GatewayDefaultScaleLandscapeAccessibilityTest : GatewayLandscapeAccessibilityTest() {
    override val fontScale = 1f
}
