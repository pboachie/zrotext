// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.os.Build
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.node.RootForTest
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assume.assumeTrue
import org.junit.Assert.assertTrue
import org.junit.runner.RunWith

/** Explicitly opt in on a disposable emulator; manual disclosure only, no claims or radio actions. */
@RunWith(AndroidJUnit4::class)
@OptIn(ExperimentalComposeUiApi::class)
class GatewayAccessibilityDeviceTest : GatewayAccessibilityChecks() {
    override val primaryMetricsSideBySide: Boolean
        get() {
            val requested = InstrumentationRegistry.getArguments().getString("primaryMetricsLayout")
            if (requested != null) {
                require(requested in setOf("row", "stack"))
                return requested == "row"
            }
            val configuration = InstrumentationRegistry.getInstrumentation().targetContext.resources.configuration
            return configuration.fontScale <= 1.3f && configuration.screenWidthDp >= 344
        }
    override fun onScreen(page: String, revealStatus: Boolean, revealObservations: Boolean,
        revealManualPairing: Boolean, check: (RootForTest) -> Unit) {
        assumeTrue(InstrumentationRegistry.getArguments().getString("a11yIsolatedEmulator") == "true")
        assumeTrue(Build.HARDWARE in setOf("ranchu", "goldfish"))
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java)
                .putExtra("gateway_screen", page.substringBefore('/'))
                .putExtra("gateway_setup_step", page.substringAfter('/', "OVERVIEW"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        try {
            instrumentation.waitForIdleSync()
            if (revealManualPairing) {
                instrumentation.runOnMainSync {
                    val root = requireNotNull(findRoot(activity.window.decorView))
                    val manual = nodes(root).single { text(it) == "Use existing manual pairing" }
                    assertTrue(requireNotNull(manual.config[SemanticsActions.OnClick].action).invoke())
                }
                instrumentation.waitForIdleSync()
                // Main-queue idleness can precede the frame that recomposes the
                // explicitly disclosed manual fields. Wait for actual semantics.
                var ready = false
                for (attempt in 0 until 20) {
                    instrumentation.runOnMainSync {
                        val root = requireNotNull(findRoot(activity.window.decorView))
                        root.measureAndLayoutForTest()
                        ready = nodes(root).filter { it.config.contains(SemanticsProperties.EditableText) }
                            .map(::text) == listOf("HTTPS server origin", "Pairing ID", "One-use pairing token")
                    }
                    if (ready) break
                    instrumentation.waitForIdleSync()
                    Thread.sleep(100)
                }
                assertTrue("Explicit manual pairing fields must render before accessibility checks", ready)
            }
            if (revealStatus || revealObservations) {
                for (attempt in 0 until 20) {
                    var visible = false
                    instrumentation.runOnMainSync {
                        val root = requireNotNull(findRoot(activity.window.decorView))
                        root.measureAndLayoutForTest()
                        visible = if (revealObservations) homeObservationsAreVisible(root) else homeStatusIsVisible(root)
                        if (!visible) scrollTowardHomeStatus(root)
                    }
                    if (visible) break
                    // Scroll semantics enqueue work; let the real UI deliver it.
                    instrumentation.waitForIdleSync()
                    Thread.sleep(100)
                }
            }
            instrumentation.runOnMainSync {
                val root = requireNotNull(findRoot(activity.window.decorView))
                root.measureAndLayoutForTest()
                check(root)
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            instrumentation.waitForIdleSync()
        }
    }
}
