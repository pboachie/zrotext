// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.view.View
import android.view.ViewGroup
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.node.RootForTest
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import org.junit.Assert.*
import org.junit.Test

/** Same rendered-screen assertions in JVM CI and the opt-in emulator harness. */
@OptIn(ExperimentalComposeUiApi::class)
abstract class GatewayAccessibilityChecks {
    protected abstract fun onScreen(page: String = "HOME", check: (RootForTest) -> Unit)

    /** The MMS spike section (#438) exists only in debug builds. */
    private fun debugOnly(vararg labels: String): List<String> =
        if (BuildConfig.DEBUG) labels.toList() else emptyList()

    private fun everyScreen(check: (GatewayPage, RootForTest) -> Unit) {
        GatewayPage.entries.forEach { page -> onScreen(page.name) { check(page, it) } }
    }

    @Test fun sectionsAreHeadingsInReadingOrder() = everyScreen { page, root ->
        val expected = when (page) {
            GatewayPage.HOME -> listOf("Gateway home", "Authenticated connection", "This phone")
            GatewayPage.SETUP -> listOf("Set up this phone", "Device pairing")
            GatewayPage.CONNECTION -> listOf("Authenticated device heartbeat")
            GatewayPage.TOOLS -> listOf("Advanced pilots", "Gateway connection test", "Controlled SMS test") +
                debugOnly("Controlled MMS spike")
        }
        val headings = nodes(root).filter { it.config.contains(SemanticsProperties.Heading) }
        assertEquals(listOf("ZROtext") + expected, headings.map(::text))
        assertTrue(headings.zipWithNext().all { (first, next) ->
            first.positionInRoot.y < next.positionInRoot.y
        })
    }

    @Test fun statusRegionsExcludeRoutineHeartbeatCounters() = everyScreen { page, root ->
        val expected = when (page) {
            GatewayPage.HOME -> listOf("Device status", "Pairing in this session", "Test connection")
            GatewayPage.SETUP -> listOf("Pairing status")
            GatewayPage.CONNECTION -> listOf("Authenticated connection status")
            GatewayPage.TOOLS -> listOf("Pilot status", "Connection status") + debugOnly("MMS spike status")
        }
        val regions = nodes(root).filter { it.config.contains(SemanticsProperties.LiveRegion) }
        assertTrue(regions.all { it.config[SemanticsProperties.LiveRegion] == LiveRegionMode.Polite })
        assertTrue(regions.none { text(it).contains("acknowledgments") })
        assertEquals(expected, regions.map { text(it).substringBefore(":") })
    }

    @Test fun platformNodesExposeHeadingsAndVisibleStatusRegions() = onScreen { root ->
        root.forceAccessibilityForTesting(true)
        try {
            val view = (root as ViewRootForTest).view
            val provider = requireNotNull(view.accessibilityNodeProvider)
            val title = nodes(root).single { text(it) == "ZROtext" }
            val titleInfo = requireNotNull(provider.createAccessibilityNodeInfo(title.id))
            assertTrue("The platform node must expose the heading: $titleInfo", titleInfo.isHeading)
            val visibleStatuses = nodes(root).filter {
                it.config.contains(SemanticsProperties.LiveRegion) && !it.boundsInRoot.isEmpty
            }
            assertTrue("At least the connection status is visible", visibleStatuses.isNotEmpty())
            for (status in visibleStatuses) {
                val info = requireNotNull(provider.createAccessibilityNodeInfo(status.id))
                assertEquals(View.ACCESSIBILITY_LIVE_REGION_POLITE, info.liveRegion)
            }
        } finally {
            root.forceAccessibilityForTesting(false)
        }
    }

    @Test fun fieldsKeepLabelsAndTokensRemainPasswordFields() = everyScreen { page, root ->
        val expected = when (page) {
            GatewayPage.HOME -> emptyList()
            GatewayPage.SETUP -> listOf("HTTPS server origin", "Pairing ID", "One-use pairing token")
            GatewayPage.CONNECTION -> listOf("WSS device stream URL", "Approved device UUID")
            GatewayPage.TOOLS -> listOf("WSS test endpoint", "Short-lived test token", "Controlled recipient +E.164") +
                debugOnly("Controlled MMS recipient +E.164", "Optional subject")
        }
        val fields = nodes(root).filter { it.config.contains(SemanticsProperties.EditableText) }
        assertEquals(expected, fields.map(::text))
        assertEquals(expected.filter { it.contains("token") },
            fields.filter { it.config.contains(SemanticsProperties.Password) }.map(::text))
    }

    @Test fun actionsRetainNamesAndMinimumTouchTargetsAtCurrentTextScale() = everyScreen { _, root ->
        val buttons = nodes(root).filter { it.config.getOrNull(SemanticsProperties.Role) == Role.Button }
        assertTrue("Navigation must remain reachable", buttons.size >= 4)
        for (button in buttons) {
            assertTrue("An action needs a spoken name", text(button).isNotBlank())
            val widthDp = button.size.width / root.density.density
            val heightDp = button.size.height / root.density.density
            assertTrue("${text(button)} width is $widthDp dp", widthDp >= 48f)
            assertTrue("${text(button)} height is $heightDp dp", heightDp >= 48f)
        }
    }

    protected fun nodes(root: RootForTest): List<SemanticsNode> {
        fun walk(node: SemanticsNode): List<SemanticsNode> = listOf(node) + node.children.flatMap(::walk)
        return walk(root.semanticsOwner.rootSemanticsNode)
    }

    protected fun text(node: SemanticsNode): String =
        node.config.getOrNull(SemanticsProperties.Text)?.joinToString(" ") { it.text }.orEmpty()

    protected fun findRoot(view: View): RootForTest? {
        if (view is ViewRootForTest) return view
        if (view is ViewGroup) for (index in 0 until view.childCount) {
            findRoot(view.getChildAt(index))?.let { return it }
        }
        return null
    }
}
