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
    protected abstract fun onScreen(check: (RootForTest) -> Unit)

    @Test fun sectionsAreHeadingsInReadingOrder() = onScreen { root ->
        val headings = nodes(root).filter { it.config.contains(SemanticsProperties.Heading) }
        assertEquals(listOf("ZROtext", "Gateway connection test", "Authenticated device heartbeat",
            "Controlled SMS test", "Device pairing"), headings.map(::text))
        assertTrue(headings.zipWithNext().all { (first, next) ->
            first.positionInRoot.y < next.positionInRoot.y
        })
    }

    @Test fun statusRegionsExcludeRoutineHeartbeatCounters() = onScreen { root ->
        val regions = nodes(root).filter { it.config.contains(SemanticsProperties.LiveRegion) }
        assertEquals(3, regions.size)
        assertTrue(regions.all { it.config[SemanticsProperties.LiveRegion] == LiveRegionMode.Polite })
        assertTrue(regions.none { text(it).contains("acknowledgments") })
        assertEquals(listOf("Connection status", "Authenticated connection status", "Pairing status"),
            regions.map { text(it).substringBefore(":") })
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

    @Test fun fieldsKeepLabelsAndTokensRemainPasswordFields() = onScreen { root ->
        val fields = nodes(root).filter { it.config.contains(SemanticsProperties.EditableText) }
        assertEquals(8, fields.size)
        val expected = listOf("WSS test endpoint", "Short-lived test token", "WSS device stream URL",
            "Approved device UUID", "Controlled recipient +E.164", "HTTPS server origin", "Pairing ID",
            "One-use pairing token")
        assertEquals(expected, fields.map(::text))
        assertEquals(listOf("Short-lived test token", "One-use pairing token"),
            fields.filter { it.config.contains(SemanticsProperties.Password) }.map(::text))
    }

    @Test fun actionsRetainNamesAndMinimumTouchTargetsAtCurrentTextScale() = onScreen { root ->
        val buttons = nodes(root).filter { it.config.getOrNull(SemanticsProperties.Role) == Role.Button }
        assertTrue("Core actions must remain reachable", buttons.size >= 9)
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
