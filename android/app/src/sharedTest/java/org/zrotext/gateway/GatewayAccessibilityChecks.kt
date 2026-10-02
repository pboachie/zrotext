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
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.getOrNull
import org.junit.Assert.*
import org.junit.Test
import kotlin.math.abs

/** Same rendered-screen assertions in JVM CI and the opt-in emulator harness. */
@OptIn(ExperimentalComposeUiApi::class)
abstract class GatewayAccessibilityChecks {
    protected abstract val primaryMetricsSideBySide: Boolean
    protected abstract fun onScreen(page: String = "HOME", revealStatus: Boolean = false,
        revealObservations: Boolean = false,
        check: (RootForTest) -> Unit)

    /** The MMS spike section (#438) exists only in debug builds. */
    private fun debugOnly(vararg labels: String): List<String> =
        if (BuildConfig.DEBUG) labels.toList() else emptyList()

    private fun everyScreen(check: (String, RootForTest) -> Unit) {
        (GatewayPage.entries.map { it.name } + listOf("SETUP/ACCESS", "SETUP/SIM", "SETUP/PAIRING"))
            .forEach { page -> onScreen(page) { check(page, it) } }
    }

    @Test fun sectionsAreHeadingsInReadingOrder() = everyScreen { page, root ->
        val expected = when (page) {
            "HOME" -> listOf("Gateway home", "Message activity", "This phone", "Quick controls")
            "SETUP" -> listOf("Set up this phone")
            "SETUP/ACCESS" -> listOf("Set up this phone", "Review access", "Android access")
            "SETUP/SIM" -> listOf("Set up this phone", "Choose a SIM")
            "SETUP/PAIRING" -> listOf("Set up this phone", "Device pairing")
            "CONNECTION" -> listOf("Conversation content", "Authenticated device heartbeat", "Message summary reader")
            "TOOLS" -> listOf("Advanced pilots", "Gateway connection test", "Controlled SMS test") +
                debugOnly("Controlled MMS spike")
            else -> error("Unknown test screen")
        }
        val headings = nodes(root).filter { it.config.contains(SemanticsProperties.Heading) }
        assertEquals(listOf("ZROtext") + expected, headings.map(::text))
        assertTrue(headings.zipWithNext().all { (first, next) ->
            first.positionInRoot.y < next.positionInRoot.y
        })
    }

    @Test fun statusRegionsExcludeRoutineHeartbeatCounters() = everyScreen { page, root ->
        val expected = when (page) {
            "HOME" -> listOf("Device status")
            "SETUP" -> listOf("Pairing in this session")
            "SETUP/ACCESS", "SETUP/SIM" -> emptyList()
            "SETUP/PAIRING" -> listOf("Pairing status")
            "CONNECTION" -> listOf("Authenticated connection status")
            "TOOLS" -> listOf("Pilot status", "Connection status") + debugOnly("MMS spike status")
            else -> error("Unknown test screen")
        }
        val regions = nodes(root).filter { it.config.contains(SemanticsProperties.LiveRegion) }
        assertTrue(regions.all { it.config[SemanticsProperties.LiveRegion] == LiveRegionMode.Polite })
        assertTrue(regions.none { text(it).contains("acknowledgments") })
        assertEquals(expected, regions.map { text(it).substringBefore(":") })
    }

    @Test fun homeObservationsKeepReadOnlyLabelsAndReadingOrderAtCurrentTextScale() = onScreen { root ->
        val tags = listOf("Submitted today", "In queue").map { "home-observation-$it" }
        val summaries = nodes(root).filter { it.config.getOrNull(SemanticsProperties.TestTag) in tags }
        assertEquals("The semantics tree keeps the logical observation order", tags,
            summaries.map { it.config[SemanticsProperties.TestTag] })
        val primary = summaries.take(2)
        val first = primary[0]
        val second = primary[1]
        if (primaryMetricsSideBySide) {
            assertEquals("Normal-width metrics share a row", first.positionInRoot.y, second.positionInRoot.y, 1f)
            assertEquals("Both metrics have equal space", first.size.width, second.size.width)
            assertTrue("Metric columns have positive widths", first.size.width > 0)
            val rtl = (root as ViewRootForTest).view.layoutDirection == View.LAYOUT_DIRECTION_RTL
            if (rtl) {
                assertTrue("The first metric occupies the RTL start column: ${first.positionInRoot}, ${second.positionInRoot}", second.positionInRoot.x + second.size.width <= first.positionInRoot.x)
            } else {
                assertTrue("The first metric occupies the LTR start column", first.positionInRoot.x + first.size.width <= second.positionInRoot.x)
            }
        } else {
            assertTrue("Compact or large-text metrics stack without overlap", first.positionInRoot.y + first.size.height <= second.positionInRoot.y)
            assertEquals("Stacked metrics align", first.positionInRoot.x, second.positionInRoot.x, 1f)
        }
        val group = nodes(root).single { it.config.getOrNull(SemanticsProperties.TestTag) == "home-primary-metrics" }
        assertTrue("The primary metrics form a traversal group", group.config[SemanticsProperties.IsTraversalGroup])
        assertEquals(listOf(0f, 1f), primary.map { it.config[SemanticsProperties.TraversalIndex] })
        summaries.forEach { summary ->
            assertTrue("An absent summary reader must not display a measured zero", text(summary).endsWith("Unavailable"))
            assertFalse("Summary observations must not initiate work", summary.config.contains(SemanticsActions.OnClick))
            assertFalse("Static unavailable observations are not live announcements", summary.config.contains(SemanticsProperties.LiveRegion))
        }
        assertTrue(nodes(root).any { text(it) == "Summary reader not connected." })
        val rows = listOf("Sending from", "Power", "Connection").map { label ->
            nodes(root).single { it.config.getOrNull(SemanticsProperties.TestTag) == "home-observation-$label" }
        }
        assertTrue("Message observations precede phone observations", summaries.last().positionInRoot.y < rows.first().positionInRoot.y)
        assertTrue(rows.zipWithNext().all { (first, next) -> first.positionInRoot.y < next.positionInRoot.y })
        val pause = nodes(root).single { text(it) == "Pause connections" && it.config.contains(SemanticsActions.OnClick) }
        assertTrue("Observations precede Pause in the Home hierarchy", rows.last().positionInRoot.y < pause.positionInRoot.y)
        assertTrue(rows.all { !it.config.contains(SemanticsActions.OnClick) })
        assertTrue(text(rows[1]).contains("Unavailable") || text(rows[1]).contains("%"))
        assertTrue(text(rows[2]).contains("paused") || text(rows[2]).contains("authenticated") ||
            text(rows[2]).contains("network") || text(rows[2]).contains("connection") || text(rows[2]).contains("Proving"))
        dashboardFitsOrdinaryPortraitAndPreservesReadableOverflow(root)
    }

    private fun platformObservationsRetainFullTextAndLogicalTraversal() = onScreen(revealObservations = true) { root ->
        root.forceAccessibilityForTesting(true)
        try {
            val view = (root as ViewRootForTest).view
            val provider = requireNotNull(view.accessibilityNodeProvider)
            val observations = listOf("Submitted today", "In queue").map { label ->
                nodes(root).single { it.config.getOrNull(SemanticsProperties.TestTag) == "home-observation-$label" }
            }
            assertTrue("All observations must be visible after actual scrolling", homeObservationsAreVisible(root))
            val platformNodes = observations.map { requireNotNull(provider.createAccessibilityNodeInfo(it.id)) }
            platformNodes.take(2).zip(observations.take(2)).forEach { (info, node) ->
                assertEquals("Each observation exposes its full label and value once", text(node),
                    requireNotNull(info.text).toString().replace(Regex("\\s+"), " ").trim())
            }
            platformNodes.forEach { info ->
                assertFalse("Static observations must not expose an action", info.isClickable)
                assertEquals(View.ACCESSIBILITY_LIVE_REGION_NONE, info.liveRegion)
            }
            val beforeKey = "android.view.accessibility.extra.EXTRA_DATA_TEST_TRAVERSALBEFORE_VAL"
            platformNodes.zip(observations).forEach { (info, node) ->
                provider.addExtraDataToAccessibilityNodeInfo(node.id, info, beforeKey, null)
            }
            assertEquals("Submitted precedes In queue in platform traversal", observations[1].id,
                platformNodes[0].extras.getInt(beforeKey, -1))
        } finally {
            root.forceAccessibilityForTesting(false)
        }
    }

    @Test fun platformNodesExposeHeadingsAndVisibleStatusRegions() {
        onScreen { root ->
          root.forceAccessibilityForTesting(true)
          try {
              val view = (root as ViewRootForTest).view
              val provider = requireNotNull(view.accessibilityNodeProvider)
              val title = nodes(root).single { text(it) == "ZROtext" }
              val titleInfo = requireNotNull(provider.createAccessibilityNodeInfo(title.id))
              assertTrue("The platform node must expose the heading: $titleInfo", titleInfo.isHeading)
          } finally {
              root.forceAccessibilityForTesting(false)
          }
        }
        onScreen(revealStatus = true) { root ->
          root.forceAccessibilityForTesting(true)
          try {
              val view = (root as ViewRootForTest).view
              val provider = requireNotNull(view.accessibilityNodeProvider)
              val visibleStatuses = nodes(root).filter {
                  it.config.contains(SemanticsProperties.LiveRegion) && !it.boundsInRoot.isEmpty
              }
              assertTrue("The Home connection status must be visible after scrolling", homeStatusIsVisible(root))
              assertTrue("At least the connection status is visible", visibleStatuses.isNotEmpty())
              for (status in visibleStatuses) {
                  val info = requireNotNull(provider.createAccessibilityNodeInfo(status.id))
                  assertEquals(View.ACCESSIBILITY_LIVE_REGION_POLITE, info.liveRegion)
              }
          } finally {
              root.forceAccessibilityForTesting(false)
          }
        }
        platformObservationsRetainFullTextAndLogicalTraversal()
    }

    @Test fun fieldsKeepLabelsAndTokensRemainPasswordFields() = everyScreen { page, root ->
        val expected = when (page) {
            "HOME", "SETUP", "SETUP/ACCESS", "SETUP/SIM" -> emptyList()
            "SETUP/PAIRING" -> listOf("HTTPS server origin", "Pairing ID", "One-use pairing token")
            "CONNECTION" -> listOf("WSS device stream URL", "Approved device UUID", "Summary HTTPS origin", "Summary device UUID", "Separate messages-read API key")
            "TOOLS" -> listOf("WSS test endpoint", "Short-lived test token", "Controlled recipient +E.164") +
                debugOnly("Controlled MMS recipient +E.164", "Optional subject")
            else -> error("Unknown test screen")
        }
        val fields = nodes(root).filter { it.config.contains(SemanticsProperties.EditableText) }
        assertEquals(expected, fields.map(::text))
        assertEquals(expected.filter { it.contains("token") || it == "Separate messages-read API key" },
            fields.filter { it.config.contains(SemanticsProperties.Password) }.map(::text))
    }

    @Test fun actionsRetainNamesAndMinimumTouchTargetsAtCurrentTextScale() = everyScreen { _, root ->
        val buttons = nodes(root).filter { it.config.getOrNull(SemanticsProperties.Role) == Role.Button }
        assertTrue("Screen navigation and all current actions remain reachable", buttons.size >= 4)
        assertTrue("Every screen exposes its navigation menu", buttons.any { text(it) == "Controls" })
        for (button in buttons) {
            assertTrue("An action needs a spoken name", text(button).isNotBlank())
            val widthDp = button.size.width / root.density.density
            val heightDp = button.size.height / root.density.density
            assertTrue("${text(button)} width is $widthDp dp", widthDp >= 48f)
            assertTrue("${text(button)} height is $heightDp dp", heightDp >= 48f)
        }
    }

    private fun dashboardFitsOrdinaryPortraitAndPreservesReadableOverflow(root: RootForTest) {
        val all = nodes(root)
        val scroll = all.single { it.config.getOrNull(SemanticsProperties.TestTag) == "gateway-screen-scroll" }
        val range = scroll.config[SemanticsProperties.VerticalScrollAxisRange]
        val viewportDp = root.semanticsOwner.rootSemanticsNode.size.height / root.density.density
        if (root.density.fontScale <= 1.3f && viewportDp >= 560f) {
            assertEquals("Ordinary portrait Home must have no scroll range", 0f, range.maxValue(), 0f)
            val required = all.filter { node ->
                val value = text(node)
                node.config.getOrNull(SemanticsProperties.TestTag)?.startsWith("home-observation-") == true ||
                    value in listOf("Controls", "Message details", "Pause connections", "Quick controls") ||
                    value.startsWith("Device status:") || value.startsWith("Pause stops connections.")
            }
            assertEquals("All five observations and six main controls/status/disclosures are checked", 11, required.size)
            assertTrue("Every required element must fit entirely in the viewport", required.all { nodeIsFullyVisible(root, it) })
        } else {
            assertTrue("Large type and short windows retain readable scrolling", range.maxValue() > 0f)
        }
    }

    protected fun nodes(root: RootForTest): List<SemanticsNode> {
        fun walk(node: SemanticsNode): List<SemanticsNode> = listOf(node) + node.children.flatMap(::walk)
        return walk(root.semanticsOwner.rootSemanticsNode)
    }

    protected fun text(node: SemanticsNode): String =
        node.config.getOrNull(SemanticsProperties.Text)?.joinToString(" ") { it.text }.orEmpty()

    /** Large text/landscape can place status below the initial viewport. */
    protected fun homeStatusIsVisible(root: RootForTest): Boolean = nodes(root).any {
        it.config.contains(SemanticsProperties.LiveRegion) &&
            text(it).startsWith("Device status:") && !it.boundsInRoot.isEmpty
    }

    protected fun homeObservationsAreVisible(root: RootForTest): Boolean {
        val tags = listOf("Submitted today", "In queue").map { "home-observation-$it" }
        val observations = nodes(root).filter { it.config.getOrNull(SemanticsProperties.TestTag) in tags }
        return observations.size == tags.size && observations.all { nodeIsFullyVisible(root, it) }
    }

    private fun nodeIsFullyVisible(root: RootForTest, node: SemanticsNode): Boolean {
        val coordinates = root.semanticsOwner.rootSemanticsNode.layoutInfo.coordinates
        val complete = coordinates.localBoundingBoxOf(node.layoutInfo.coordinates, clipBounds = false)
        val clipped = coordinates.localBoundingBoxOf(node.layoutInfo.coordinates, clipBounds = true)
        return !complete.isEmpty && !clipped.isEmpty &&
            abs(complete.left - clipped.left) <= 1f && abs(complete.top - clipped.top) <= 1f &&
            abs(complete.right - clipped.right) <= 1f && abs(complete.bottom - clipped.bottom) <= 1f &&
            complete.left >= -1f && complete.top >= -1f &&
            complete.right <= coordinates.size.width + 1f && complete.bottom <= coordinates.size.height + 1f
    }

    protected fun scrollTowardHomeStatus(root: RootForTest) {
        val scroll = nodes(root).first { it.config.contains(SemanticsActions.ScrollBy) }
        val view = (root as ViewRootForTest).view
        val height = maxOf(view.height, root.semanticsOwner.rootSemanticsNode.size.height)
        assertTrue("The rendered viewport must have a positive height", height > 0)
        assertTrue("The actual screen must accept scrolling to its status",
            requireNotNull(scroll.config[SemanticsActions.ScrollBy].action).invoke(0f, height * 0.25f))
    }

    protected fun findRoot(view: View): RootForTest? {
        if (view is ViewRootForTest) return view
        if (view is ViewGroup) for (index in 0 until view.childCount) {
            findRoot(view.getChildAt(index))?.let { return it }
        }
        return null
    }
}
