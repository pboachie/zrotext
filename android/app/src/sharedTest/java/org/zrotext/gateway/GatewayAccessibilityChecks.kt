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

/** Same rendered-screen assertions in JVM CI and the opt-in emulator harness. */
@OptIn(ExperimentalComposeUiApi::class)
abstract class GatewayAccessibilityChecks {
    protected abstract fun onScreen(page: String = "HOME", revealStatus: Boolean = false,
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
            "HOME" -> listOf("Gateway home", "This phone", "Quick controls")
            "SETUP" -> listOf("Set up this phone")
            "SETUP/ACCESS" -> listOf("Set up this phone", "Review access", "Android access")
            "SETUP/SIM" -> listOf("Set up this phone", "Choose a SIM")
            "SETUP/PAIRING" -> listOf("Set up this phone", "Device pairing")
            "CONNECTION" -> listOf("Authenticated device heartbeat")
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
        val rows = listOf("Sending from", "Power", "Connection").map { label ->
            nodes(root).single { it.config.getOrNull(SemanticsProperties.TestTag) == "home-observation-$label" }
        }
        assertTrue(rows.zipWithNext().all { (first, next) -> first.positionInRoot.y < next.positionInRoot.y })
        val pause = nodes(root).single { text(it) == "Pause connections" && it.config.contains(SemanticsActions.OnClick) }
        assertTrue("Observations precede Pause in the Home hierarchy", rows.last().positionInRoot.y < pause.positionInRoot.y)
        assertTrue(rows.all { !it.config.contains(SemanticsActions.OnClick) })
        assertTrue(text(rows[1]).contains("Unavailable") || text(rows[1]).contains("%"))
        assertTrue(text(rows[2]).contains("paused") || text(rows[2]).contains("authenticated") ||
            text(rows[2]).contains("network") || text(rows[2]).contains("connection") || text(rows[2]).contains("Proving"))
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
    }

    @Test fun fieldsKeepLabelsAndTokensRemainPasswordFields() = everyScreen { page, root ->
        val expected = when (page) {
            "HOME", "SETUP", "SETUP/ACCESS", "SETUP/SIM" -> emptyList()
            "SETUP/PAIRING" -> listOf("HTTPS server origin", "Pairing ID", "One-use pairing token")
            "CONNECTION" -> listOf("WSS device stream URL", "Approved device UUID")
            "TOOLS" -> listOf("WSS test endpoint", "Short-lived test token", "Controlled recipient +E.164") +
                debugOnly("Controlled MMS recipient +E.164", "Optional subject")
            else -> error("Unknown test screen")
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

    /** Large text/landscape can place status below the initial viewport. */
    protected fun homeStatusIsVisible(root: RootForTest): Boolean = nodes(root).any {
        it.config.contains(SemanticsProperties.LiveRegion) &&
            text(it).startsWith("Device status:") && !it.boundsInRoot.isEmpty
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
