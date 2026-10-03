// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.TextButton
import androidx.compose.material3.IconButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.isTraversalGroup
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.traversalIndex
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

internal val LocalGatewayScrollReset = staticCompositionLocalOf<() -> Unit> { {} }
private val LocalGatewayCompactHome = staticCompositionLocalOf { true }
private val LocalGatewayHomePanel = staticCompositionLocalOf<MutableState<String?>?> { null }

internal enum class GatewayPage(val label: String) {
    HOME("Home"), SETUP("Setup"), CONNECTION("Connection"), TOOLS("Tools")
}

/** Navigation is presentation only: changing pages never starts a service or asks for access. */
@Composable
internal fun GatewayCompanion(initialPage: GatewayPage = GatewayPage.HOME,
    onPageChanged: (GatewayPage) -> Unit = {},
    content: @Composable ColumnScope.(GatewayPage, (GatewayPage) -> Unit) -> Unit) {
    var page by rememberSaveable { mutableStateOf(initialPage) }
    LaunchedEffect(page) { onPageChanged(page) }
    val screenState = rememberSaveableStateHolder()
    val homePanel = remember { mutableStateOf<String?>(null) }
    val navigate: (GatewayPage) -> Unit = { page = it }
    BackHandler(enabled = page != GatewayPage.HOME) { page = GatewayPage.HOME }
    // Ordinary Home fits one viewport. Readable overflow remains available for
    // enlarged type, short landscape windows, keyboards and long status errors.
    BoxWithConstraints(Modifier.fillMaxSize().safeDrawingPadding().imePadding().clipToBounds()) {
        val compactHome = maxHeight < 700.dp
        screenState.SaveableStateProvider(page.name) {
            val scroll = rememberScrollState()
            val scope = rememberCoroutineScope()
            val resetScroll: () -> Unit = { scope.launch { scroll.scrollTo(0) } }
            Column(Modifier.fillMaxSize().verticalScroll(scroll).testTag("gateway-screen-scroll")
                .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(if (page == GatewayPage.HOME) 4.dp else 16.dp)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    GatewayBrandMark()
                    Text("ZROtext", style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.weight(1f).semantics { heading() })
                    var menu by remember { mutableStateOf(false) }
                    Box {
                        IconButton(onClick = { menu = true }, modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)
                            .testTag("gateway-controls").semantics {
                                contentDescription = "Controls"
                                stateDescription = "${page.label}. Open controls menu"
                            }) { GatewayGearMark() }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false },
                            containerColor = MaterialTheme.colorScheme.surface) {
                            listOf("Quick controls" to "controls", "Android access" to "access", "Phone details" to "details")
                                .forEach { (label, panel) ->
                                    DropdownMenuItem(text = { Text(label) },
                                        onClick = { menu = false; homePanel.value = panel; navigate(GatewayPage.HOME) },
                                        modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp))
                                }
                            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
                            GatewayPage.entries.forEach { destination ->
                                DropdownMenuItem(text = { Text(destination.label) },
                                    onClick = { menu = false; navigate(destination) },
                                    modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp).semantics {
                                        selected = page == destination
                                        stateDescription = if (page == destination) "Current screen" else "Open screen"
                                    })
                            }
                        }
                    }
                }
                CompositionLocalProvider(LocalGatewayScrollReset provides resetScroll,
                    LocalGatewayCompactHome provides compactHome,
                    LocalGatewayHomePanel provides homePanel) {
                    content(page, navigate)
                }
            }
        }
    }
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
internal fun GatewayHome(
    authenticatedStatus: String,
    testStatus: String,
    heartbeats: Int,
    sim: String,
    pairingStatus: String,
    power: GatewayPowerObservation = GatewayPowerObservation.unavailable(),
    summary: GatewaySummaryState.View = GatewaySummaryState.View(GatewaySummaryState.Phase.UNAVAILABLE, null),
    summaryStatus: String = "Message counts are unavailable on this phone. An authorized summary reader is not connected.",
    onSetup: () -> Unit,
    onConnection: () -> Unit,
    onPause: () -> Unit
) {
    val motion = gatewayMotionAllowed()
    val mood = GatewayConnectionMood.from(authenticatedStatus)
    val localPanel = remember { mutableStateOf<String?>(null) }
    var widget by (LocalGatewayHomePanel.current ?: localPanel)
    val compact = LocalGatewayCompactHome.current
    fun label(count: GatewaySummaryCount?): String = when (summary.phase) {
        GatewaySummaryState.Phase.UNAVAILABLE -> "Unavailable"
        GatewaySummaryState.Phase.LOADING -> count?.let { "${it.label()} (refreshing)" } ?: "Loading…"
        GatewaySummaryState.Phase.STALE -> count?.let { "${it.label()} (stale)" } ?: "Unavailable"
        GatewaySummaryState.Phase.FRESH -> count?.label() ?: "Unavailable"
    }
    GatewayEntrance(0, motion) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Gateway home", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.semantics { heading() })
            val status: @Composable () -> Unit = {
                Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(mood.title, style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
                    GatewayStatusText("Device status", authenticatedStatus, textAlign = TextAlign.Center)
                }
            }
            if (compact) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    GatewaySignal(mood, motion, compact = true)
                    Box(Modifier.weight(1f)) { status() }
                }
            } else {
                GatewaySignal(mood, motion)
                status()
            }
            Text("Connection proof only. SMS readiness is not verified.", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
        }
    }
    GatewayEntrance(1, motion) {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
            val prominent = summary.snapshot != null && summary.phase != GatewaySummaryState.Phase.UNAVAILABLE
            val connections = when (mood) {
                GatewayConnectionMood.CONNECTED -> "1"
                GatewayConnectionMood.PAUSED, GatewayConnectionMood.OFFLINE, GatewayConnectionMood.CONNECTING -> "0"
                GatewayConnectionMood.ATTENTION -> "Unavailable"
            }
            GatewayDashboardMetrics(connections, label(summary.snapshot?.submittedToday), prominent,
                onConnections = { widget = "connection" }, onMessages = { widget = "messages" })
            // Routine absent-reader information is available through Messages.
            // Every other observation, including refusal, revocation and errors,
            // stays visible without opening a panel.
            if (summaryStatus != "Message counts are unavailable on this phone. An authorized summary reader is not connected.") {
                Text(summaryStatus, modifier = Modifier.testTag("home-reader-status"), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
    GatewayEntrance(1, motion) {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
            GatewayObservationRow("Sending from", sim)
            GatewayObservationRow("Power", power.label)
        }
    }
    // Pause stays beside its complete disclosure in the main dashboard.
    GatewayHomeButton("Pause connections", onPause, Modifier.fillMaxWidth())
    Text("Pause stops connections. SMS receiving access can still process messages locally; revoke it in Android app settings to stop local processing.",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    if (widget != null) {
        ModalBottomSheet(onDismissRequest = { widget = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            containerColor = MaterialTheme.colorScheme.surface, contentColor = MaterialTheme.colorScheme.onSurface) {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)) {
                if (widget == "controls") {
                    GatewaySectionTitle("Quick controls")
                    GatewayHomeButton("Connection controls", { widget = null; onConnection() }, Modifier.fillMaxWidth())
                    GatewayHomeButton("Set up this phone", { widget = null; onSetup() }, Modifier.fillMaxWidth())
                    GatewayHomeButton("Android access", { widget = "access" }, Modifier.fillMaxWidth())
                    GatewayHomeButton("Phone details", { widget = "details" }, Modifier.fillMaxWidth())
                    Text("Full conversation sync is not available in this build.")
                } else if (widget == "messages") {
                    GatewaySectionTitle("Message details")
                    GatewayPrimaryMetrics(label(summary.snapshot?.submittedToday), label(summary.snapshot?.pending),
                        summary.snapshot != null && summary.phase != GatewaySummaryState.Phase.UNAVAILABLE)
                    GatewayObservationRow("Awaiting receipt", label(summary.snapshot?.inFlight))
                    Text(summaryStatus)
                    summary.snapshot?.let { snapshot ->
                        Text("Device-scoped UTC observation: ${java.time.Instant.ofEpochMilli(snapshot.observedMs)}. Submitted is not delivered. In queue includes accepted, queued and claimed work, which can already hold a grant. Awaiting receipt includes submitting and submitted states.")
                    }
                } else if (widget == "connection") {
                    GatewaySectionTitle("Connection details")
                    GatewayStatusText("Authenticated connection status", authenticatedStatus)
                    GatewayStatusText("Pairing in this session", pairingStatus)
                    GatewayStatusText("Test connection", testStatus)
                    Text("Heartbeat acknowledgments this session: $heartbeats")
                    Text("Counts authenticated links on this phone. Test sockets and heartbeat acknowledgments are not connection counts. An unrecognized connection state is unavailable.")
                    Text("Connection proof does not establish SMS readiness. Full conversation sync is not available in this build.")
                    GatewayHomeButton("Connection controls", { widget = null; onConnection() }, Modifier.fillMaxWidth())
                    Text("Pause stops connections. SMS receiving access can still process messages locally; revoke it in Android app settings to stop local processing.")
                } else if (widget == "access") {
                    GatewayAccessSummary()
                    Text("Pause stops connections. To stop permission-enabled local SMS processing, revoke SMS receiving access in Android app settings.")
                } else {
                    GatewaySectionTitle("Phone details")
                    GatewayStatusText("Pairing in this session", pairingStatus)
                    GatewayStatusText("Test connection", testStatus)
                    Text("Heartbeat acknowledgments this session: $heartbeats")
                    Text("This build supports connection tests, an inbound metadata pilot and a manually armed one-shot SMS test. Full conversation sync is not available.")
                    Text("Pause stops the connection, but SMS receiving access can still process messages locally. Revoke that access in Android app settings to stop local processing.")
                }
                TextButton(onClick = { widget = null }, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) {
                    Text("Close widget")
                }
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

/** The two quiet numbers open observations, never connection or messaging work. */
@Composable
private fun GatewayDashboardMetrics(connections: String, messages: String, prominent: Boolean,
    onConnections: () -> Unit, onMessages: () -> Unit) {
    BoxWithConstraints(Modifier.fillMaxWidth().testTag("home-dashboard-metrics")
        .semantics { isTraversalGroup = true }) {
        if (maxWidth < 312.dp || LocalDensity.current.fontScale > 1.3f) {
            val inline = LocalDensity.current.fontScale <= 1.3f
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                GatewayDashboardMetric("Connections", "Authenticated links", connections, true, 0f,
                    onConnections, Modifier.fillMaxWidth(), inline)
                GatewayDashboardMetric("Messages", "Submitted today", messages, prominent, 1f,
                    onMessages, Modifier.fillMaxWidth(), inline)
            }
        } else {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                GatewayDashboardMetric("Connections", "Authenticated links", connections, true, 0f,
                    onConnections, Modifier.weight(1f))
                GatewayDashboardMetric("Messages", "Submitted today", messages, prominent, 1f,
                    onMessages, Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun GatewayDashboardMetric(label: String, scope: String, value: String, prominent: Boolean,
    order: Float, onOpen: () -> Unit, modifier: Modifier, inline: Boolean = false) {
    TextButton(onClick = onOpen, modifier = modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)
        .clearAndSetSemantics {
            this[SemanticsProperties.TestTag] = "home-metric-$label"
            this[SemanticsProperties.Text] = listOf(AnnotatedString("$label. $scope. $value"))
            role = Role.Button
            traversalIndex = order
            onClick(label = "Open ${if (label == "Connections") "connection" else "message"} details") {
                onOpen(); true
            }
        }, colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onSurface),
        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 12.dp)) {
        val valueStyle = if (prominent) MaterialTheme.typography.headlineSmall else MaterialTheme.typography.bodyMedium
        val captions: @Composable () -> Unit = {
            Column(horizontalAlignment = if (inline) Alignment.Start else Alignment.CenterHorizontally) {
                Text(label, style = MaterialTheme.typography.labelMedium)
                Text(scope, style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = if (inline) TextAlign.Start else TextAlign.Center)
            }
        }
        if (inline) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Box(Modifier.weight(1f)) { captions() }
                Text(value, modifier = Modifier.weight(1f), style = valueStyle, textAlign = TextAlign.End,
                    color = if (prominent) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(value, style = valueStyle, textAlign = TextAlign.Center,
                    color = if (prominent) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                captions()
            }
        }
    }
}

/** Match the concept at ordinary width; compact windows and enlarged type keep a readable stack. */
@Composable
private fun GatewayPrimaryMetrics(submitted: String, pending: String, prominent: Boolean) {
    BoxWithConstraints(Modifier.fillMaxWidth().testTag("home-primary-metrics")
        .semantics { isTraversalGroup = true }) {
        if (maxWidth < 312.dp || LocalDensity.current.fontScale > 1.3f) {
            val inline = LocalDensity.current.fontScale <= 1.3f
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                GatewayPrimaryMetric("Submitted today", submitted, prominent, 0f, Modifier.fillMaxWidth(), inline)
                GatewayPrimaryMetric("In queue", pending, prominent, 1f, Modifier.fillMaxWidth(), inline)
            }
        } else {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                GatewayPrimaryMetric("Submitted today", submitted, prominent, 0f, Modifier.weight(1f))
                GatewayPrimaryMetric("In queue", pending, prominent, 1f, Modifier.weight(1f))
            }
        }
    }
}

/** Each static metric reads label first once, even though its visual value is above the label. */
@Composable
private fun GatewayPrimaryMetric(label: String, value: String, prominent: Boolean, order: Float, modifier: Modifier,
    inline: Boolean = false) {
    val observation = modifier.clearAndSetSemantics {
        this[SemanticsProperties.TestTag] = "home-observation-$label"
        this[SemanticsProperties.Text] = listOf(AnnotatedString("$label $value"))
        traversalIndex = order
    }
    val valueStyle = if (prominent) MaterialTheme.typography.titleLarge else MaterialTheme.typography.bodyMedium
    if (inline) {
        Row(observation, verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, modifier = Modifier.weight(1f), style = valueStyle, textAlign = TextAlign.End)
        }
    } else {
        Column(observation, horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(value, style = valueStyle, textAlign = TextAlign.Center)
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center)
        }
    }
}

/** Labels and observations reflow rather than truncating at large text sizes. */
@Composable
private fun GatewayObservationRow(label: String, value: String, prominent: Boolean = false) {
    val largeType = LocalDensity.current.fontScale > 1.3f
    val valueStyle = if (prominent) MaterialTheme.typography.titleLarge else MaterialTheme.typography.bodyMedium
    val description = Modifier.fillMaxWidth().testTag("home-observation-$label")
        .semantics(mergeDescendants = true) {}
    if (largeType) {
        Column(description, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = valueStyle)
        }
    } else {
        Row(description, horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.Top) {
            Text(label, modifier = Modifier.weight(0.35f), style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, modifier = Modifier.weight(0.65f), style = valueStyle, textAlign = TextAlign.End)
        }
    }
}

@Composable
private fun GatewayHomeSectionTitle(label: String) {
    Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.semantics { heading() })
}

/** Quiet Home actions retain a visible boundary, native button semantics and full-size targets. */
@Composable
private fun GatewayHomeButton(label: String, action: () -> Unit, modifier: Modifier = Modifier) {
    OutlinedButton(onClick = action, modifier = modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp),
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp), shape = MaterialTheme.shapes.small,
        colors = ButtonDefaults.outlinedButtonColors(containerColor = Color.Transparent,
            contentColor = MaterialTheme.colorScheme.onSurface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
        Text(label, textAlign = TextAlign.Center)
    }
}
