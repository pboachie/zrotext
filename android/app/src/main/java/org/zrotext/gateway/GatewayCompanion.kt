// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.TextButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

internal val LocalGatewayScrollReset = staticCompositionLocalOf<() -> Unit> { {} }

internal enum class GatewayPage(val label: String) {
    HOME("Home"), SETUP("Setup"), CONNECTION("Connection"), TOOLS("Tools")
}

/** Navigation is presentation only: changing pages never starts a service or asks for access. */
@Composable
internal fun GatewayCompanion(initialPage: GatewayPage = GatewayPage.HOME,
    content: @Composable ColumnScope.(GatewayPage, (GatewayPage) -> Unit) -> Unit) {
    var page by rememberSaveable { mutableStateOf(initialPage) }
    val screenState = rememberSaveableStateHolder()
    val navigate: (GatewayPage) -> Unit = { page = it }
    BackHandler(enabled = page != GatewayPage.HOME) { page = GatewayPage.HOME }
    // Scroll the entire screen so a keyboard, landscape window or large type
    // cannot let fixed navigation consume the space needed by the controls.
    screenState.SaveableStateProvider(page.name) {
        val scroll = rememberScrollState()
        val scope = rememberCoroutineScope()
        val resetScroll: () -> Unit = { scope.launch { scroll.scrollTo(0) } }
        Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding().clipToBounds()
            .verticalScroll(scroll).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                GatewayBrandMark()
                Text("ZROtext", style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.semantics { heading() })
            }
            val columns = if (LocalDensity.current.fontScale > 1.3f) 2 else 4
            GatewayPage.entries.chunked(columns).forEach { pages ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    pages.forEach { destination ->
                        OutlinedButton(onClick = { navigate(destination) },
                            contentPadding = PaddingValues(horizontal = 4.dp, vertical = 8.dp),
                            shape = MaterialTheme.shapes.medium,
                            colors = ButtonDefaults.outlinedButtonColors(
                                containerColor = if (page == destination) MaterialTheme.colorScheme.surfaceVariant else Color.Transparent,
                                contentColor = if (page == destination) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface),
                            modifier = Modifier.weight(1f).sizeIn(minHeight = 48.dp).semantics {
                                selected = page == destination
                                stateDescription = if (page == destination) "Current screen" else "Open screen"
                            }, border = BorderStroke(1.dp, if (page == destination)
                                MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline)) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                GatewayShortcutIcon(destination)
                                Text(destination.label, style = MaterialTheme.typography.labelSmall,
                                    textAlign = TextAlign.Center)
                            }
                        }
                    }
                }
            }
            CompositionLocalProvider(LocalGatewayScrollReset provides resetScroll) {
                content(page, navigate)
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
    onSetup: () -> Unit,
    onConnection: () -> Unit,
    onPause: () -> Unit
) {
    val motion = gatewayMotionAllowed()
    val mood = GatewayConnectionMood.from(authenticatedStatus)
    var widget by remember { mutableStateOf<String?>(null) }
    GatewayEntrance(0, motion) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Gateway home", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.semantics { heading() })
            GatewaySignal(mood, motion)
            Text(mood.title, style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
            GatewayStatusText("Device status", authenticatedStatus)
            Text("Connection proof, not SMS readiness.", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center)
        }
    }
    // Pause stays in the main flow, never inside a secondary widget.
    OutlinedButton(onClick = onPause, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.primary),
        shape = MaterialTheme.shapes.medium, border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
        Text("Pause connections")
    }
    Text("Pause stops connections. SMS receiving access can still process messages locally; revoke it in Android app settings to stop local processing.",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    GatewayEntrance(1, motion) {
        Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.large,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                GatewaySectionTitle("This phone")
                Text("Selected SIM: $sim", style = MaterialTheme.typography.bodyMedium)
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.45f))
                Text("Heartbeat acknowledgments this session: $heartbeats",
                    style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
    GatewayEntrance(2, motion) {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            GatewaySectionTitle("Quick controls")
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                GatewayButton(onClick = onConnection, modifier = Modifier.weight(1f)) { Text("Connection controls") }
                GatewayButton(onClick = onSetup, modifier = Modifier.weight(1f)) { Text("Set up this phone") }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { widget = "access" }, modifier = Modifier.weight(1f).sizeIn(minHeight = 48.dp)) {
                    Text("Android access")
                }
                OutlinedButton(onClick = { widget = "details" }, modifier = Modifier.weight(1f).sizeIn(minHeight = 48.dp)) {
                    Text("Phone details")
                }
            }
        }
    }
    Text("Full conversation sync is not available in this build.",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    if (widget != null) {
        ModalBottomSheet(onDismissRequest = { widget = null },
            containerColor = MaterialTheme.colorScheme.surface, contentColor = MaterialTheme.colorScheme.onSurface) {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)) {
                if (widget == "access") {
                    GatewayAccessSummary()
                    Text("Pause stops connections. To stop permission-enabled local SMS processing, revoke SMS receiving access in Android app settings.")
                } else {
                    GatewaySectionTitle("Phone details")
                    GatewayStatusText("Pairing in this session", pairingStatus)
                    GatewayStatusText("Test connection", testStatus)
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
