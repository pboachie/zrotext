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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp

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
        Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding().clipToBounds()
            .verticalScroll(scroll).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("ZROtext", style = MaterialTheme.typography.headlineLarge,
                color = MaterialTheme.colorScheme.primary, modifier = Modifier.semantics { heading() })
            Text("Your phone. Your SMS gateway.", style = MaterialTheme.typography.bodyMedium)
            GatewayPage.entries.chunked(2).forEach { pages ->
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    pages.forEach { destination ->
                        OutlinedButton(onClick = { navigate(destination) },
                            shape = MaterialTheme.shapes.medium,
                            colors = ButtonDefaults.outlinedButtonColors(
                                containerColor = if (page == destination) MaterialTheme.colorScheme.surfaceVariant else Color.Transparent,
                                contentColor = if (page == destination) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface),
                            modifier = Modifier.weight(1f).sizeIn(minHeight = 48.dp).semantics {
                                selected = page == destination
                                stateDescription = if (page == destination) "Current screen" else "Open screen"
                            }, border = BorderStroke(1.dp, if (page == destination)
                                MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline)) {
                            Text(destination.label)
                        }
                    }
                }
            }
            content(page, navigate)
        }
    }
}

@Composable
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
    GatewaySectionTitle("Gateway home")
    Surface(color = MaterialTheme.colorScheme.surface, shape = MaterialTheme.shapes.large,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            GatewaySectionTitle("Authenticated connection")
            GatewayStatusText("Device status", authenticatedStatus)
            Text("Heartbeat acknowledgments this session: $heartbeats")
            Text("A connection does not establish SMS readiness or authorize sending.",
                style = MaterialTheme.typography.bodyMedium)
            GatewayButton(onClick = onConnection, modifier = Modifier.fillMaxWidth()) {
                Text("Connection controls")
            }
            GatewayButton(onClick = onPause, modifier = Modifier.fillMaxWidth()) {
                Text("Pause connections")
            }
        }
    }
    GatewaySectionTitle("This phone")
    Text("Selected SIM: $sim")
    GatewayStatusText("Pairing in this session", pairingStatus)
    GatewayButton(onClick = onSetup, modifier = Modifier.fillMaxWidth()) { Text("Set up this phone") }
    GatewayStatusText("Test connection", testStatus)
    Text("This build supports connection tests, an inbound metadata pilot and a manually armed one-shot SMS test. Full conversation sync is not available.",
        style = MaterialTheme.typography.bodyMedium)
    Text("Pause stops the connection, but SMS receiving access can still process messages locally. Revoke that access in Android app settings to stop local processing.",
        style = MaterialTheme.typography.bodyMedium)
}
