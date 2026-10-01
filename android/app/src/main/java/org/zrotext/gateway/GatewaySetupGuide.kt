// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

internal enum class GatewaySetupStep { OVERVIEW, ACCESS, SIM, PAIRING }

/** All actions are supplied by the activity: this guide only changes presentation. */
@Composable
internal fun GatewaySetupGuide(
    selectedSim: String,
    pairingStatus: String,
    onConnection: () -> Unit,
    initialStep: GatewaySetupStep = GatewaySetupStep.OVERVIEW,
    accessContent: @Composable ColumnScope.() -> Unit,
    simContent: @Composable ColumnScope.() -> Unit,
    pairingContent: @Composable ColumnScope.() -> Unit
) {
    var step by rememberSaveable { mutableStateOf(initialStep) }
    val resetScroll = LocalGatewayScrollReset.current
    val motion = gatewayMotionAllowed()
    fun show(next: GatewaySetupStep) { step = next; resetScroll() }
    BackHandler(enabled = step != GatewaySetupStep.OVERVIEW) { show(GatewaySetupStep.OVERVIEW) }
    GatewaySectionTitle("Set up this phone")
    key(step) {
        GatewayEntrance(0, motion) {
            Column(Modifier.fillMaxWidth().semantics { paneTitle = "Phone setup: ${step.name.lowercase()}" },
                verticalArrangement = Arrangement.spacedBy(16.dp)) {
                if (step != GatewaySetupStep.OVERVIEW) {
                    TextButton(onClick = { show(GatewaySetupStep.OVERVIEW) },
                        modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)) { Text("Setup overview") }
                }
                when (step) {
                    GatewaySetupStep.OVERVIEW -> {
                        Text("SMS access is optional for pairing and connection tests. Pairing can proceed without selecting a SIM; current connection controls require a selected SIM.")
                        Text("Selected SIM: $selectedSim")
                        GatewayStatusText("Pairing in this session", pairingStatus)
                        GatewaySetupCard("1. Review access", "Choose each purpose separately. You can decline SMS access.") { show(GatewaySetupStep.ACCESS) }
                        GatewaySetupCard("2. Choose a SIM", "Choose an active line for connection controls and controlled SMS pilots; pairing can proceed without one.") { show(GatewaySetupStep.SIM) }
                        GatewaySetupCard("3. Pair this phone", "Enter the one-use pairing values and compare the phone and browser before owner approval.") { show(GatewaySetupStep.PAIRING) }
                        OutlinedButton(onClick = onConnection, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Open connection controls") }
                        Text("These steps do not activate SMS or full conversation sync. Connection controls remain a separate, explicit action.",
                            style = MaterialTheme.typography.bodySmall)
                    }
                    GatewaySetupStep.ACCESS -> {
                        Text("Step 1 of 3")
                        GatewaySectionTitle("Review access")
                        GatewayAccessSummary()
                        accessContent()
                        GatewayButton(onClick = { show(GatewaySetupStep.SIM) }, modifier = Modifier.fillMaxWidth()) { Text("Next: choose SIM") }
                        TextButton(onClick = { show(GatewaySetupStep.PAIRING) }, modifier = Modifier.sizeIn(minHeight = 48.dp)) { Text("Go to pairing without SMS access") }
                    }
                    GatewaySetupStep.SIM -> {
                        Text("Step 2 of 3")
                        GatewaySectionTitle("Choose a SIM")
                        Text("If no line appears, review SIM access or check that an active SIM is installed. A selected line alone does not prove SMS readiness.")
                        simContent()
                        GatewayButton(onClick = { show(GatewaySetupStep.PAIRING) }, modifier = Modifier.fillMaxWidth()) { Text("Next: pairing") }
                        Text("You can pair without selecting a SIM. A controlled SMS pilot still requires its own checks and explicit authorization.", style = MaterialTheme.typography.bodySmall)
                    }
                    GatewaySetupStep.PAIRING -> {
                        Text("Step 3 of 3")
                        GatewaySectionTitle("Device pairing")
                        Text("Use the one-use pairing values from your owner account and keep the owner page open for comparison. If this screen restarts, re-enter those one-use values.")
                        pairingContent()
                        OutlinedButton(onClick = onConnection, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Open connection controls") }
                        Text("Compare the browser values before owner approval. Opening connection controls does not approve pairing or start a session.", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

@Composable
private fun GatewaySetupCard(title: String, detail: String, onClick: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.large,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            GatewayButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) { Text(title) }
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
