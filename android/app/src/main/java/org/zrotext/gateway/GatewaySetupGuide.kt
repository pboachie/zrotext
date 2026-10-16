// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.key
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

internal enum class GatewaySetupStep { OVERVIEW, ACCESS, SIM, PAIRING, COMPARE, CONNECT }

/** Presentation state is saveable. Permissions, key proofs and connection consent are not. */
@Composable
internal fun GatewaySetupGuide(
    selectedSim: String,
    pairingStatus: String,
    onConnection: () -> Unit,
    initialStep: GatewaySetupStep = GatewaySetupStep.OVERVIEW,
    recovery: GatewaySetupRecovery = GatewaySetupRecovery.NEW,
    onCheck: () -> Unit = {},
    onOwnerCustody: () -> Unit = {},
    onReplace: () -> Boolean = { false },
    accessContent: @Composable ColumnScope.() -> Unit,
    simContent: @Composable ColumnScope.() -> Unit,
    pairingContent: @Composable ColumnScope.() -> Unit,
    comparisonContent: @Composable ColumnScope.() -> Unit = {},
    connectionContent: @Composable ColumnScope.() -> Unit = {}
) {
    var step by rememberSaveable { mutableStateOf(initialStep) }
    val resetScroll = LocalGatewayScrollReset.current
    fun show(next: GatewaySetupStep) { step = next; resetScroll() }
    val next = when (recovery) {
        GatewaySetupRecovery.APPROVED -> if (selectedSim == "Not selected") GatewaySetupStep.SIM else GatewaySetupStep.CONNECT
        GatewaySetupRecovery.COMPARE, GatewaySetupRecovery.CHECKING, GatewaySetupRecovery.UNAVAILABLE,
        GatewaySetupRecovery.KEYS_LOST -> GatewaySetupStep.COMPARE
        else -> GatewaySetupStep.PAIRING
    }
    LaunchedEffect(recovery, selectedSim) {
        when (recovery) {
            GatewaySetupRecovery.NEW -> Unit
            GatewaySetupRecovery.APPROVED -> show(next)
            else -> show(GatewaySetupStep.COMPARE)
        }
    }
    BackHandler(enabled = step != GatewaySetupStep.OVERVIEW) { show(GatewaySetupStep.OVERVIEW) }
    if (step == GatewaySetupStep.OVERVIEW) {
        GatewaySectionTitle("Set up this phone")
        Text("1 Scan  ·  2 Compare  ·  3 SIM & access  ·  4 Connect", style = MaterialTheme.typography.labelSmall)
    }
    key(step) {
        Column(Modifier.fillMaxWidth().semantics { paneTitle = "Phone setup: ${step.name.lowercase()}" },
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (step != GatewaySetupStep.OVERVIEW) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween) {
                    TextButton(onClick = { show(GatewaySetupStep.OVERVIEW) },
                        modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)) { Text("Setup overview") }
                    Text(when (step) {
                        GatewaySetupStep.PAIRING -> "Step 1 of 4"
                        GatewaySetupStep.COMPARE -> "Step 2 of 4"
                        GatewaySetupStep.SIM -> "Step 3 of 4"
                        GatewaySetupStep.CONNECT -> "Step 4 of 4"
                        else -> "Optional access"
                    }, style = MaterialTheme.typography.labelSmall)
                }
            }
            when (step) {
                GatewaySetupStep.OVERVIEW -> {
                    Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = MaterialTheme.shapes.large,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline), modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(recovery.title, style = MaterialTheme.typography.titleMedium)
                            Text(recovery.detail)
                            Text("Selected SIM: $selectedSim")
                            GatewayStatusText("Pairing in this session", pairingStatus)
                            GatewayButton(onClick = { show(next) }, modifier = Modifier.fillMaxWidth()) { Text("Continue setup") }
                        }
                    }
                    Text("Pairing does not require SMS access. Your account and subscription stay on the website; this app connects the phone.")
                    TextButton(onClick = { show(GatewaySetupStep.ACCESS) }, modifier = Modifier.sizeIn(minHeight = 48.dp)) { Text("Review Android access") }
                    OutlinedButton(onClick = onConnection, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Advanced connection controls") }
                    TextButton(onClick = onOwnerCustody, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Set up or recover owner custody on Android") }
                }
                GatewaySetupStep.PAIRING -> {
                    GatewaySectionTitle("Device pairing")
                    Text("Use the service you trust. The QR must match it; scanning does not approve the phone or grant SMS access.")
                    pairingContent()
                }
                GatewaySetupStep.COMPARE -> {
                    GatewaySectionTitle(if (recovery in setOf(GatewaySetupRecovery.NEW, GatewaySetupRecovery.COMPARE))
                        "Compare phone details" else "Pairing recovery")
                    if (recovery != GatewaySetupRecovery.COMPARE) Text(recovery.title, style = MaterialTheme.typography.titleSmall)
                    Text(recovery.detail)
                    comparisonContent()
                    if (recovery !in setOf(GatewaySetupRecovery.KEYS_LOST, GatewaySetupRecovery.COMPARE)) {
                        OutlinedButton(onClick = onCheck, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Check saved pairing") }
                    }
                    if (recovery == GatewaySetupRecovery.UNAVAILABLE) {
                        var help by rememberSaveable { mutableStateOf(false) }
                        TextButton(onClick = { help = !help }, modifier = Modifier.sizeIn(minHeight = 48.dp)) { Text("Get setup help") }
                        if (help) Text("Open your trusted operator's owner dashboard to check service availability or contact support. Support reference: pairing-status-unavailable. Do not share pairing tokens, private keys or message content.")
                    }
                    if (recovery in setOf(GatewaySetupRecovery.EXPIRED, GatewaySetupRecovery.CANCELLED,
                            GatewaySetupRecovery.PROOF_REQUIRED, GatewaySetupRecovery.KEYS_LOST)) {
                        TextButton(onClick = { if (onReplace()) show(GatewaySetupStep.PAIRING) }, modifier = Modifier.sizeIn(minHeight = 48.dp)) { Text("Use replacement pairing") }
                    }
                }
                GatewaySetupStep.SIM -> {
                    GatewaySectionTitle("Choose a SIM")
                    Text("Choose the active line explicitly. If the SIM changes or access is revoked, return here; account and phone pairing remain separate.")
                    simContent()
                    TextButton(onClick = { show(GatewaySetupStep.ACCESS) }, modifier = Modifier.sizeIn(minHeight = 48.dp)) { Text("Review Android access") }
                    GatewayButton(onClick = { show(GatewaySetupStep.CONNECT) }, modifier = Modifier.fillMaxWidth()) { Text("Next: connection") }
                    Text("SMS sending and receiving access are separate choices. A selected SIM alone does not prove carrier readiness.", style = MaterialTheme.typography.bodySmall)
                }
                GatewaySetupStep.ACCESS -> {
                    GatewaySectionTitle("Review access")
                    GatewayAccessSummary()
                    accessContent()
                    GatewayButton(onClick = { show(GatewaySetupStep.SIM) }, modifier = Modifier.fillMaxWidth()) { Text("Back to SIM selection") }
                }
                GatewaySetupStep.CONNECT -> {
                    GatewaySectionTitle("Connect this phone")
                    connectionContent()
                    TextButton(onClick = { show(GatewaySetupStep.SIM) }, modifier = Modifier.sizeIn(minHeight = 48.dp)) { Text("Change SIM or review access") }
                    OutlinedButton(onClick = onConnection, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Advanced connection controls") }
                }
            }
        }
    }
}
