// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import java.util.concurrent.atomic.AtomicBoolean

/** A user must affirm the exact displayed original while the Activity remains foreground.
 * Backgrounding or replacement withdraws a pending signing decision before worker completion.
 */
@Composable internal fun ConversationInterval03Content(lifecycle: Lifecycle) {
    val shown = ConversationInterval03Mount.review ?: return
    val foreground = remember(shown) { AtomicBoolean(false) }
    var approved by remember(shown) { mutableStateOf(false) }
    DisposableEffect(lifecycle, shown) {
        val observer = LifecycleEventObserver { _, _ -> foreground.set(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
        lifecycle.addObserver(observer); foreground.set(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
        onDispose { foreground.set(false); lifecycle.removeObserver(observer) }
    }
    Column(Modifier.fillMaxWidth().padding(vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        GatewaySectionTitle("Approve conversation")
        GatewayStatusText("Conversation", shown.peer)
        GatewayStatusText("Line", shown.line.toString())
        GatewayStatusText("Archive reader", shown.archiveKey)
        GatewayStatusText("Phone content signer", shown.phoneSigner)
        GatewayStatusText("Browser content signer", shown.browserSigner)
        GatewayStatusText("Additional customer readers", shown.integrationCount.toString())
        GatewayStatusText("Approval ends", java.time.Instant.ofEpochMilli(shown.intervalExpiresMs).toString())
        Text(ConversationInterval03.DISCLOSURE)
        Row { Checkbox(approved, { approved = it }); Text("I approve this conversation and these encrypted-content readers") }
        Button(onClick = { runCatching { ConversationInterval03Mount.approve(shown, foreground) }; approved = false },
            enabled = approved, modifier = Modifier.fillMaxWidth()) { Text("Approve or continue this conversation") }
        OutlinedButton(onClick = { runCatching { ConversationInterval03Mount.readStatus(shown) } },
            modifier = Modifier.fillMaxWidth()) { Text("Check original status") }
        OutlinedButton(onClick = { runCatching { ConversationInterval03Mount.retry(shown, foreground) } },
            modifier = Modifier.fillMaxWidth()) { Text("Retry original acknowledgement") }
        OutlinedButton(onClick = { runCatching { ConversationInterval03Mount.stop(shown) }; approved = false },
            modifier = Modifier.fillMaxWidth()) { Text("Stop conversation on this phone") }
        Text(ConversationInterval03Mount.status)
    }
}
