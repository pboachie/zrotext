// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/** Deliberate receive-only surface. The caller owns transient input, live authority and cancellation. */
@Composable
internal fun ConversationMessageReceivePane(
    reference: String,
    available: Boolean,
    outcome: ConversationMessageReceiveController.Outcome,
    onReference: (String) -> Unit,
    onReceive: () -> Unit,
    onCancel: () -> Unit
) {
    val busy = outcome == ConversationMessageReceiveController.Outcome.RECEIVING
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        GatewaySectionTitle("Receive a confirmed message")
        Text("Use the message reference from your paired browser after confirming its exact recipient and text. Receiving and verifying a message does not send carrier SMS.")
        OutlinedTextField(value = reference, onValueChange = { if (it.length <= 36) onReference(it) },
            enabled = available && !busy, singleLine = true, modifier = Modifier.fillMaxWidth(),
            label = { Text("Message reference") })
        Button(onClick = onReceive, enabled = available && !busy && reference.length == 36,
            modifier = Modifier.fillMaxWidth().sizeIn(minWidth = 48.dp, minHeight = 48.dp)) {
            Text("Receive and verify message")
        }
        if (busy) OutlinedButton(onClick = onCancel,
            modifier = Modifier.fillMaxWidth().sizeIn(minWidth = 48.dp, minHeight = 48.dp)) {
            Text("Cancel message review")
        }
        val status = when (outcome) {
            ConversationMessageReceiveController.Outcome.IDLE -> "The current conversation must be approved and active."
            ConversationMessageReceiveController.Outcome.RECEIVING -> "Receiving and verifying the confirmed message…"
            ConversationMessageReceiveController.Outcome.VERIFIED -> "Confirmed message received and verified."
            ConversationMessageReceiveController.Outcome.REFUSED -> "Use the exact message reference and a current approved conversation."
            ConversationMessageReceiveController.Outcome.UNKNOWN -> "Receipt not confirmed. Check the current conversation before another deliberate review."
            ConversationMessageReceiveController.Outcome.CANCELLED -> "Message review ended. Any receipt already saved remains protected on this phone."
        }
        Text(status, modifier = if (outcome == ConversationMessageReceiveController.Outcome.IDLE) Modifier
            else Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    }
}
