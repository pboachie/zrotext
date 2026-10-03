// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

/** Separate line-only disclosure. No permission, body-transfer or reply approval is inferred. */
@Composable internal fun SealedLineReviewPane(
    line: String, generation: String, onLine: (String) -> Unit, onGeneration: (String) -> Unit,
    review: SealedLineReviewController.Review?, status: String,
    onPrepare: () -> Unit, onConfirm: (SealedLineReviewController.Review) -> Unit, onCancel: () -> Unit
) {
    Dialog(onDismissRequest = onCancel, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding()
                .verticalScroll(rememberScrollState()).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Approve this phone line", style = MaterialTheme.typography.titleLarge)
                Text("Enter the line ID and generation shown by your paired browser. This separate phone choice approves line setup only. Message content transfer and replies require their own later approvals. This action does not send an SMS.")
                OutlinedTextField(line, onLine, label = { Text("Browser line ID") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(generation, onGeneration, label = { Text("Browser line generation") },
                    singleLine = true, modifier = Modifier.fillMaxWidth())
                Button(onClick = onPrepare, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) {
                    Text("Review selected phone line")
                }
                review?.let { exact ->
                    Text("Account: ${exact.account}\nPhone: ${exact.device}\nLine: ${exact.line}\nGeneration: ${exact.generation}\nSelected SIM subscription: ${exact.subscription}")
                    Text("Confirm only if these details match your paired browser and selected phone SIM.")
                    Button(onClick = { onConfirm(exact) }, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) {
                        Text("Approve this exact line on this phone")
                    }
                }
                if (status.isNotEmpty()) Text(status)
                OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) {
                    Text("Close review and withdraw line approval")
                }
            }
        }
    }
}
