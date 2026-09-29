// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Handler
import android.os.Looper
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext

/** Spike status shown on screen; updates from worker threads are posted to the main thread. */
internal object MmsSpikeStatus {
    var value by mutableStateOf("Not started")
        private set

    private val main = Handler(Looper.getMainLooper())

    fun post(text: String) {
        main.post { value = text }
    }
}

/**
 * Local checks before the confirmation dialog. The same rules run again, with
 * the server grant and the STOP lookup, in [MmsSpikePolicy.preflight].
 */
internal fun mmsSpikeReviewRefusal(
    context: Context, recipient: String, selectedSim: Int?, activeSimIds: List<Int>
): String? = when {
    context.getSharedPreferences("mms_spike", Context.MODE_PRIVATE).getString("attempt_id", null) != null ->
        "Refused: one spike attempt already used on this install"
    selectedSim == null || selectedSim !in activeSimIds -> "Select an active SIM first"
    !recipient.matches(MmsSpikePolicy.E164) -> "Enter a valid +E.164 recipient"
    recipient !in MmsSpikeSend.buildAllowlist() -> "Refused: recipient is not in this build's MMS spike allowlist"
    else -> null
}

/**
 * Debug builds only: the release source set replaces this with an empty
 * composable, so a release screen has no MMS spike section.
 */
@Composable
internal fun MmsSpikeSection(selectedSim: Int?, activeSimIds: List<Int>) {
    val context = LocalContext.current
    var recipient by remember { mutableStateOf("") }
    var subject by remember { mutableStateOf("") }
    var confirming by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        JournalRuntime.io.execute { MmsSpikeSend.sweepOrphans(context.applicationContext) }
    }

    GatewaySectionTitle("Controlled MMS spike")
    Text("Debug builds only. Stage one of the MMS spike (#438): after you confirm the recipient, " +
        "the phone waits for a server-issued MMS grant on the authenticated device stream, checks " +
        "the build allowlist and the STOP list, and submits one synthetic-image MMS from the selected " +
        "SIM through the carrier default MMSC. One attempt per installation; an uncertain result is " +
        "never retried. The recipient is not journaled, and the composed message file is deleted " +
        "once the attempt ends.")
    OutlinedTextField(value = recipient, onValueChange = { recipient = it.trim() },
        label = { Text("Controlled MMS recipient +E.164") })
    OutlinedTextField(value = subject, onValueChange = { subject = it },
        label = { Text("Optional subject") })
    GatewayButton(onClick = {
        val refusal = mmsSpikeReviewRefusal(context, recipient, selectedSim, activeSimIds)
        if (refusal != null) MmsSpikeStatus.post(refusal) else confirming = recipient
    }) { Text("Review one synthetic MMS") }
    GatewayStatusText("MMS spike status", MmsSpikeStatus.value)
    HorizontalDivider()

    val shown = confirming
    val sim = selectedSim
    if (shown != null && sim != null) {
        AlertDialog(
            onDismissRequest = { confirming = null },
            title = { Text("Send one MMS?") },
            text = { Text("Recipient: $shown\nSIM subscription: $sim\n\nThis arms one attempt for " +
                "five minutes. It is sent only if the server issues a grant for this recipient.") },
            confirmButton = {
                TextButton(onClick = {
                    confirming = null
                    MmsSpikeArm.arm(MmsSpikeArmed(recipient, shown, subject, sim,
                        System.currentTimeMillis()))
                    MmsSpikeStatus.post("Armed for five minutes; waiting for a server MMS grant")
                }) { Text("Arm one MMS") }
            },
            dismissButton = {
                TextButton(onClick = { confirming = null }) { Text("Cancel") }
            }
        )
    }
}
