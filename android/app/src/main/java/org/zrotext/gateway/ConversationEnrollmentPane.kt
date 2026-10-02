// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.runtime.Composable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.Checkbox
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Public bytes only. Fingerprint is entered separately; a downloaded value never fills it. */
@Composable internal fun ConversationEnrollmentPane(
    pin: String, fingerprint: String, compared: Boolean, reviewed: Boolean, busy: Boolean,
    status: String, export: String, chain: String,
    changePin: (String) -> Unit, changeFingerprint: (String) -> Unit, changeCompared: (Boolean) -> Unit,
    changeChain: (String) -> Unit, createReader: () -> Unit, reviewRoot: () -> Unit, confirmRoot: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Enrollment is separate from pairing and content consent. Creating a reader keeps a private hardware key and local journal keys on this phone. Closing this screen stops pending work; it does not delete completed enrollment. No message is sent here.")
        Button(onClick = createReader, enabled = !busy,
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Enroll hardware reader and journal protection") }
        if (export.isNotEmpty()) OutlinedTextField(value = export, onValueChange = {}, readOnly = true,
            label = { Text("Public reader for the owner enrollment") }, modifier = Modifier.fillMaxWidth())
        Text("Obtain your existing account's public root pin from the offline custodian. Compare its full fingerprint through an independent channel. Never enter a private root or recovery token here.")
        OutlinedTextField(value = pin, onValueChange = changePin, enabled = !busy,
            label = { Text("Public root pin (base64, 94 bytes)") }, maxLines = 3, modifier = Modifier.fillMaxWidth())
        Button(onClick = reviewRoot, enabled = !busy && pin.isNotEmpty(),
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Review public root for this account") }
        OutlinedTextField(value = fingerprint, onValueChange = changeFingerprint, enabled = !busy,
            label = { Text("Independent full root fingerprint (64 hex characters)") }, maxLines = 2,
            modifier = Modifier.fillMaxWidth())
        Text("I independently compared this account and full fingerprint with my offline custodian.")
        Checkbox(checked = compared, onCheckedChange = changeCompared, enabled = !busy)
        Button(onClick = confirmRoot, enabled = !busy && reviewed && compared && fingerprint.length == 64,
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Enroll independently compared root") }
        Text("For the first review, paste the complete root-signed manifest chain from genesis through the setup predecessor, one canonical base64 manifest per line. Every newly accepted link must still be unexpired. These public bytes are checked using authenticated server time when you explicitly start review. This flow cannot restore expired history or replace a lost key. Existing enrolled phones can leave this blank.")
        OutlinedTextField(value = chain, onValueChange = changeChain, enabled = !busy,
            label = { Text("Public initial manifest chain (base64 lines)") }, maxLines = 4,
            modifier = Modifier.fillMaxWidth())
        if (status.isNotEmpty()) Text(status)
    }
}
