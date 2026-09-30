// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Public policy and monitored deletion-request instructions; opens no SMS flow. */
@Composable
fun GatewayPrivacyLinks() {
    val context = LocalContext.current
    fun open(url: String) {
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
        } catch (_: ActivityNotFoundException) {
            Toast.makeText(context, "Open $url in a browser", Toast.LENGTH_LONG).show()
        }
    }
    Column {
        TextButton(onClick = { open("https://zrotext.com/privacy") },
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) {
            Text("Privacy policy")
        }
        TextButton(onClick = { open("https://zrotext.com/privacy#deletion") },
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) {
            Text("Account and data deletion requests")
        }
        Text("Request instructions explain identity verification and retained-data limits.")
    }
}
