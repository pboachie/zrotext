// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.launch

/** Optional content in the existing details panel. It displays one exact metadata row;
 * it neither decrypts content nor reconstructs a peer/old positive permission. */
@Composable internal fun TypedNoSubmit03Content() {
    val app = LocalContext.current.applicationContext
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val foreground = remember { ConversationInterval03Foreground() }
    val scope = rememberCoroutineScope()
    var selected by remember { mutableStateOf<Pair<TypedSubmit03Record, TypedHistory03Connections.Host>?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    fun load(host: TypedHistory03Connections.Host, after: String) {
        TypedHistory03Runtime.cancellationWork {
            val row = runCatching {
                host.requireCurrent()
                val dao = SmsJournalDatabase.get(app).typedNoSubmits03()
                fun page(cursor: String) = dao.choices(host.identity.accountId, host.identity.deviceId,
                    host.identity.originHash, TypedSubmit03Record.base(host.point()), cursor)
                var rows = page(after); host.requireCurrent()
                if (rows.isEmpty() && after.isNotEmpty()) { rows = page(""); host.requireCurrent() }
                rows.firstOrNull()?.also(host::requireOriginal)
            }.getOrNull()
            scope.launch { if (row != null) {
                foreground.update(false)
                foreground.update(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
                selected = row to host
            } }
        }
    }
    DisposableEffect(lifecycle) {
        val listener = LifecycleEventObserver { _, _ -> foreground.update(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
        lifecycle.addObserver(listener); foreground.update(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
        onDispose { lifecycle.removeObserver(listener); foreground.close() }
    }
    LaunchedEffect(Unit) {
        val host = TypedHistory03Connections.current() ?: return@LaunchedEffect
        load(host, "")
    }
    selected?.let { (row, host) ->
        fun act(checkOnly: Boolean) {
            if (busy) return
            val action = runCatching { TypedNoSubmit03Action.capture(row, host, foreground.decision()) }.getOrNull()
            if (action == null) { status = "Reconnect this phone and review its saved cancellation while the app is open."; return }
            busy = true
            status = if (checkOnly) "Checking this saved cancellation…" else "Reporting this saved cancellation…"
            TypedHistory03Runtime.cancellationWork {
                val result = runCatching {
                    val reporter = TypedNoSubmit03Reporter(SmsJournalDatabase.get(app)) { entry, context ->
                        DeviceSigningKeyStore(app).signNoSubmit03(entry, context)
                    }
                    if (checkOnly) reporter.status(action) else reporter.report(action)
                }.getOrNull()
                val refreshed = runCatching {
                    host.requireCurrent()
                    SmsJournalDatabase.get(app).typedSubmits03().get(row.attemptId)?.also(host::requireOriginal)
                }.getOrNull()
                scope.launch {
                    foreground.update(false)
                    foreground.update(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
                    if (refreshed != null) selected = refreshed to host
                    busy = false
                    status = result?.text ?: "Saved cancellation remains unconfirmed. Its original records are kept; no message is retried."
                }
            }
        }
        Column {
            Text("Saved cancellation for message ${row.messageId}")
            Text("Reporting this saved cancellation does not send or retry a message.")
            status?.let { Text(it) }
            GatewayHomeButton("Report saved cancellation", { act(false) })
            GatewayHomeButton("Check saved cancellation status", { act(true) })
            GatewayHomeButton("Next saved cancellation", {
                if (!busy) {
                    // A display replacement withdraws a previous queued decision even if
                    // the replacement finishes after another resume/frame.
                    foreground.update(false)
                    foreground.update(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
                    status = null; load(host, row.attemptId)
                }
            })
        }
    }
}
