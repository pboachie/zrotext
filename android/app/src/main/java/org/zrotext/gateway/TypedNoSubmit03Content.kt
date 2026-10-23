// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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

/** Optional metadata in the existing details panel. Resume/Host changes discover rows
 * only; reporting, status, clock and signing still require a NEW affirmative action. */
@Composable internal fun TypedNoSubmit03Content() {
    val app = LocalContext.current.applicationContext
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val foreground = remember(lifecycle) { ConversationInterval03Foreground() }
    val discovery = remember(foreground) { TypedNoSubmit03Discovery(foreground) }
    val hostRevision by TypedHistory03Connections.hostChanges.collectAsState()
    val scope = rememberCoroutineScope()
    var selected by remember { mutableStateOf<TypedNoSubmit03Discovery.Display?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    fun load(after: String = "", previousHost: TypedHistory03Connections.Host? = null) {
        val host = TypedHistory03Connections.current()
        val pending = runCatching { discovery.begin(host, lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }.getOrNull()
        selected = null; busy = false; status = null
        pending ?: return
        val cursor = if (host === previousHost) after else ""
        TypedHistory03Runtime.cancellationWork {
            val row = runCatching {
                pending.host.requireCurrent()
                val dao = SmsJournalDatabase.get(app).typedNoSubmits03()
                fun page(value: String) = dao.choices(pending.host.identity.accountId, pending.host.identity.deviceId,
                    pending.host.identity.originHash, TypedSubmit03Record.base(pending.host.point()), value)
                var rows = page(cursor); pending.host.requireCurrent()
                if (rows.isEmpty() && cursor.isNotEmpty()) { rows = page(""); pending.host.requireCurrent() }
                rows.firstOrNull()?.also(pending.host::requireOriginal)
            }.getOrNull()
            scope.launch {
                runCatching { discovery.publish(pending, row, lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
                    .getOrNull()?.let { selected = it }
            }
        }
    }
    DisposableEffect(lifecycle) {
        val listener = LifecycleEventObserver { _, _ ->
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) load()
            else {
                discovery.begin(null, false)
                selected = null; busy = false
            }
        }
        lifecycle.addObserver(listener)
        foreground.update(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
        onDispose { lifecycle.removeObserver(listener); discovery.close() }
    }
    LaunchedEffect(hostRevision, lifecycle) {
        if (lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) load()
    }
    selected?.let { display ->
        val row = display.row
        fun act(checkOnly: Boolean) {
            if (busy) return
            val action = runCatching { discovery.capture(display) }.getOrNull()
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
                    display.host.requireCurrent()
                    SmsJournalDatabase.get(app).typedSubmits03().get(row.attemptId)?.also(display.host::requireOriginal)
                }.getOrNull()
                scope.launch {
                    val next = refreshed?.let { runCatching {
                        discovery.refresh(display, it, lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
                    }.getOrNull() }
                    if (next != null) {
                        selected = next; busy = false
                        status = result?.text ?: "Saved cancellation remains unconfirmed. Its original records are kept; no message is retried."
                    } else if (discovery.isDisplayed(display)) {
                        busy = false
                        status = "Original cancellation records could not be refreshed. The saved cancellation remains unconfirmed."
                    }
                }
            }
        }
        Column {
            Text("Saved cancellation for message ${row.messageId}")
            Text("Reporting this saved cancellation does not send or retry a message.")
            status?.let { Text(it) }
            GatewayHomeButton("Report saved cancellation", { act(false) })
            GatewayHomeButton("Check saved cancellation status", { act(true) })
            GatewayHomeButton("Next saved cancellation", { if (!busy) load(row.attemptId, display.host) })
        }
    }
}
