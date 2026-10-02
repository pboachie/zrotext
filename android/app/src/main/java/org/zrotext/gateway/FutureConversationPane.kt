// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.delay

/** Dormant presentation only. The caller must resolve the exact line/generation to a known label. */
@Composable
internal fun FutureConversationPane(
    port: ConversationPresentationPort,
    lineLabel: (String, Long) -> String?,
    modifier: Modifier = Modifier,
    onDismiss: () -> Unit = {},
    onStopRequested: () -> Unit = {}
) {
    var snapshot by remember(port) { mutableStateOf<ConversationPresentationSnapshot?>(null) }
    var receivedAt by remember(port) { mutableLongStateOf(0) }
    var expired by remember(port) { mutableStateOf(false) }
    var pending by remember(port) { mutableStateOf(false) }
    var actionFailed by remember(port) { mutableStateOf(false) }
    var dismissedVersion by remember(port) { mutableStateOf<Long?>(null) }
    var highestVersion by remember(port) { mutableLongStateOf(0) }
    var observationFailed by remember(port) { mutableStateOf(false) }
    var subscriptionRetry by remember(port) { mutableIntStateOf(0) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(port, lifecycle, subscriptionRetry) {
        val handler = Handler(Looper.getMainLooper())
        var subscription: AutoCloseable? = null
        var accepting = AtomicBoolean(false)
        fun unsubscribe() {
            accepting.set(false)
            subscription?.let { runCatching { it.close() } }
            subscription = null
            snapshot = null
            expired = false
            pending = false
        }
        fun subscribe() {
            if (subscription != null) return
            val token = AtomicBoolean(true)
            accepting = token
            subscription = runCatching { port.observe { next ->
                val observedAt = SystemClock.elapsedRealtime()
                handler.post {
                    if (token.get() && next.version > highestVersion) {
                        highestVersion = next.version
                        snapshot = next
                        receivedAt = observedAt
                        val remaining = next.review?.remainingMs ?: next.remainingMs
                        val elapsed = SystemClock.elapsedRealtime() - observedAt
                        expired = remaining > 0 && (elapsed < 0 || elapsed >= remaining)
                        pending = false
                        actionFailed = false
                    }
                }
            } }.getOrElse { token.set(false); observationFailed = true; null }
        }
        val observer = LifecycleEventObserver { _, _ ->
            if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) subscribe() else unsubscribe()
        }
        lifecycle.addObserver(observer)
        if (lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) subscribe()
        onDispose { lifecycle.removeObserver(observer); unsubscribe() }
    }
    val current = snapshot
    val budget = current?.review?.remainingMs ?: current?.remainingMs ?: 0
    LaunchedEffect(current?.version, receivedAt) {
        if (budget > 0) {
            delay((budget - (SystemClock.elapsedRealtime() - receivedAt)).coerceAtLeast(0))
            expired = true
        }
    }
    fun submit(action: () -> Unit) {
        if (pending || current == null || expired) return
        val elapsed = SystemClock.elapsedRealtime() - receivedAt
        if (budget > 0 && (elapsed < 0 || elapsed >= budget)) {
            expired = true
            return
        }
        pending = true
        actionFailed = runCatching(action).isFailure
    }
    fun dismissReview() {
        val review = current?.review
        if (review != null && !pending) submit { port.declinePhoneReview(review.requestId, current.version) }
        dismissedVersion = current?.version
        onDismiss()
    }
    BackHandler(enabled = current?.review != null) { dismissReview() }
    Column(modifier.fillMaxSize().safeDrawingPadding().imePadding()
        .verticalScroll(rememberScrollState()).padding(20.dp)
        .semantics { paneTitle = "Conversation content review" },
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        GatewaySectionTitle("Conversation content")
        Surface(color = MaterialTheme.colorScheme.surfaceVariant,
            shape = MaterialTheme.shapes.large,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                GatewayStatusText("Content transfer", when {
                    expired -> "Confirmation expired"
                    current == null -> "Checking availability"
                    else -> when (current.phase) {
                        ConversationPresentationPhase.UNAVAILABLE -> "Unavailable"
                        ConversationPresentationPhase.OFF -> "Off"
                        ConversationPresentationPhase.AWAITING_PHONE_REVIEW -> "Awaiting phone approval"
                        ConversationPresentationPhase.PREPARING -> "Preparing — capture is not confirmed"
                        ConversationPresentationPhase.RECOVERING -> "Verifying — capture is not confirmed"
                        ConversationPresentationPhase.CONFIRMED_ACTIVE -> "Confirmed for this interval"
                        ConversationPresentationPhase.PAUSING -> "Stopping"
                        ConversationPresentationPhase.DURABLY_CLOSED -> "Interval closed"
                        ConversationPresentationPhase.EXPIRED -> "Confirmation expired"
                        ConversationPresentationPhase.FAILURE -> if (current.close == ConversationCloseOutcome.DISABLED_CLOSURE_FAILED)
                            "Capture disabled here; closure unconfirmed" else "Unavailable"
                    }
                })
                if (current?.phase == ConversationPresentationPhase.DURABLY_CLOSED)
                    Text("New capture and transfer are stopped. Retained encrypted content is deleted separately.")
                if (current?.close == ConversationCloseOutcome.DISABLED_CLOSURE_FAILED)
                    Text("Capture is disabled in this process, but the durable stop could not be confirmed. Refresh to check its state.")
                if (current?.phase == ConversationPresentationPhase.FAILURE && current.close == null)
                    Text(when (current.failure) {
                        ConversationPresentationFailure.STORAGE_UNAVAILABLE -> "Secure storage is unavailable. Content transfer is not confirmed."
                        ConversationPresentationFailure.STALE_REVIEW -> "The review changed. Refresh before approving."
                        ConversationPresentationFailure.UNSUPPORTED -> "Content transfer is not supported here."
                        else -> "Current authority could not be verified. Content transfer is not confirmed."
                    })
                if (current?.phase in setOf(ConversationPresentationPhase.OFF, ConversationPresentationPhase.RECOVERING))
                    Text("After a restart, a new interval and fresh phone approval are required.")
                if (current?.phase == ConversationPresentationPhase.CONFIRMED_ACTIVE && !expired) {
                    Text("Phone line: ${lineLabel(current.lineId!!, current.lineGeneration!!) ?: "Label unavailable"}")
                    Text("Stop prevents new capture and transfer. It cannot recall a submitted message.")
                }
            }
        }
        val review = current?.review
        if (review != null && dismissedVersion != current.version && !expired) {
            val label = lineLabel(review.lineId, review.lineGeneration)?.takeIf { it.isNotBlank() }
            GatewaySectionTitle("Approve this conversation")
            Text("Phone line: ${label ?: "Unverified"}")
            Text("Conversation with: ${review.peer}")
            Text(review.disclosure)
            if (label == null) Text("The selected phone line could not be verified. Refresh before approving.")
            Button(onClick = { submit { port.approvePhoneReview(review.requestId, current.version) } },
                enabled = !pending && label != null, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) {
                Text("Agree and continue")
            }
            OutlinedButton(onClick = { dismissReview() }, enabled = !pending,
                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Not now") }
        }
        if (expired) Text("Refresh for a current request. This screen does not renew approval.")
        if (dismissedVersion == current?.version && current?.review != null)
            Text("Review closed. Refresh to check the current state.")
        if (pending && !actionFailed) Text("Request sent. Awaiting updated status.")
        if (actionFailed || observationFailed) Text("The request could not be completed. Refresh to check the current state.")
        if (current?.canStop == true && current.intervalId != null && !expired)
            Button(onClick = { submit {
                onStopRequested()
                port.requestStop(current.intervalId, current.version)
            } }, enabled = !pending,
                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Stop content transfer") }
        OutlinedButton(onClick = {
            if (observationFailed) { observationFailed = false; subscriptionRetry++ }
            runCatching { port.refresh() }.onFailure { actionFailed = true }
        },
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Refresh status") }
        Text("Pairing and Android SMS access do not approve content transfer. Local SMS processing can continue until receiving access is revoked.",
            style = MaterialTheme.typography.bodySmall)
    }
}
