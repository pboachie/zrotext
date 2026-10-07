// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import kotlinx.coroutines.delay
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Google owns the permissionless scanner Activity; only QR results reach our strict parser. */
internal class AndroidPairingQrGoogleScanner(private val context: Context) : AndroidPairingQrScanSource {

    override fun start(callback: (AndroidPairingQrScanResult) -> Unit) {
        if (!busy.compareAndSet(false, true)) { callback(AndroidPairingQrScanResult.Unavailable); return }
        val settled = AtomicBoolean(false)
        fun finish(result: AndroidPairingQrScanResult) {
            if (settled.compareAndSet(false, true)) { busy.set(false); callback(result) }
        }
        try {
            // Manual pairing must remain usable before the scanner SDK/module is available.
            // Client initialization belongs only to this explicit, guarded scan gesture.
            val scanner = GmsBarcodeScanning.getClient(context,
                GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())
            scanner.startScan().addOnSuccessListener { barcode ->
                val raw = barcode.rawValue
                finish(if (barcode.format == Barcode.FORMAT_QR_CODE && raw != null)
                    AndroidPairingQrScanResult.Scanned(raw) else AndroidPairingQrScanResult.Unavailable)
            }.addOnCanceledListener { finish(AndroidPairingQrScanResult.Canceled) }
                .addOnFailureListener { finish(AndroidPairingQrScanResult.Unavailable) }
        } catch (_: Exception) { finish(AndroidPairingQrScanResult.Unavailable) }
    }

    companion object {
        // Configuration changes cannot start a second platform scanner before the first task settles.
        private val busy = AtomicBoolean(false)
    }
}

/** Standalone entry for the existing pairing owner to mount. No scanned token is displayed/saved.
 * claimAndProve must be the existing pairing transport; its browser comparison/approval stays separate.
 * Module absence/cancel keeps the explicit manual path available without camera permission/provisioning.
 */
@Composable internal fun AndroidPairingQrScannerPane(
    knownOrigin: () -> String,
    claimAndProve: (String, String, String) -> VerifiedPairing,
    onVerified: (VerifiedPairing) -> Unit,
    onManual: () -> Unit,
    modifier: Modifier = Modifier,
    onUnknown: () -> Unit = {},
    source: AndroidPairingQrScanSource? = null,
    manualCredentials: (() -> AndroidPairingQrManualCredentials?)? = null,
    onState: (AndroidPairingQrScanner.Snapshot) -> Unit = {},
    onScannerReady: (AndroidPairingQrScanner?) -> Unit = {},
    renderStatus: Boolean = true
) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val currentOrigin by rememberUpdatedState(knownOrigin)
    val currentClaim by rememberUpdatedState(claimAndProve)
    val currentVerified by rememberUpdatedState(onVerified)
    val currentManual by rememberUpdatedState(onManual)
    val currentUnknown by rememberUpdatedState(onUnknown)
    val currentManualCredentials by rememberUpdatedState(manualCredentials)
    val currentState by rememberUpdatedState(onState)
    val currentReady by rememberUpdatedState(onScannerReady)
    val handler = remember { Handler(Looper.getMainLooper()) }
    val scanSource = remember(source, context) { source ?: AndroidPairingQrGoogleScanner(context) }
    val worker = remember(scanSource, lifecycle) { Executors.newSingleThreadExecutor() }
    val disposed = remember(scanSource, lifecycle) { AtomicBoolean(false) }
    var snapshot by remember { mutableStateOf<AndroidPairingQrScanner.Snapshot?>(null) }
    var confirmed by remember { mutableStateOf(false) }
    val scanner = remember(scanSource, lifecycle) {
        lateinit var coordinator: AndroidPairingQrScanner
        coordinator = AndroidPairingQrScanner(scanSource, { currentOrigin() }, SystemClock::elapsedRealtime,
            claim = { inputs, complete ->
                worker.execute {
                    val outcome = try { AndroidPairingQrClaimOutcome.Verified(inputs.use { origin, id, token -> currentClaim(origin, id, token) }) }
                        catch (_: Exception) { AndroidPairingQrClaimOutcome.Unknown }
                    finally { inputs.close() }
                    complete(outcome)
                }
            }, verified = { result, ticket, origin ->
                handler.post {
                    val current = coordinator.snapshot()
                    if (!disposed.get() && lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) &&
                        current.generation == ticket && current.phase == AndroidPairingQrScanner.Phase.VERIFIED &&
                        runCatching { AndroidPairingQrPayload.canonicalOrigin(currentOrigin()) == origin }.getOrDefault(false))
                        currentVerified(result)
                }
            }, changed = { handler.post { if (!disposed.get()) snapshot = coordinator.snapshot() } })
        coordinator
    }
    DisposableEffect(scanner, lifecycle) {
        disposed.set(false)
        snapshot = scanner.snapshot()
        currentReady(scanner)
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) scanner.pause()
        val observer = LifecycleEventObserver { _, event -> when (event) {
            Lifecycle.Event.ON_RESUME -> scanner.resume()
            Lifecycle.Event.ON_PAUSE -> { confirmed = false; scanner.pause() }
            Lifecycle.Event.ON_DESTROY -> scanner.close()
            else -> Unit
        } }
        lifecycle.addObserver(observer)
        onDispose {
            disposed.set(true); lifecycle.removeObserver(observer); confirmed = false
            currentReady(null)
            scanner.close(); worker.shutdownNow()
        }
    }
    LaunchedEffect(scanner) { while (true) { delay(1000); snapshot = scanner.snapshot() } }
    LaunchedEffect(snapshot?.generation) { confirmed = false }
    LaunchedEffect(snapshot?.phase) { if (snapshot?.phase == AndroidPairingQrScanner.Phase.UNKNOWN) currentUnknown() }
    val state = snapshot ?: scanner.snapshot()
    LaunchedEffect(state) { currentState(state) }
    Column(modifier.padding(12.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Scan a pairing QR")
        Text("Set the HTTPS server you know in the existing pairing fields first. Scanning supplies a one-use claim; it does not authenticate the owner or approve the phone.")
        Button(onClick = { confirmed = false; scanner.scan() }, enabled = state.canScan,
            modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)) { Text("Scan pairing QR") }
        if (state.phase == AndroidPairingQrScanner.Phase.REVIEW) {
            Text("Selected HTTPS server: ${state.expectedOrigin}")
            Text("Scanned HTTPS server: ${state.scannedOrigin}")
            Row {
                Checkbox(checked = confirmed, onCheckedChange = { confirmed = it }, enabled = state.canConfirm)
                Text("I recognize this server and approve sending this pairing claim.")
            }
            Button(onClick = { scanner.confirmOrigin(confirmed); confirmed = false }, enabled = state.canConfirm && confirmed,
                modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)) {
                Text("Claim this pairing ticket")
            }
        }
        if (renderStatus) Text(state.status, Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        Button(onClick = { confirmed = false; scanner.cancel() }, enabled = state.phase != AndroidPairingQrScanner.Phase.CLOSED,
            modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)) { Text("Clear scanned pairing") }
        Button(onClick = { scanner.cancel(); currentManual() }, enabled = state.canUseManual,
            modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)) { Text("Use existing manual pairing") }
        if (manualCredentials != null) Button(onClick = {
            if (scanner.snapshot().canUseManual) {
                val input = runCatching { currentManualCredentials?.invoke() }.getOrNull()
                if (input != null) scanner.claimManual(input.origin, input.pairingId, input.token, confirmed = true)
            }
        }, enabled = state.canUseManual,
            modifier = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)) { Text("Claim manually entered pairing ticket") }
        Text("The server enforces ticket expiry and one-use rules. An unknown claim must be checked in the original browser before retrying.")
    }
}
