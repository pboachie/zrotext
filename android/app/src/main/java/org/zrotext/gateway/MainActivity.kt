// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.telephony.SubscriptionManager
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import java.util.concurrent.Executors

object GatewayStatus {
    var value by mutableStateOf("Paused")
    var heartbeats by mutableIntStateOf(0)
}

class MainActivity : ComponentActivity() {
    private var sims by mutableStateOf<List<Pair<Int, String>>>(emptyList())
    private var selectedSim by mutableStateOf<Int?>(null)
    private var endpoint by mutableStateOf("")
    private var testToken by mutableStateOf("")
    private var deviceStreamEndpoint by mutableStateOf("")
    private var approvedDeviceId by mutableStateOf("")
    private var alphaRecipient by mutableStateOf("")
    private var pairingOrigin by mutableStateOf("")
    private var pairingId by mutableStateOf("")
    private var pairingToken by mutableStateOf("")
    private var pairingStatus by mutableStateOf("Not paired")
    private var comparisonCode by mutableStateOf("")
    private var signingFingerprint by mutableStateOf("")
    private var signingSecurity by mutableStateOf("")
    private var defaultSmsAppRcsRisk by mutableStateOf(DefaultSmsAppRcsRisk.Risk.UNAVAILABLE)
    private val pairingWorker = Executors.newSingleThreadExecutor()
    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        refreshSims()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(GatewayColors.background.toArgb()),
            navigationBarStyle = SystemBarStyle.dark(GatewayColors.background.toArgb())
        )
        // Older Android versions do not replay BOOT_COMPLETED after force-stop.
        // A manual app launch with no heartbeat service means the old reboot
        // choice cannot be treated as consent for a future boot.
        if (!AuthenticatedGatewayService.processActive &&
            HeartbeatResumeStore.read(this) != null &&
            !HeartbeatResumeStore.clear(this)) {
            AuthenticatedGatewayStatus.value = "Could not disable previous reboot resume; retry Pause"
        }
        refreshSims()
        defaultSmsAppRcsRisk = DefaultSmsAppRcsRisk.observe(this)
        setContent {
            GatewayTheme {
                Column(
                    modifier = Modifier.fillMaxSize().safeDrawingPadding().imePadding().clipToBounds()
                        .verticalScroll(rememberScrollState()).padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text("ZROtext", style = MaterialTheme.typography.headlineLarge,
                        modifier = Modifier.semantics { heading() })
                    GatewaySectionTitle("Gateway connection test")
                    Text("Check SIM visibility and a test socket connection. This connection test does not send or receive SMS.")
                    GatewayStatusText("Connection status", GatewayStatus.value)
                    Text("Heartbeat acknowledgments this process: ${GatewayStatus.heartbeats}")
                    GatewayButton(onClick = { askPermissions() }) { Text("Grant gateway permissions") }
                    Text("Selected SIM: ${selectedSim?.toString() ?: "none"}")
                    sims.forEach { (id, label) ->
                        GatewayButton(onClick = {
                            selectedSim = id
                            getSharedPreferences("gateway_selection", MODE_PRIVATE).edit()
                                .putInt("subscription_id", id).apply()
                        }, modifier = Modifier.semantics {
                            selected = selectedSim == id
                            stateDescription = if (selectedSim == id) "Selected SIM" else "Not selected"
                        }) { Text(label) }
                    }
                    OutlinedTextField(value = endpoint, onValueChange = { endpoint = it }, label = { Text("WSS test endpoint") })
                    OutlinedTextField(
                        value = testToken,
                        onValueChange = { testToken = it },
                        label = { Text("Short-lived test token") },
                        visualTransformation = PasswordVisualTransformation()
                    )
                    GatewayButton(onClick = {
                        if (selectedSim == null) {
                            GatewayStatus.value = "Select a SIM first"
                        } else if (!GatewayInputValidation.testEndpoint(endpoint) || testToken.isBlank()) {
                            GatewayStatus.value = "Set a WSS endpoint and test token"
                        } else if (!GatewaySessionSelection.startVisibleTestSession(
                                this@MainActivity, endpoint, testToken)) {
                            GatewayStatus.value = "Could not disable heartbeat reboot resume; try again"
                        } else {
                            testToken = ""
                        }
                    }) { Text("Start visible gateway session") }
                    GatewayButton(onClick = {
                        startService(Intent(this@MainActivity, GatewayService::class.java).setAction(GatewayService.ACTION_PAUSE))
                    }) { Text("Pause gateway") }
                    Text("Keep this dedicated phone plugged in for a screen-off connection test. The test-token session requires a manual restart after a stop or reboot.")
                    HorizontalDivider()
                    GatewaySectionTitle("Authenticated device heartbeat")
                    Text("After owner approval, enter the approved device UUID and trusted WSS origin. The heartbeat button only proves the phone's Keystore key and exchanges heartbeats.")
                    GatewayStatusText("Authenticated connection status", AuthenticatedGatewayStatus.value)
                    Text("Heartbeat acknowledgments this session: ${AuthenticatedGatewayStatus.heartbeats}")
                    OutlinedTextField(value = deviceStreamEndpoint, onValueChange = { deviceStreamEndpoint = it },
                        label = { Text("WSS device stream URL") })
                    OutlinedTextField(value = approvedDeviceId, onValueChange = { approvedDeviceId = it },
                        label = { Text("Approved device UUID") })
                    GatewayButton(onClick = { startHeartbeat(rebootResume = false) }) {
                        Text("Start authenticated heartbeat")
                    }
                    GatewayButton(onClick = { startHeartbeat(rebootResume = true) }) {
                        Text("Start heartbeat and resume after reboot")
                    }
                    Text("Reboot resume is heartbeat-only and must be chosen explicitly. Pause clears it. A force-stop requires reopening the app and starting a session again.")
                    GatewayButton(onClick = {
                        startService(Intent(this@MainActivity, AuthenticatedGatewayService::class.java)
                            .setAction(AuthenticatedGatewayService.ACTION_PAUSE))
                    }) { Text("Pause authenticated heartbeat") }
                    Text("Inbound pilot: capture carrier SMS replies and upload signed metadata. RCS replies do not reach this SMS receiver. Before using a dedicated gateway line, verify that a sender with unchanged messaging settings can send an SMS reply and this app acknowledges it. The sender number and SMS body stay on this phone.")
                    Text(when (defaultSmsAppRcsRisk) {
                        DefaultSmsAppRcsRisk.Risk.RCS_CAPABLE_APP ->
                            "Default messaging app: RCS-capable app detected. This app cannot see whether RCS chats are enabled on this phone; if they are, RCS replies stay in that app and bypass the gateway. Keep RCS chats off and verify with a controlled sender."
                        DefaultSmsAppRcsRisk.Risk.UNKNOWN_APP ->
                            "Default messaging app: not recognized. This app cannot see whether it registers RCS chats, so RCS replies may still bypass the gateway. Verify with a controlled sender."
                        DefaultSmsAppRcsRisk.Risk.UNAVAILABLE ->
                            "Default messaging app: not observable. This app cannot see whether RCS chats could register on this phone. Verify with a controlled sender."
                    })
                    GatewayButton(onClick = {
                        if (!validAuthenticatedFields()) return@GatewayButton
                        stopService(Intent(this@MainActivity, GatewayService::class.java))
                        val intent = Intent(this@MainActivity, AuthenticatedGatewayService::class.java)
                            .putExtra(AuthenticatedGatewayService.EXTRA_URL, deviceStreamEndpoint)
                            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, approvedDeviceId.trim())
                            .putExtra(AuthenticatedGatewayService.EXTRA_INBOUND_UPLOAD, true)
                        ContextCompat.startForegroundService(this@MainActivity, intent)
                    }) { Text("Start inbound metadata pilot") }
                    HorizontalDivider()
                    GatewaySectionTitle("Controlled SMS test")
                    Text("Enter a recipient you control in +E.164 form. This test allows one send per app installation. A confirmed grant can send one SMS from the selected SIM; an uncertain result is never retried automatically.")
                    OutlinedTextField(value = alphaRecipient, onValueChange = { alphaRecipient = it.trim() },
                        label = { Text("Controlled recipient +E.164") })
                    GatewayButton(onClick = {
                        val sim = selectedSim
                        if (!validAuthenticatedFields()) return@GatewayButton
                        if (getSharedPreferences("alpha_pilot", MODE_PRIVATE)
                                .getBoolean("attempt_used", false)) {
                            AuthenticatedGatewayStatus.value = "Alpha arm refused: one test attempt already used"
                        } else if (sim == null || sims.none { it.first == sim } ||
                            !alphaRecipient.matches(Regex("^\\+[1-9][0-9]{1,14}$"))) {
                            AuthenticatedGatewayStatus.value = "Select an active SIM and enter a valid recipient"
                        } else {
                            stopService(Intent(this@MainActivity, GatewayService::class.java))
                            val intent = Intent(this@MainActivity, AuthenticatedGatewayService::class.java)
                                .putExtra(AuthenticatedGatewayService.EXTRA_URL, deviceStreamEndpoint)
                                .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, approvedDeviceId.trim())
                                .putExtra(AuthenticatedGatewayService.EXTRA_ALPHA_RECIPIENT, alphaRecipient)
                                .putExtra(AuthenticatedGatewayService.EXTRA_ALPHA_SUBSCRIPTION_ID, sim)
                            ContextCompat.startForegroundService(this@MainActivity, intent)
                            alphaRecipient = ""
                        }
                    }) { Text("Arm one test SMS") }
                    HorizontalDivider()
                    MmsSpikeSection(selectedSim, sims.map { it.first })
                    GatewaySectionTitle("Device pairing")
                    Text("Enter the one-use pairing ID and token from the owner account. The phone will prove possession of its Keystore key. Compare both values below with the browser before approving there.")
                    OutlinedTextField(value = pairingOrigin, onValueChange = { pairingOrigin = it },
                        label = { Text("HTTPS server origin") })
                    OutlinedTextField(value = pairingId, onValueChange = { pairingId = it },
                        label = { Text("Pairing ID") })
                    OutlinedTextField(value = pairingToken, onValueChange = { pairingToken = it },
                        label = { Text("One-use pairing token") }, visualTransformation = PasswordVisualTransformation())
                    GatewayButton(onClick = { beginPairing() }) { Text("Claim pairing and prove key") }
                    GatewayStatusText("Pairing status", pairingStatus)
                    if (comparisonCode.isNotEmpty()) {
                        Text("Comparison code: $comparisonCode")
                        Text("Key fingerprint: $signingFingerprint")
                        Text("Key protection: $signingSecurity")
                        Text("Approve only when the browser shows the same code and fingerprint. This screen does not authorize SMS or establish a device session.")
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        pairingWorker.shutdownNow()
        super.onDestroy()
    }

    private fun beginPairing() {
        val origin = pairingOrigin
        val id = pairingId
        val token = pairingToken
        pairingToken = ""
        pairingStatus = "Claiming and proving key"
        comparisonCode = ""
        signingFingerprint = ""
        signingSecurity = ""
        pairingWorker.execute {
            try {
                val result = PairingClient(DeviceSigningKeyStore(applicationContext))
                    .claimAndProve(origin, id, token)
                runOnUiThread {
                    if (isDestroyed) return@runOnUiThread
                    comparisonCode = result.comparisonCode
                    signingFingerprint = result.fingerprintHex
                    signingSecurity = result.keySecurity.name +
                        if (result.strongBoxFallbackOnCreation == true) " (StrongBox unavailable; fallback used)" else ""
                    pairingStatus = "Key proof accepted; waiting for owner approval"
                }
            } catch (_: Exception) {
                runOnUiThread {
                    if (!isDestroyed) pairingStatus = "Pairing did not finish. Start a new one-use pairing if the token was claimed."
                }
            }
        }
    }

    private fun startHeartbeat(rebootResume: Boolean) {
        if (selectedSim == null) {
            AuthenticatedGatewayStatus.value = "Select a SIM first"
            return
        }
        if (!validAuthenticatedFields()) return
        stopService(Intent(this, GatewayService::class.java))
        val intent = Intent(this, AuthenticatedGatewayService::class.java)
            .putExtra(AuthenticatedGatewayService.EXTRA_URL, deviceStreamEndpoint)
            .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, approvedDeviceId.trim())
            .putExtra(AuthenticatedGatewayService.EXTRA_REBOOT_RESUME, rebootResume)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun validAuthenticatedFields(): Boolean {
        if (HeartbeatResumeStore.validUrl(deviceStreamEndpoint) &&
            GatewayInputValidation.deviceId(approvedDeviceId.trim()) != null) return true
        AuthenticatedGatewayStatus.value = "Set a WSS device stream and approved device ID"
        return false
    }

    private fun askPermissions() {
        val requested = mutableListOf(Manifest.permission.READ_PHONE_STATE, Manifest.permission.SEND_SMS, Manifest.permission.RECEIVE_SMS)
        if (Build.VERSION.SDK_INT >= 33) requested += Manifest.permission.POST_NOTIFICATIONS
        permissions.launch(requested.toTypedArray())
    }

    private fun refreshSims() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) {
            sims = emptyList()
            selectedSim = null
            return
        }
        val manager = getSystemService(SubscriptionManager::class.java)
        sims = (manager.activeSubscriptionInfoList ?: emptyList()).map { info ->
            info.subscriptionId to "SIM ${info.simSlotIndex + 1}: ${info.displayName}"
        }
        val saved = getSharedPreferences("gateway_selection", MODE_PRIVATE)
            .getInt("subscription_id", SubscriptionManager.INVALID_SUBSCRIPTION_ID)
        selectedSim = saved.takeIf { id -> sims.any { it.first == id } }
    }
}
