// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.telephony.SubscriptionManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
    private val pairingWorker = Executors.newSingleThreadExecutor()
    private val permissions = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        refreshSims()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        refreshSims()
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(
                primary = Color(0xFFB6F36A),
                onPrimary = Color(0xFF0B0F0C),
                background = Color(0xFF0B0F0C),
                surface = Color(0xFF111712),
                onBackground = Color(0xFFF0F3E9),
                onSurface = Color(0xFFF0F3E9)
            )) {
                Column(
                    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text("ZROtext", style = MaterialTheme.typography.headlineLarge)
                    Text("Gateway mode spike", style = MaterialTheme.typography.titleMedium)
                    Text("The M0 gateway button tests SIM visibility and a token socket heartbeat. That button does not send or receive SMS.")
                    Text("Status: ${GatewayStatus.value}; heartbeat acknowledgments this process: ${GatewayStatus.heartbeats}")
                    Button(onClick = { askPermissions() }) { Text("Grant gateway permissions") }
                    Text("Selected SIM: ${selectedSim?.toString() ?: "none"}")
                    sims.forEach { (id, label) ->
                        Button(onClick = {
                            selectedSim = id
                            getSharedPreferences("gateway_selection", MODE_PRIVATE).edit()
                                .putInt("subscription_id", id).apply()
                        }) { Text(label) }
                    }
                    OutlinedTextField(value = endpoint, onValueChange = { endpoint = it }, label = { Text("WSS test endpoint") })
                    OutlinedTextField(
                        value = testToken,
                        onValueChange = { testToken = it },
                        label = { Text("Short-lived test token") },
                        visualTransformation = PasswordVisualTransformation()
                    )
                    Button(onClick = {
                        if (selectedSim == null) {
                            GatewayStatus.value = "Select a SIM first"
                        } else {
                            stopService(Intent(this@MainActivity, AuthenticatedGatewayService::class.java))
                            val intent = Intent(this@MainActivity, GatewayService::class.java)
                                .putExtra(GatewayService.EXTRA_URL, endpoint)
                                .putExtra(GatewayService.EXTRA_TOKEN, testToken)
                            ContextCompat.startForegroundService(this@MainActivity, intent)
                            testToken = ""
                        }
                    }) { Text("Start visible gateway session") }
                    Button(onClick = {
                        startService(Intent(this@MainActivity, GatewayService::class.java).setAction(GatewayService.ACTION_PAUSE))
                    }) { Text("Pause gateway") }
                    Text("Keep this dedicated phone plugged in for the screen-off test. Reopen the app after a stop or reboot; automatic recovery is not implemented in M0.")
                    HorizontalDivider()
                    Text("Authenticated device heartbeat", style = MaterialTheme.typography.titleMedium)
                    Text("After owner approval, enter the approved device UUID and trusted WSS origin. The heartbeat button only proves the phone's Keystore key and exchanges heartbeats.")
                    Text("Status: ${AuthenticatedGatewayStatus.value}; acknowledgments this session: ${AuthenticatedGatewayStatus.heartbeats}")
                    OutlinedTextField(value = deviceStreamEndpoint, onValueChange = { deviceStreamEndpoint = it },
                        label = { Text("WSS device stream URL") })
                    OutlinedTextField(value = approvedDeviceId, onValueChange = { approvedDeviceId = it },
                        label = { Text("Approved device UUID") })
                    Button(onClick = {
                        if (selectedSim == null) {
                            AuthenticatedGatewayStatus.value = "Select a SIM first"
                        } else {
                            stopService(Intent(this@MainActivity, GatewayService::class.java))
                            val intent = Intent(this@MainActivity, AuthenticatedGatewayService::class.java)
                                .putExtra(AuthenticatedGatewayService.EXTRA_URL, deviceStreamEndpoint)
                                .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, approvedDeviceId.trim())
                            ContextCompat.startForegroundService(this@MainActivity, intent)
                        }
                    }) { Text("Start authenticated heartbeat") }
                    Button(onClick = {
                        startService(Intent(this@MainActivity, AuthenticatedGatewayService::class.java)
                            .setAction(AuthenticatedGatewayService.ACTION_PAUSE))
                    }) { Text("Pause authenticated heartbeat") }
                    HorizontalDivider()
                    Text("One controlled synthetic SMS", style = MaterialTheme.typography.titleMedium)
                    Text("Enter a recipient you control in +E.164 form. This private pilot can consume one grant per app installation. A valid writer ack can make one SMS call from the selected SIM; silence or an uncertain result is never retried.")
                    OutlinedTextField(value = alphaRecipient, onValueChange = { alphaRecipient = it.trim() },
                        label = { Text("Controlled recipient +E.164") })
                    Button(onClick = {
                        val sim = selectedSim
                        if (sim == null || !alphaRecipient.matches(Regex("^\\+[1-9][0-9]{1,14}$"))) {
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
                    }) { Text("Arm one synthetic SMS") }
                    HorizontalDivider()
                    Text("Device pairing", style = MaterialTheme.typography.titleMedium)
                    Text("Enter the one-use pairing ID and token from the owner account. The phone will prove possession of its Keystore key. Compare both values below with the browser before approving there.")
                    OutlinedTextField(value = pairingOrigin, onValueChange = { pairingOrigin = it },
                        label = { Text("HTTPS server origin") })
                    OutlinedTextField(value = pairingId, onValueChange = { pairingId = it },
                        label = { Text("Pairing ID") })
                    OutlinedTextField(value = pairingToken, onValueChange = { pairingToken = it },
                        label = { Text("One-use pairing token") }, visualTransformation = PasswordVisualTransformation())
                    Button(onClick = { beginPairing() }) { Text("Claim pairing and prove key") }
                    Text("Pairing status: $pairingStatus")
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
