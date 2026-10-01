// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.ui.window.DialogProperties
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import android.telephony.SubscriptionManager
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.unit.dp
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.input.PasswordVisualTransformation
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
    private var permissionDisclosure by mutableStateOf<GatewayPermissionPurpose?>(null)
    private val pairingWorker = Executors.newSingleThreadExecutor()
    // Release activation remains disabled. No intent, saved state or preference enables it.
    internal var conversationSetupEnabled = false
    internal var conversationHandleFactory: ((Uri, (ConversationPresentationPort) -> Unit) -> ConversationSetupEntrySession.Handle)? = null
    private val conversationWorker = Executors.newSingleThreadExecutor()
    private var conversationEntryOpen by mutableStateOf(false)
    private var conversationSetupFile by mutableStateOf<Uri?>(null)
    private var conversationReplyFile by mutableStateOf<Uri?>(null)
    private var conversationPort by mutableStateOf<ConversationPresentationPort?>(null)
    private var conversationEntryState by mutableStateOf(ConversationSetupEntrySession.State.CLOSED)
    private var conversationEntryStatus by mutableStateOf("")
    private var conversationEntry: ConversationSetupEntrySession? = null
    private var conversationController: ConversationUserSetupController? = null
    private var conversationUiEpoch = 0L
    private var conversationPickEpoch: Long? = null
    private var conversationReplyPending by mutableStateOf(false)
    private val conversationSetupPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val accepted = conversationEntryOpen && conversationPickEpoch == conversationUiEpoch
        conversationPickEpoch = null
        if (accepted) acceptConversationSetupFile(uri)
    }
    private val conversationReplyPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val accepted = conversationEntryOpen && conversationPickEpoch == conversationUiEpoch
        conversationPickEpoch = null
        if (accepted && uri != null) {
            conversationReplyFile = uri
            conversationEntryStatus = "Public reply authority selected. Reopen and approve the conversation before verifying it."
        }
    }
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
                if (conversationEntryOpen) ConversationEntryContent()
                permissionDisclosure?.let { purpose ->
                    Dialog(onDismissRequest = { permissionDisclosure = null }) {
                        Surface(shape = MaterialTheme.shapes.large) {
                            Column(Modifier.fillMaxWidth()
                                .heightIn(max = with(LocalDensity.current) {
                                    LocalWindowInfo.current.containerSize.height.toDp() * 0.85f
                                })
                                .verticalScroll(rememberScrollState()).padding(24.dp),
                                verticalArrangement = Arrangement.spacedBy(16.dp)) {
                                GatewaySectionTitle(purpose.title)
                                Text(purpose.disclosure)
                                GatewayButton(onClick = {
                                    permissionDisclosure = null
                                    askPermissions(purpose)
                                }, modifier = Modifier.fillMaxWidth()) { Text("Agree and continue") }
                                GatewayButton(onClick = { permissionDisclosure = null },
                                    modifier = Modifier.fillMaxWidth()) { Text("Not now") }
                            }
                        }
                    }
                }

                GatewayCompanion(initialPage = GatewayPage.entries.firstOrNull {
                    it.name == intent.getStringExtra("gateway_screen")
                } ?: GatewayPage.HOME) { page, navigate ->
                    if (page == GatewayPage.HOME) {
                        GatewayHome(
                            AuthenticatedGatewayStatus.value, GatewayStatus.value,
                            AuthenticatedGatewayStatus.heartbeats,
                            sims.firstOrNull { it.first == selectedSim }?.second ?: "Not selected",
                            pairingStatus,
                            power = rememberGatewayPower(),
                            onSetup = { navigate(GatewayPage.SETUP) },
                            onConnection = { navigate(GatewayPage.CONNECTION) },
                            onPause = {
                                startService(Intent(this@MainActivity, GatewayService::class.java)
                                    .setAction(GatewayService.ACTION_PAUSE))
                                startService(Intent(this@MainActivity, AuthenticatedGatewayService::class.java)
                                    .setAction(AuthenticatedGatewayService.ACTION_PAUSE))
                            }
                        )
                    }
                    if (page == GatewayPage.SETUP) {
                        GatewaySetupGuide(
                            selectedSim = sims.firstOrNull { it.first == selectedSim }?.second ?: "Not selected",
                            pairingStatus = pairingStatus,
                            onConnection = { navigate(GatewayPage.CONNECTION) },
                            initialStep = GatewaySetupStep.entries.firstOrNull {
                                it.name == intent.getStringExtra("gateway_setup_step")
                            } ?: GatewaySetupStep.OVERVIEW,
                            accessContent = {
                                GatewayButton(onClick = { permissionDisclosure = GatewayPermissionPurpose.SIM }) { Text("Choose SIM permissions") }
                                GatewayButton(onClick = { permissionDisclosure = GatewayPermissionPurpose.SEND }) { Text("Review SMS sending access") }
                                GatewayButton(onClick = { permissionDisclosure = GatewayPermissionPurpose.RECEIVE }) { Text("Review SMS receiving access") }
                                Text("SMS access is optional for pairing and connection tests. Pause stops the connection, but receiving access can still process incoming SMS locally. Revoke SMS access in Android app settings to stop that processing.")
                                GatewayButton(onClick = {
                                    startActivity(Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                        android.net.Uri.parse("package:$packageName")))
                                }) { Text("Manage or revoke permissions") }
                                GatewayPrivacyLinks()
                            },
                            simContent = {
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
                            },
                            pairingContent = {
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
                        )
                    }
                    if (page == GatewayPage.CONNECTION) {
                        GatewaySectionTitle("Conversation content")
                        Text("Review a selected conversation from your paired browser. Opening this screen does not approve SMS content transfer.")
                        GatewayButton(onClick = {
                            conversationUiEpoch++
                            conversationEntryOpen = true
                            conversationEntryStatus = ""
                        }) { Text("Open conversation review") }
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
                    }
                    if (page == GatewayPage.TOOLS) {
                        GatewaySectionTitle("Advanced pilots")
                        GatewayStatusText("Pilot status", AuthenticatedGatewayStatus.value)
                        Text("Connection credentials are configured on the Connection screen. These controls are for explicit, controlled tests.")
                        GatewaySectionTitle("Gateway connection test")
                        Text("Check SIM visibility and a test socket connection. This connection test does not send or receive SMS.")
                        GatewayStatusText("Connection status", GatewayStatus.value)
                        Text("Heartbeat acknowledgments this process: ${GatewayStatus.heartbeats}")
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
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshSims()
        defaultSmsAppRcsRisk = DefaultSmsAppRcsRisk.observe(this)
    }

    override fun onDestroy() {
        closeConversationEntry()
        conversationWorker.shutdownNow()
        pairingWorker.shutdownNow()
        super.onDestroy()
    }

    override fun onStop() {
        // A file picker may return a public candidate, but never preserves phone authority.
        conversationEntry?.close()
        conversationEntry = null
        conversationController = null
        conversationPort = null
        conversationSelectedLine = null
        conversationVerifiedLineLabel = null
        conversationReplyPending = false
        if (conversationPickEpoch == null) closeConversationEntry()
        super.onStop()
    }

    internal fun acceptConversationSetupFile(uri: Uri?) {
        if (!conversationEntryOpen) return
        conversationSetupFile = uri
        conversationEntryStatus = if (uri == null) "File selection cancelled." else "Public setup selected. Phone approval is still required."
    }

    private fun closeConversationEntry() {
        // Capture CLOSE_FAILED while this exact view generation is still observable.
        conversationEntry?.close()
        ++conversationUiEpoch
        conversationEntryOpen = false
        conversationPickEpoch = null
        conversationEntry = null
        conversationController = null
        conversationPort = null
        conversationSetupFile = null
        conversationReplyFile = null
        conversationSelectedLine = null
        conversationVerifiedLineLabel = null
        conversationReplyPending = false
    }

    @Composable private fun ConversationEntryContent() {
        Dialog(onDismissRequest = { closeConversationEntry() }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(Modifier.fillMaxSize()) {
                Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding().padding(16.dp),
                    verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(12.dp)) {
                    GatewaySectionTitle("Conversation review")
                    OutlinedButton(onClick = { closeConversationEntry() }, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) {
                        Text("Close conversation review")
                    }
                    val port = conversationPort
                    if (port != null) {
                        FutureConversationPane(port, { line, generation ->
                            conversationVerifiedLineLabel?.takeIf { conversationSelectedLine == (line to generation) }
                        }, Modifier.weight(1f), onDismiss = { closeConversationEntry() })
                    } else {
                        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()),
                            verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(12.dp)) {
                            Text("Select the public phone setup file from the paired browser. The existing paired device, selected line and enrolled hardware key must match. No key is created here.")
                            if (!conversationSetupEnabled) Text("Conversation setup is not enabled in this build.")
                            Button(onClick = {
                                conversationPickEpoch = conversationUiEpoch
                                conversationSetupPicker.launch(arrayOf("application/octet-stream"))
                            }, enabled = conversationSetupEnabled && conversationEntryState != ConversationSetupEntrySession.State.OPENING &&
                                conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED,
                                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Select conversation setup file") }
                            Button(onClick = { beginConversationEntry() }, enabled = conversationSetupEnabled && conversationSetupFile != null &&
                                conversationEntryState != ConversationSetupEntrySession.State.OPENING && conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED,
                                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Review selected conversation") }
                            if (conversationEntryState == ConversationSetupEntrySession.State.OPENING) Text("Checking the selected conversation. Content transfer is not confirmed.")
                            if (conversationEntryState == ConversationSetupEntrySession.State.CLOSE_FAILED) Text("Review closure could not be completed. Content transfer is not confirmed.")
                        }
                    }
                    if (port != null) OutlinedButton(onClick = {
                        conversationPickEpoch = conversationUiEpoch
                        conversationReplyPicker.launch(arrayOf("application/octet-stream"))
                    }, enabled = conversationSetupEnabled && !conversationReplyPending,
                        modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Select reply authority file") }
                    if (port != null && conversationReplyFile != null) OutlinedButton(onClick = {
                        conversationReplyFile?.let { installConversationReplyFile(it) }
                    }, enabled = conversationSetupEnabled && !conversationReplyPending,
                        modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Verify selected reply authority") }
                    if (conversationEntryStatus.isNotEmpty()) Text(conversationEntryStatus, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }

    private var conversationSelectedLine: Pair<String, Long>? = null
    private var conversationVerifiedLineLabel: String? = null

    private fun beginConversationEntry() {
        if (!conversationSetupEnabled || conversationEntryState == ConversationSetupEntrySession.State.CLOSE_FAILED) return
        val uri = conversationSetupFile ?: return
        conversationEntry?.close()
        val epoch = conversationUiEpoch
        val session = ConversationSetupEntrySession({ ready ->
            conversationHandleFactory?.invoke(uri, ready) ?: createConversationHandle(uri, epoch, ready)
        }, { state, port ->
            if (conversationEntryOpen && conversationUiEpoch == epoch) {
                conversationEntryState = state
                conversationPort = port
            }
        })
        conversationEntry = session
        session.open()
    }

    private fun createConversationHandle(uri: Uri, epoch: Long, ready: (ConversationPresentationPort) -> Unit): ConversationSetupEntrySession.Handle {
        val cancelled = AtomicBoolean(false)
        val owned = AtomicReference<ConversationUserSetupController?>(null)
        val selectedSubscription = selectedSim
        val labels = sims.toMap()
        fun report(text: String) = runOnUiThread {
            if (!cancelled.get() && conversationEntryOpen && conversationUiEpoch == epoch) conversationEntryStatus = text
        }
        return object : ConversationSetupEntrySession.Handle {
            override fun begin(): Boolean {
                if (!conversationSetupEnabled) return false
                conversationWorker.execute {
                    try {
                        val bytes = contentResolver.openInputStream(uri)?.use { readConversationSetupFile(it, 1128) }
                            ?: error("Public file unavailable")
                        if (cancelled.get()) return@execute
                        val database = SmsJournalDatabase.get(applicationContext)
                        val prepared = ConversationUserSetupProvider(applicationContext, database.attempts()).resolve(bytes, enabled = true)
                            ?: error("Setup unavailable")
                        val binding = checkNotNull(database.attempts().currentLineBinding())
                        check(binding.accountId == prepared.selection.identity.accountId && binding.deviceId == prepared.selection.identity.deviceId &&
                            binding.lineId == prepared.selection.lineId && binding.generation == prepared.selection.bindingGeneration)
                        val verifiedLabel = conversationEntryLineLabel(binding, prepared.selection, selectedSubscription, labels)
                        if (cancelled.get()) return@execute
                        val controller = ConversationUserSetupController(applicationContext, database.attempts(), prepared.payloadAlias,
                            conversationWorker, java.util.concurrent.Executor { action -> runOnUiThread(action) },
                            ConversationExecutionComposition(applicationContext, database, enabled = false), { port ->
                                if (!cancelled.get() && conversationEntryOpen && conversationUiEpoch == epoch) {
                                    conversationSelectedLine = prepared.selection.lineId to prepared.selection.bindingGeneration
                                    conversationVerifiedLineLabel = verifiedLabel
                                    ready(port)
                                }
                            })
                        owned.set(controller)
                        if (cancelled.get()) { owned.getAndSet(null)?.close(); return@execute }
                        if (!controller.begin(prepared.selection, enabled = true)) error("Setup refused")
                        runOnUiThread {
                            if (!cancelled.get() && conversationEntryOpen && conversationUiEpoch == epoch) conversationController = controller
                        }
                    } catch (error: Exception) {
                        runCatching { owned.getAndSet(null)?.close() }
                        report(if (error is ConversationUserSetupProvider.ExistingHardwareEnrollmentRequired)
                            "An existing enrolled hardware reader is required. Complete enrollment before reviewing."
                            else "The selected conversation could not be verified. Check pairing, the selected line and the setup file.")
                        runOnUiThread {
                            if (!cancelled.get() && conversationEntryOpen && conversationUiEpoch == epoch) {
                                conversationEntry?.close(); conversationEntry = null
                            }
                        }
                    }
                }
                return true
            }
            override fun close() { cancelled.set(true); owned.getAndSet(null)?.close() }
        }
    }

    private fun installConversationReplyFile(uri: Uri) {
        // The picker backgrounds this activity, which closes authority. Fresh review is mandatory.
        val controller = conversationController ?: run {
            conversationEntryStatus = "The review closed while selecting a file. Reopen the selected conversation and approve it again."
            return
        }
        val epoch = conversationUiEpoch
        conversationReplyPending = true
        conversationWorker.execute {
            try {
                val bytes = contentResolver.openInputStream(uri)?.use { readConversationSetupFile(it, 16423) } ?: error("File unavailable")
                val candidate = ConversationUserSetupProvider.decodeReplyAuthority(bytes)
                controller.installReplyAuthority(candidate.signedSuccessor(), candidate.signerId()) { accepted ->
                    if (conversationEntryOpen && conversationUiEpoch == epoch && conversationController === controller) {
                        conversationReplyPending = false
                        conversationEntryStatus = if (accepted) "Reply authority verified for the current interval. No message was sent."
                            else "Reply authority was not accepted. Current phone approval and matching authority are required."
                    }
                }
            } catch (_: Exception) {
                runOnUiThread {
                    if (conversationEntryOpen && conversationUiEpoch == epoch && conversationController === controller) {
                        conversationReplyPending = false
                        conversationEntryStatus = "The reply authority file could not be verified."
                    }
                }
            }
        }
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

    private fun askPermissions(purpose: GatewayPermissionPurpose) {
        val requested = purpose.permissions(Build.VERSION.SDK_INT).filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (requested.isNotEmpty()) permissions.launch(requested.toTypedArray())
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
