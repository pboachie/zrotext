// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.net.Uri
import android.os.SystemClock
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.runtime.Composable
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.lifecycle.Lifecycle
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
    // Separate read authority. Nothing here is persisted, saved in a Bundle,
    // inferred from pairing, or shared with a heartbeat/radio service.
    private var summaryOrigin by mutableStateOf("")
    private var summaryDeviceId by mutableStateOf("")
    private var summaryCredential by mutableStateOf("")
    private var summaryView by mutableStateOf(GatewaySummaryState.View(GatewaySummaryState.Phase.UNAVAILABLE, null))
    private var summaryStatus by mutableStateOf("Message counts are unavailable on this phone. An authorized summary reader is not connected.")
    private val summaryState = GatewaySummaryState()
    private val summaryClient = GatewaySummaryClient()
    private val summaryWorker = Executors.newSingleThreadExecutor()
    private val summaryHandler = Handler(Looper.getMainLooper())
    private var summaryRead: GatewaySummaryClient.Read? = null
    private var summarySelectedDevice: java.util.UUID? = null
    private var summaryHome = false
    private var summaryResumed = false
    private var summaryRequested = false
    private val summaryAge = Runnable { updateSummaryView() }
    private val pairingWorker = Executors.newSingleThreadExecutor()
    // Foreground-only user opt-in. No intent, saved state or preference enables it.
    internal var conversationSetupEnabled by mutableStateOf(false)
        private set
    internal var conversationHandleFactory: ((Uri, (ConversationPresentationPort) -> Unit) -> ConversationSetupEntrySession.Handle)? = null
    internal var conversationReplyInstaller: ((ByteArray, ByteArray, (Boolean) -> Unit) -> Unit)? = null
    private val conversationWorker = Executors.newSingleThreadExecutor()
    private var conversationEntryOpen by mutableStateOf(false)
    private var conversationSetupFile by mutableStateOf<Uri?>(null)
    private var conversationReplyText by mutableStateOf("")
    private var conversationReplyEditorOpen by mutableStateOf(false)
    private var conversationReplyObservation by mutableStateOf<ConversationPresentationSnapshot?>(null)
    private var conversationReplyReceivedAt by mutableStateOf(0L)
    private var conversationReplyExpired by mutableStateOf(false)
    private var conversationReplyToken: AtomicBoolean? = null
    private var conversationPort by mutableStateOf<ConversationPresentationPort?>(null)
    private var conversationEntryState by mutableStateOf(ConversationSetupEntrySession.State.CLOSED)
    private var conversationEntryStatus by mutableStateOf("")
    private var conversationEntry: ConversationSetupEntrySession? = null
    private var conversationController: ConversationUserSetupController? = null
    private var conversationUiEpoch = 0L
    private var conversationPickEpoch: Long? = null
    private var conversationReplyPending by mutableStateOf(false)
    internal var conversationRepliesEnabled by mutableStateOf(false)
        private set
    private var conversationReplyChoiceGeneration by mutableStateOf(0L)
    private var conversationEnrollmentOpen by mutableStateOf(false)
    private var conversationEnrollmentBusy by mutableStateOf(false)
    private var conversationEnrollmentStatus by mutableStateOf("")
    private var conversationReaderExport by mutableStateOf("")
    private var conversationPhoneExport: ConversationPhonePublicExport? = null
    private var pendingConversationPhoneExport: ConversationPhonePublicExport? = null
    private var pendingConversationExportUri: Uri? = null
    private var conversationExportWriteToken: AtomicBoolean? = null
    private val conversationExportPicker = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        acceptConversationPublicExportDestination(uri)
    }
    internal fun acceptConversationPublicExportDestination(uri: Uri?) {
        if (pendingConversationPhoneExport == null) return
        if (uri == null) {
            pendingConversationPhoneExport = null
            pendingConversationExportUri = null
        } else {
            pendingConversationExportUri = uri
            finishConversationPublicExport()
        }
    }
    private var conversationRootPin by mutableStateOf("")
    private var conversationRootFingerprint by mutableStateOf("")
    private var conversationRootCompared by mutableStateOf(false)
    private var conversationRootReviewed by mutableStateOf(false)
    private var conversationInitialChain by mutableStateOf("")
    private var conversationEnrollmentToken: AtomicBoolean? = null
    private val conversationEnrollment = AtomicReference<ConversationEnrollmentSession?>(null)
    private val conversationSetupPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val accepted = conversationEntryOpen && conversationPickEpoch == conversationUiEpoch
        conversationPickEpoch = null
        if (accepted) acceptConversationSetupFile(uri)
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
                } ?: GatewayPage.HOME, onPageChanged = ::summaryPageChanged) { page, navigate ->
                    if (page == GatewayPage.HOME) {
                        GatewayHome(
                            AuthenticatedGatewayStatus.value, GatewayStatus.value,
                            AuthenticatedGatewayStatus.heartbeats,
                            sims.firstOrNull { it.first == selectedSim }?.second ?: "Not selected",
                            pairingStatus,
                            power = rememberGatewayPower(),
                            summary = summaryView,
                            summaryStatus = summaryStatus,
                            onSetup = { navigate(GatewayPage.SETUP) },
                            onConnection = { navigate(GatewayPage.CONNECTION) },
                            onPause = {
                                clearSummaryReader(clearKey = true)
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
                        HorizontalDivider()
                        GatewaySectionTitle("Message summary reader")
                        Text("Optional read-only metadata. Use a separate messages:read API key restricted to this device. Connection and pairing credentials cannot read counts. Nothing is saved; backgrounding the app clears this key. This action never starts a service or sends SMS.")
                        OutlinedTextField(value = summaryOrigin, onValueChange = {
                            summaryOrigin = it; clearSummaryReader(clearKey = true)
                        }, label = { Text("Summary HTTPS origin") })
                        OutlinedTextField(value = summaryDeviceId, onValueChange = {
                            summaryDeviceId = it; clearSummaryReader(clearKey = true)
                        }, label = { Text("Summary device UUID") })
                        OutlinedTextField(value = summaryCredential, onValueChange = {
                            summaryCredential = it; clearSummaryReader(clearKey = false)
                        }, visualTransformation = PasswordVisualTransformation(),
                            label = { Text("Separate messages-read API key") })
                        GatewayButton(onClick = {
                            if (prepareSummaryRead()) {
                                summaryRequested = true
                                navigate(GatewayPage.HOME)
                            }
                        }) { Text("Read summary on Home") }
                        GatewayButton(onClick = { clearSummaryReader(clearKey = true) }) { Text("Clear summary reader") }
                        Text(summaryStatus)

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
        summaryResumed = true
        if (summaryHome) summaryState.resume()
        updateSummaryView()
        refreshSims()
        defaultSmsAppRcsRisk = DefaultSmsAppRcsRisk.observe(this)
    }

    override fun onPause() {
        revokeConversationForeground()
        summaryResumed = false
        clearSummaryReader(clearKey = true)
        super.onPause()
    }

    override fun onDestroy() {
        pendingConversationPhoneExport = null
        pendingConversationExportUri = null
        closeConversationEntry()
        conversationWorker.shutdownNow()
        clearSummaryReader(clearKey = true)
        summaryWorker.shutdownNow()
        pairingWorker.shutdownNow()
        super.onDestroy()
    }

    override fun onStop() {
        revokeConversationForeground()
        super.onStop()
    }

    private fun revokeConversationForeground() {
        conversationExportWriteToken?.set(false)
        conversationSetupEnabled = false
        withdrawConversationReplyChoice()
        closeConversationEnrollment(preservePendingPublicFile = true)
        // A file picker may return a public candidate, but never preserves phone authority.
        conversationEntry?.close()
        conversationEntry = null
        conversationController = null
        conversationPort = null
        conversationSelectedLine = null
        conversationVerifiedLineLabel = null
        conversationReplyPending = false
        cancelConversationReplyImport()
        if (conversationPickEpoch == null && conversationEntryOpen) closeConversationEntry(preservePendingPublicFile = true)
    }

    internal fun acceptConversationSetupFile(uri: Uri?) {
        if (!conversationEntryOpen) return
        conversationSetupEnabled = false
        withdrawConversationReplyChoice()
        conversationSetupFile = uri
        conversationEntryStatus = if (uri == null) "File selection cancelled." else "Public setup selected. Phone approval is still required."
    }

    private fun closeConversationEntry(preservePendingPublicFile: Boolean = false) {
        conversationSetupEnabled = false
        withdrawConversationReplyChoice()
        closeConversationEnrollment(preservePendingPublicFile)
        // Capture CLOSE_FAILED while this exact view generation is still observable.
        conversationEntry?.close()
        ++conversationUiEpoch
        conversationEntryOpen = false
        conversationPickEpoch = null
        conversationEntry = null
        conversationController = null
        conversationPort = null
        conversationSetupFile = null
        cancelConversationReplyImport()
        conversationSelectedLine = null
        conversationVerifiedLineLabel = null
        conversationReplyPending = false
    }

    @Composable private fun ConversationEntryContent() {
        if (conversationEnrollmentOpen) {
            Dialog(onDismissRequest = { closeConversationEnrollment() },
                properties = DialogProperties(usePlatformDefaultWidth = false)) {
                Surface(Modifier.fillMaxSize()) {
                    Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding()
                        .verticalScroll(rememberScrollState()).padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        GatewaySectionTitle("Conversation enrollment")
                        OutlinedButton(onClick = { closeConversationEnrollment() },
                            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Close enrollment and return to review") }
                        ConversationEnrollmentPane(conversationRootPin, conversationRootFingerprint,
                            conversationRootCompared, conversationRootReviewed, conversationEnrollmentBusy,
                            conversationEnrollmentStatus, conversationReaderExport, conversationInitialChain,
                            { value ->
                                if (value.length <= 128) {
                                    closeConversationEnrollmentSession()
                                    conversationRootPin = value; conversationRootCompared = false; conversationRootReviewed = false
                                }
                            }, { value -> if (value.length <= 64) conversationRootFingerprint = value },
                            { conversationRootCompared = it },
                            { value -> if (value.length <= ConversationEnrollmentSession.MAX_CHAIN_TEXT) conversationInitialChain = value },
                            { runConversationEnrollment({ session -> session.enrollReaderPublicExport() }) { result ->
                                conversationPhoneExport = result
                                conversationReaderExport = java.util.Base64.getEncoder().encodeToString(result.publicBytes())
                                conversationEnrollmentStatus = "Public phone export fingerprint: ${result.fingerprintHex}. Compare all 64 characters directly on this phone before owner import."
                            } },
                            {
                                val pin = conversationRootPin
                                runConversationEnrollment({ session ->
                                    val display = session.reviewRoot(ConversationEnrollmentSession.decodePublic(pin, 94, 94))
                                    "Account " + display.accountHex + "; full public root fingerprint " + display.fingerprintHex
                                }) { result -> conversationRootReviewed = true; conversationEnrollmentStatus = result }
                            }, {
                                val fingerprint = conversationRootFingerprint; val compared = conversationRootCompared
                                runConversationEnrollment({ session ->
                                    val result = session.enrollComparedRoot(fingerprint, compared)
                                    check(result.status == Draft02TrustStore.Status.NEEDS_FRESHNESS)
                                    "Compared root enrolled. Import its complete signed predecessor chain before your first review. No content transfer or sending is approved."
                                }) { result -> conversationRootReviewed = false; conversationRootCompared = false; conversationEnrollmentStatus = result }
                            }, {
                                val packet = conversationPhoneExport
                                if (packet != null && conversationEnrollmentOpen && !conversationEnrollmentBusy &&
                                    lifecycle.currentState == Lifecycle.State.RESUMED && pendingConversationPhoneExport == null) {
                                    runCatching { packet.requireCurrent() }.onSuccess {
                                        // Only this public packet survives the destination picker. All review/reply authority still withdraws on pause.
                                        pendingConversationPhoneExport = packet
                                        conversationExportPicker.launch("zrotext-phone-public-keys.bin")
                                    }.onFailure { conversationEnrollmentStatus = "Public export expired or pairing/line/key changed. Enroll and review its current public values again." }
                                }
                            })
                    }
                }
            }
            return
        }
        val observedPort = conversationPort
        val replyChoiceGeneration = conversationReplyChoiceGeneration
        val replyChoiceView = conversationUiEpoch
        val replyChoiceFocus = remember { FocusRequester() }
        var replyChoiceFocused by remember { mutableStateOf(false) }
        var restoreReplyChoiceFocus by remember { mutableStateOf<Long?>(null) }
        LaunchedEffect(replyChoiceGeneration) {
            if (restoreReplyChoiceFocus == replyChoiceGeneration) {
                restoreReplyChoiceFocus = null
                if (replyChoiceGeneration == conversationReplyChoiceGeneration &&
                    replyChoiceView == conversationUiEpoch && conversationEntryOpen &&
                    conversationSetupEnabled && conversationPort == null &&
                    lifecycle.currentState == Lifecycle.State.RESUMED) replyChoiceFocus.requestFocus()
            }
        }
        DisposableEffect(observedPort) {
            conversationReplyObservation = null
            conversationReplyExpired = false
            val token = AtomicBoolean(true)
            val subscription = runCatching { observedPort?.observe { value ->
                val received = SystemClock.elapsedRealtime()
                runOnUiThread {
                    if (token.get() && conversationEntryOpen && conversationPort === observedPort &&
                        value.version > (conversationReplyObservation?.version ?: 0)) {
                        // An action belongs to one observation, never a later active lease.
                        if (conversationReplyToken != null) cancelConversationReplyImport()
                        conversationReplyObservation = value
                        conversationReplyReceivedAt = received
                        val elapsed = SystemClock.elapsedRealtime() - received
                        conversationReplyExpired = elapsed < 0 || value.remainingMs <= elapsed
                        if (value.phase != ConversationPresentationPhase.CONFIRMED_ACTIVE) cancelConversationReplyImport()
                    }
                }
            } }.getOrNull()
            onDispose { token.set(false); runCatching { subscription?.close() } }
        }
        LaunchedEffect(conversationReplyObservation?.version, conversationReplyReceivedAt) {
            val budget = conversationReplyObservation?.remainingMs ?: 0
            if (budget > 0) {
                kotlinx.coroutines.delay((budget - (SystemClock.elapsedRealtime() - conversationReplyReceivedAt)).coerceAtLeast(0))
                conversationReplyExpired = true
                cancelConversationReplyImport()
            }
        }
        Dialog(onDismissRequest = {
            if (conversationReplyEditorOpen && !conversationReplyPending) cancelConversationReplyImport() else closeConversationEntry()
        }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
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
                        }, Modifier.weight(1f), onDismiss = { closeConversationEntry() }, onStopRequested = {
                            conversationSetupEnabled = false
                            withdrawConversationReplyChoice()
                            cancelConversationReplyImport()
                        })
                    } else {
                        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()),
                            verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(12.dp)) {
                            Text("Select the public phone setup file from the paired browser. The existing paired device, selected line and enrolled hardware key must match. No key is created here.")
                            OutlinedButton(onClick = {
                                conversationSetupEnabled = false; withdrawConversationReplyChoice()
                                conversationEnrollmentOpen = true
                            }, enabled = conversationEntryState != ConversationSetupEntrySession.State.OPENING &&
                                conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED,
                                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Enroll conversation keys and compared root") }
                            Text(if (conversationSetupEnabled) "Review is enabled for this foreground session. Phone approval is still required."
                                else "Review is off for this session.")
                            Text("Selecting a public file does not start setup. Enable review explicitly after selection to check the existing pairing, line and reader. This is not agreement to SMS content transfer: the selected conversation needs separate phone approval. Leaving this app turns review and replies off and closes its setup. Replies additionally require your separate choice below, signed reply authority and server permission.")
                            Button(onClick = {
                                conversationSetupEnabled = false
                                conversationSetupFile = null
                                conversationPickEpoch = conversationUiEpoch
                                conversationSetupPicker.launch(arrayOf("application/octet-stream"))
                            }, enabled = conversationEntryState != ConversationSetupEntrySession.State.OPENING &&
                                conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED,
                                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Select conversation setup file") }
                            Button(onClick = {
                                if (conversationSetupFile != null && conversationEntryOpen &&
                                    conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED) {
                                    conversationSetupEnabled = true
                                    conversationEntryStatus = "Review enabled. Verify the selected conversation before agreeing to content transfer."
                                }
                            }, enabled = !conversationSetupEnabled && conversationSetupFile != null &&
                                conversationEntryState != ConversationSetupEntrySession.State.OPENING &&
                                conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED,
                                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Enable review for this session") }
                            Text(if (conversationRepliesEnabled) "Approved replies are enabled for this foreground review."
                                else "Replies are off. Review can continue without sending.")
                            key(replyChoiceGeneration) {
                                OutlinedButton(onClick = {
                                    if (replyChoiceGeneration == conversationReplyChoiceGeneration &&
                                        replyChoiceView == conversationUiEpoch && conversationEntryOpen &&
                                        conversationSetupEnabled && lifecycle.currentState == Lifecycle.State.RESUMED &&
                                        conversationEntryState != ConversationSetupEntrySession.State.OPENING &&
                                        conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED) {
                                        if (conversationRepliesEnabled) {
                                            val restoreFocus = replyChoiceFocused
                                            withdrawConversationReplyChoice()
                                            if (restoreFocus) restoreReplyChoiceFocus = conversationReplyChoiceGeneration
                                        } else {
                                            conversationRepliesEnabled = true
                                        }
                                    }
                                }, enabled = conversationSetupEnabled &&
                                    conversationEntryState != ConversationSetupEntrySession.State.OPENING &&
                                    conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED,
                                    modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)
                                        .focusRequester(replyChoiceFocus).onFocusChanged { replyChoiceFocused = it.isFocused }) {
                                    Text(if (conversationRepliesEnabled) "Turn replies off" else "Allow approved replies for this session")
                                }
                            }
                            Text("Allowing replies authorizes this phone to send only individually confirmed replies for the selected conversation after phone content approval and reply-authority verification. SMS carrier charges may apply. Leaving the app withdraws this permission.")
                            Button(onClick = { beginConversationEntry() }, enabled = conversationSetupEnabled && conversationSetupFile != null &&
                                conversationEntryState != ConversationSetupEntrySession.State.OPENING && conversationEntryState != ConversationSetupEntrySession.State.CLOSE_FAILED,
                                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Review selected conversation") }
                            if (conversationEntryState == ConversationSetupEntrySession.State.OPENING) Text("Checking the selected conversation. Content transfer is not confirmed.")
                            if (conversationEntryState == ConversationSetupEntrySession.State.CLOSE_FAILED) Text("Review closure could not be completed. Content transfer is not confirmed.")
                        }
                    }
                    if (port != null && !conversationReplyEditorOpen) OutlinedButton(onClick = {
                        conversationReplyText = ""
                        conversationReplyEditorOpen = true
                    }, enabled = conversationSetupEnabled && conversationReplyIsCurrent(),
                        modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Import public reply authority") }
                    if (conversationEntryStatus.isNotEmpty()) Text(conversationEntryStatus, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        // Keep the original consent pane mounted: opening an editor cannot renew its lease.
        if (conversationReplyEditorOpen && observedPort != null) {
            Dialog(onDismissRequest = {
                if (conversationReplyPending) closeConversationEntry() else cancelConversationReplyImport()
            }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
                Surface(Modifier.fillMaxSize()) {
                    Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding()
                        .verticalScroll(rememberScrollState()).padding(16.dp),
                        verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(12.dp)) {
                        GatewaySectionTitle("Public reply authority")
                        Text("Manually paste the public reply authority from the paired browser. This verifies authority for the current approved interval; it does not send a message.")
                        OutlinedTextField(value = conversationReplyText, onValueChange = {
                            if (it.length <= 21900) conversationReplyText = it else {
                                conversationReplyText = ""
                                conversationEntryStatus = "Public reply authority exceeds the allowed size."
                            }
                        }, enabled = !conversationReplyPending, label = { Text("Public reply authority (base64)") },
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, autoCorrectEnabled = false),
                            maxLines = 4, modifier = Modifier.fillMaxWidth())
                        Button(onClick = { installConversationReplyText() }, enabled = conversationSetupEnabled &&
                            conversationReplyText.isNotEmpty() && !conversationReplyPending && conversationReplyIsCurrent(),
                            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Verify pasted reply authority") }
                        OutlinedButton(onClick = { cancelConversationReplyImport() }, enabled = !conversationReplyPending,
                            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Cancel reply import") }
                        OutlinedButton(onClick = { closeConversationEntry() },
                            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Close review and stop setup") }
                        if (conversationReplyPending) Text("Checking reply authority. No message is sent by this action.")
                        if (conversationEntryStatus.isNotEmpty()) Text(conversationEntryStatus)
                    }
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
        val allowReplies = conversationRepliesEnabled
        val initialChain = conversationInitialChain
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
                        val prepared = ConversationUserSetupProvider(applicationContext, database.attempts()).resolve(bytes, enabled = true,
                            initialManifests = ConversationEnrollmentSession.decodeChain(initialChain))
                            ?: error("Setup unavailable")
                        val binding = checkNotNull(database.attempts().currentLineBinding())
                        check(binding.accountId == prepared.selection.identity.accountId && binding.deviceId == prepared.selection.identity.deviceId &&
                            binding.lineId == prepared.selection.lineId && binding.generation == prepared.selection.bindingGeneration)
                        val verifiedLabel = conversationEntryLineLabel(binding, prepared.selection, selectedSubscription, labels)
                        if (cancelled.get()) return@execute
                        val controller = ConversationUserSetupController(applicationContext, database.attempts(), prepared.payloadAlias,
                            conversationWorker, java.util.concurrent.Executor { action -> runOnUiThread(action) },
                            ConversationExecutionComposition(applicationContext, database, enabled = allowReplies), { port ->
                                if (!cancelled.get() && conversationEntryOpen && conversationUiEpoch == epoch) {
                                    conversationInitialChain = ""
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
                                conversationSetupEnabled = false
                            }
                        }
                    }
                }
                return true
            }
            override fun close() { cancelled.set(true); owned.getAndSet(null)?.close() }
        }
    }

    private fun cancelConversationReplyImport() {
        conversationReplyToken?.set(false)
        conversationReplyToken = null
        conversationReplyText = ""
        conversationReplyEditorOpen = false
        conversationReplyPending = false
    }

    private fun withdrawConversationReplyChoice() {
        conversationReplyChoiceGeneration++
        conversationRepliesEnabled = false
    }

    private fun closeConversationEnrollmentSession() {
        conversationEnrollmentToken?.set(false)
        conversationEnrollmentToken = null
        conversationEnrollment.getAndSet(null)?.close()
        conversationEnrollmentBusy = false
        conversationRootReviewed = false
        conversationRootCompared = false
    }

    private fun closeConversationEnrollment(preservePendingPublicFile: Boolean = false) {
        conversationExportWriteToken?.set(false)
        if (!preservePendingPublicFile) {
            pendingConversationPhoneExport = null
            pendingConversationExportUri = null
        }
        closeConversationEnrollmentSession()
        conversationEnrollmentOpen = false
        conversationRootFingerprint = ""
        conversationPhoneExport = null
        conversationReaderExport = ""
    }

    override fun onPostResume() {
        super.onPostResume()
        Handler(Looper.getMainLooper()).post { finishConversationPublicExport() }
    }

    private fun <T> runConversationEnrollment(action: (ConversationEnrollmentSession) -> T, completed: (T) -> Unit) {
        if (!conversationEnrollmentOpen || conversationEnrollmentBusy) return
        val token = conversationEnrollmentToken ?: AtomicBoolean(true).also { conversationEnrollmentToken = it }
        conversationEnrollmentBusy = true
        conversationWorker.execute {
            val result = runCatching {
                check(token.get())
                val session = conversationEnrollment.get() ?: ConversationAndroidEnrollment.open(applicationContext,
                    SmsJournalDatabase.get(applicationContext), token).also {
                    check(conversationEnrollment.compareAndSet(null, it))
                    if (!token.get()) { conversationEnrollment.getAndSet(null)?.close(); error("Enrollment cancelled") }
                }
                check(token.get()); action(session).also { check(token.get()) }
            }
            runOnUiThread {
                if (token.get() && conversationEnrollmentToken === token && conversationEnrollmentOpen) {
                    conversationEnrollmentBusy = false
                    result.onSuccess(completed).onFailure {
                        conversationRootReviewed = false
                        conversationEnrollmentStatus = "Enrollment refused. Check the current paired connection, selected approved line, hardware eligibility and independent root comparison. Existing protected state may require recovery."
                    }
                }
            }
        }
    }

    private fun finishConversationPublicExport() {
        if (lifecycle.currentState != Lifecycle.State.RESUMED) return
        val packet = pendingConversationPhoneExport ?: return
        val uri = pendingConversationExportUri ?: return
        pendingConversationPhoneExport = null
        pendingConversationExportUri = null
        val token = AtomicBoolean(true)
        conversationExportWriteToken = token
        conversationWorker.execute {
            val saved = runCatching {
                check(token.get())
                packet.requireCurrent()
                packet.write({ check(token.get()) }) {
                    check(token.get())
                    checkNotNull(contentResolver.openOutputStream(uri, "w"))
                }
                check(token.get())
            }.isSuccess
            runOnUiThread {
                if (conversationExportWriteToken === token) {
                    conversationExportWriteToken = null
                    conversationEntryStatus = if (saved && token.get()) "Public phone key file saved. Full export fingerprint: ${packet.fingerprintHex}. Independently compare all 64 characters directly on this phone before owner import. No content transfer or replies were approved."
                        else "Public phone export could not be completed. Check pairing, the selected line and its current keys; discard any incomplete public file."
                    if (token.get() && lifecycle.currentState == Lifecycle.State.RESUMED) conversationEntryOpen = true
                }
            }
        }
    }

    private fun conversationReplyIsCurrent(): Boolean {
        val observation = conversationReplyObservation ?: return false
        val elapsed = SystemClock.elapsedRealtime() - conversationReplyReceivedAt
        return conversationEntryOpen && conversationPort != null && !conversationReplyExpired &&
            observation.phase == ConversationPresentationPhase.CONFIRMED_ACTIVE && elapsed >= 0 && elapsed < observation.remainingMs
    }

    private fun installConversationReplyText() {
        if (!conversationSetupEnabled || conversationReplyPending || !conversationReplyEditorOpen || !conversationReplyIsCurrent()) return
        val controller = conversationController
        val installer = conversationReplyInstaller ?: controller?.let { value ->
            { bytes: ByteArray, signer: ByteArray, completion: (Boolean) -> Unit -> value.installReplyAuthority(bytes, signer, completion) }
        } ?: return
        val entry = conversationEntry ?: return
        val port = conversationPort
        val text = conversationReplyText
        val epoch = conversationUiEpoch
        val observation = conversationReplyObservation ?: return
        val receivedAt = conversationReplyReceivedAt
        fun originalLeaseIsCurrent(): Boolean {
            val elapsed = SystemClock.elapsedRealtime() - receivedAt
            return elapsed >= 0 && elapsed < observation.remainingMs
        }
        fun originalReviewIsCurrent(): Boolean = conversationEntryOpen && conversationUiEpoch == epoch &&
            conversationEntry === entry && conversationPort === port && conversationController === controller &&
            conversationReplyObservation === observation && conversationReplyReceivedAt == receivedAt &&
            conversationReplyIsCurrent() && originalLeaseIsCurrent()
        val token = AtomicBoolean(true)
        conversationReplyToken = token
        conversationReplyText = ""
        conversationReplyPending = true
        conversationWorker.execute {
            try {
                if (!token.get()) return@execute
                check(originalLeaseIsCurrent())
                val candidate = decodeConversationReplyText(text)
                if (!token.get()) return@execute
                check(originalLeaseIsCurrent())
                installer(candidate.signedSuccessor(), candidate.signerId()) { accepted ->
                    runOnUiThread {
                        if (token.get() && originalReviewIsCurrent()) {
                            cancelConversationReplyImport()
                            conversationEntryStatus = if (accepted) "Reply authority verified for the current interval. This action did not send a message."
                                else "Reply authority was not accepted. Current phone approval and matching authority are required."
                        } else if (token.get()) {
                            cancelConversationReplyImport()
                        }
                    }
                }
            } catch (_: Exception) {
                runOnUiThread {
                    if (token.get() && conversationEntryOpen && conversationUiEpoch == epoch && conversationEntry === entry && conversationPort === port) {
                        cancelConversationReplyImport()
                        conversationEntryStatus = "The public reply authority could not be verified. Use the exact complete base64 value from the paired browser."
                    }
                }
            }
        }
    }

    private fun clearSummaryReader(clearKey: Boolean) {
        summaryRead?.cancel()
        summaryRead = null
        summaryRequested = false
        summaryHandler.removeCallbacks(summaryAge)
        summaryState.clear()
        summarySelectedDevice = null
        if (clearKey) summaryCredential = ""
        summaryView = summaryState.view(SystemClock.elapsedRealtime(), System.currentTimeMillis())
        summaryStatus = "Message counts are unavailable on this phone. An authorized summary reader is not connected."
    }
    private fun prepareSummaryRead(): Boolean {
        val selected = GatewayInputValidation.deviceId(summaryDeviceId)
        if (selected == null) {
            summaryStatus = "Enter the summary device UUID and a separate messages-read API key."
            return false
        }
        return try {
            // Validate the exact origin and credential realm before navigation.
            GatewaySummaryClient.request(summaryOrigin, summaryCredential, selected)
            if (summarySelectedDevice != selected) {
                summaryState.select(selected)
                summarySelectedDevice = selected
            }
            true
        } catch (_: IllegalArgumentException) {
            summaryStatus = "Enter an HTTPS origin and a separate messages-read API key for this device."
            false
        }
    }
    private fun summaryPageChanged(page: GatewayPage) {
        summaryHome = page == GatewayPage.HOME
        if (!summaryHome) {
            summaryRead?.cancel()
            summaryRead = null
            summaryHandler.removeCallbacks(summaryAge)
            summaryState.pause()
            summaryRequested = false
        } else if (summaryResumed) {
            summaryState.resume()
            if (summaryRequested) {
                summaryRequested = false
                readSummary()
            }
        }
        updateSummaryView()
    }
    private fun readSummary() {
        if (!summaryHome || !summaryResumed) return
        val selected = summarySelectedDevice ?: return
        val ticket = summaryState.begin(SystemClock.elapsedRealtime(), System.currentTimeMillis()) ?: return
        val read = try { summaryClient.newRead(summaryOrigin, summaryCredential, selected) }
            catch (_: IllegalArgumentException) {
                summaryState.fail(ticket)
                summaryStatus = "The summary reader configuration is unavailable."
                updateSummaryView()
                return
            }
        summaryRead = read
        summaryStatus = "Loading device-scoped writer metadata…"
        updateSummaryView()
        summaryWorker.execute {
            val result = read.execute()
            runOnUiThread {
                val applied = when (result) {
                    is GatewaySummaryClient.Result.Success -> summaryState.complete(ticket, result.snapshot)
                    is GatewaySummaryClient.Result.Refused -> summaryState.fail(ticket)
                }
                if (applied) {
                    summaryRead = null
                    summaryStatus = when (result) {
                        is GatewaySummaryClient.Result.Success -> "Read-only writer metadata. Sending and delivery remain separate."
                        is GatewaySummaryClient.Result.Refused -> when (result.reason) {
                            GatewaySummaryClient.Failure.UNAUTHORIZED, GatewaySummaryClient.Failure.FORBIDDEN -> "Summary access refused. Check the separate device-scoped read key."
                            else -> "Summary unavailable. Return to Connection to retry explicitly."
                        }
                    }
                    if (result is GatewaySummaryClient.Result.Refused && result.reason in listOf(
                        GatewaySummaryClient.Failure.UNAUTHORIZED, GatewaySummaryClient.Failure.FORBIDDEN)) summaryCredential = ""
                    updateSummaryView()
                }
            }
        }
    }
    private fun updateSummaryView() {
        summaryHandler.removeCallbacks(summaryAge)
        summaryView = summaryState.view(SystemClock.elapsedRealtime(), System.currentTimeMillis())
        if (summaryView.phase == GatewaySummaryState.Phase.STALE) summaryStatus = "Historical writer metadata; current counts are unknown. Return to Connection to refresh explicitly."
        if (summaryHome && summaryResumed && summaryView.freshForMs > 0)
            summaryHandler.postDelayed(summaryAge, minOf(1_000L, summaryView.freshForMs))
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
