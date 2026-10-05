// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.delay
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicBoolean

/** No saved-state, autofill, personalized learning, clipboard copy, or extract-mode secret output.
 * UI/IME/OS buffers can still contain copies; this view does not promise total zeroization.
 */
internal class AndroidOwnerCustodyRecoveryInput(context: Context) : EditText(context) {
    init {
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI
        isSaveEnabled = false
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= 30) importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        setSingleLine(true)
        hint = "Fresh root recovery token (ZTRK1)"
        contentDescription = "Fresh owner recovery token; password input without personalized learning"
        filters = arrayOf(android.text.InputFilter.LengthFilter(79))
    }
    override fun onTextContextMenuItem(id: Int): Boolean =
        if (id == android.R.id.copy || id == android.R.id.cut) false else super.onTextContextMenuItem(id)
}

private fun Context.ownerCustodyActivity(): Activity? {
    var value: Context = this
    while (value is ContextWrapper) {
        if (value is Activity) return value
        val next = value.baseContext
        if (next === value) return null
        value = next
    }
    return value as? Activity
}

/** Parent entry point. Authority defaults unavailable until an authenticated owner adapter exists. */
@Composable internal fun AndroidOwnerCustodyScreen(
    authority: () -> AndroidOwnerCustodyAuthority? = { null }, onClose: () -> Unit = {}, modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val handler = remember { Handler(Looper.getMainLooper()) }
    val worker = remember { Executors.newSingleThreadExecutor() }
    val screenEpoch = remember { AtomicLong(0) }
    val currentController = remember { AtomicReference<AndroidOwnerCustodyController?>(null) }
    val currentIdentity = remember { AtomicReference<AndroidOwnerCustodyIdentity?>(null) }
    val actionPending = remember { AtomicBoolean(false) }
    var operationQueued by remember { mutableStateOf(false) }
    val currentAuthority by rememberUpdatedState(authority)
    val ownerContext = remember { AndroidOwnerCustodyOwnerContext(unavailable = { currentController.get()?.cancel() }) }
    val typedContext = remember { AndroidOwnerCustodyRegisteredFlowContext(ownerContext) }
    var snapshot by remember { mutableStateOf<AndroidOwnerCustodyController.Snapshot?>(null) }
    val controller = remember {
        AndroidOwnerCustodyController(AndroidOwnerCustodyNative(), AndroidOwnerCustodyStore.create(context.applicationContext),
            SystemClock::elapsedRealtime, { ownerContext.currentAuthority() ?: currentAuthority() },
            { ownerContext.refresh(checkNotNull(currentIdentity.get())) }) { _ -> handler.post { snapshot = currentController.get()?.snapshot() } }
            .also { currentController.set(it) }
    }
    val state = (snapshot ?: controller.snapshot()).let { it.copy(busy = it.busy || operationQueued) }
    var account by remember { mutableStateOf("") }
    var origin by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf("") }
    var token by remember { mutableStateOf("") }
    var revealed by remember { mutableStateOf("") }
    var retained by remember { mutableStateOf(false) }
    var approved by remember { mutableStateOf(false) }
    var backup by remember { mutableStateOf<ByteArray?>(null) }
    var card by remember { mutableStateOf<ByteArray?>(null) }
    var proposal by remember { mutableStateOf<ByteArray?>(null) }
    var publicProposalText by remember { mutableStateOf("") }
    var browserOrigin by remember { mutableStateOf<String?>(null) }
    var browserVisible by remember { mutableStateOf(false) }
    var notice by remember { mutableStateOf("") }
    var pendingExport by remember { mutableStateOf<Pair<String, ByteArray>?>(null) }
    fun action(operation: () -> Unit) {
        if (!actionPending.compareAndSet(false, true)) return
        operationQueued = true
        val expected = screenEpoch.get()
        notice = ""
        worker.execute {
            try {
                if (expected == screenEpoch.get() && lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) operation()
            } catch (_: Exception) {
                handler.post { if (expected == screenEpoch.get()) notice = "Action refused. Check the independently supplied identity, retained files, fresh token, and current owner authority." }
            } finally {
                actionPending.set(false)
                handler.post { if (currentController.get() != null) operationQueued = false }
            }
        }
    }
    fun clearSecrets() { token = ""; revealed = ""; approved = false; retained = false }
    fun independent() = AndroidOwnerCustodyIdentity.parse(account, origin, fingerprint)
    fun freshAuthority(expected: AndroidOwnerCustodyIdentity) {
        ownerContext.refresh(expected); currentIdentity.set(expected)
    }
    val exportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val pending = pendingExport; pendingExport = null
        if (uri == null || pending == null) { if (pending?.first == "backup") controller.exportUnconfirmed() }
        else worker.execute {
            try {
                context.contentResolver.openOutputStream(uri, "wt").use { out -> checkNotNull(out); out.write(pending.second); out.flush() }
                if (pending.first == "backup") {
                    val readback = context.contentResolver.openInputStream(uri).use { input ->
                        readAndroidOwnerCustodyFile(checkNotNull(input), 748)
                    }
                    controller.exportReadback(readback)
                }
                handler.post { notice = if (pending.first == "backup") "Backup write and destination readback matched. Import the independently retained files to check recovery." else "Public artifact saved. No recovery token or private root was exported." }
            } catch (_: Exception) {
                if (pending.first == "backup") controller.exportUnconfirmed()
                handler.post { notice = "Export outcome is unconfirmed. Verify your destination before continuing." }
            }
        }
    }
    val backupPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) worker.execute {
            try {
                val bytes = context.contentResolver.openInputStream(uri).use { readAndroidOwnerCustodyFile(checkNotNull(it), 748) }
                handler.post { backup = bytes; notice = "Independently retained encrypted backup imported." }
            } catch (_: Exception) { handler.post { backup = null; notice = "Encrypted backup import refused." } }
        }
    }
    val cardPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) worker.execute {
            try {
                val bytes = context.contentResolver.openInputStream(uri).use { readAndroidOwnerCustodyFile(checkNotNull(it), 645) }
                handler.post { card = bytes; notice = "Independently retained public root card imported." }
            } catch (_: Exception) { handler.post { card = null; notice = "Public root card import refused." } }
        }
    }
    val proposalPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) worker.execute {
            try {
                val bytes = context.contentResolver.openInputStream(uri).use { readAndroidOwnerCustodyFile(checkNotNull(it), 663) }
                AndroidOwnerCustodyReview.parse(bytes)
                handler.post { proposal = bytes; approved = false; notice = "Public enrollment proposal imported. No signing authority was imported." }
            } catch (_: Exception) { handler.post { proposal = null; notice = "Typed enrollment proposal import refused." } }
        }
    }
    DisposableEffect(controller, lifecycle) {
        val activity = context.ownerCustodyActivity()
        val wasSecure = (activity?.window?.attributes?.flags ?: 0).and(WindowManager.LayoutParams.FLAG_SECURE) != 0
        activity?.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_PAUSE || event == Lifecycle.Event.ON_STOP || event == Lifecycle.Event.ON_DESTROY) {
                screenEpoch.incrementAndGet(); clearSecrets(); currentIdentity.set(null); ownerContext.invalidate(); controller.cancel()
            }
        }
        lifecycle.addObserver(observer)
        onDispose {
            screenEpoch.incrementAndGet(); clearSecrets(); controller.close(); worker.shutdownNow()
            currentIdentity.set(null); ownerContext.close()
            currentController.set(null); handler.removeCallbacksAndMessages(null)
            lifecycle.removeObserver(observer)
            if (!wasSecure) activity?.window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
    LaunchedEffect(controller) {
        while (true) { delay(1000); controller.expireReveal() }
    }
    LaunchedEffect(revealed) { if (revealed.isNotEmpty()) { delay(120000); revealed = "" } }
    Box(modifier.fillMaxSize()) {
    AndroidOwnerCustodyPane(state, account, origin, fingerprint, token, revealed, retained, approved,
        backup != null, card != null, proposal != null, notice,
        changeAccount = { account = it; currentIdentity.set(null); ownerContext.invalidate(); controller.cancel(); clearSecrets() },
        changeOrigin = { origin = it; browserVisible = false; browserOrigin = null; currentIdentity.set(null); ownerContext.invalidate(); controller.cancel(); clearSecrets() },
        changeFingerprint = { fingerprint = it; currentIdentity.set(null); ownerContext.invalidate(); controller.cancel(); clearSecrets() },
        changeToken = { token = it }, changeRetained = { retained = it }, changeApproved = { approved = it },
        create = {
            val selectedAccount = account; val selectedOrigin = origin
            action { val uuid = UUID.fromString(selectedAccount); require(uuid.toString() == selectedAccount); controller.create(uuid, selectedOrigin) }
        }, reveal = { try { revealed = controller.reveal() } catch (_: Exception) { notice = "Recovery-token reveal is unavailable or expired." } },
        hideReveal = { try { controller.confirmTokenRecorded(); revealed = "" } catch (_: Exception) { revealed = ""; notice = "Token recording was not confirmed. Independently recover before exporting this kit." } },
        exportBackup = { pendingExport = "backup" to controller.encryptedBackup(); exportPicker.launch("encrypted-owner-root.ztrb") },
        exportCard = { pendingExport = "card" to controller.publicCard(); exportPicker.launch("public-owner-root.ztrc") },
        importBackup = { backupPicker.launch(arrayOf("application/octet-stream")) },
        importCard = { cardPicker.launch(arrayOf("application/octet-stream")) },
        recover = {
            val freshToken = token; token = ""; revealed = ""
            val expected = runCatching { independent() }.getOrNull()
            val selectedBackup = backup; val selectedCard = card; val selectedRetention = retained
            if (expected == null || selectedBackup == null || selectedCard == null) notice = "Independent identity and both retained files are required."
            else action { controller.recover(selectedBackup, selectedCard, decodeAndroidOwnerRecoveryToken(freshToken), expected, selectedRetention) }
        }, importProposal = { proposalPicker.launch(arrayOf("application/octet-stream")) },
        review = {
            val expected = runCatching { independent() }.getOrNull(); val candidate = proposal
            approved = false; token = ""
            if (expected == null || candidate == null) notice = "Independent identity and a typed public proposal are required."
            else action { freshAuthority(expected); controller.review(candidate, expected) }
        }, sign = {
            val consent = approved; approved = false
            action {
                freshAuthority(independent()) // Do not read or decode the root token across a network wait.
                val freshToken = token; handler.post { token = "" }
                controller.sign(decodeAndroidOwnerRecoveryToken(freshToken), consent)
            }
        }, exportSignatures = {
            state.publicSignatures?.let { pendingExport = "signatures" to it.toByteArray(Charsets.US_ASCII); exportPicker.launch("owner-custody-signatures.txt") }
        }, cancel = { screenEpoch.incrementAndGet(); clearSecrets(); ownerContext.invalidate(); controller.cancel(); onClose() },
        extra = {
            if (state.canExportKit) Button({
                pendingExport = "public" to controller.publicRootReceipt(); exportPicker.launch("public-owner-root-receipt.txt")
            }, enabled = !state.busy, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Save readable public root receipt and backup UUID") }
            Text("Use your owner browser session on this phone", style = MaterialTheme.typography.titleMedium)
            Text("Sign in to the intended HTTPS owner origin here. The native custodian reads that same live owner cookie/session and authenticated server time; the phone device bearer and imported challenge cannot replace it. Keep this page open while exchanging public proposal/response text.")
            Button({
                try {
                    AndroidOwnerCustodyIdentity.validateAccountOrigin(UUID(0, 1), origin)
                    if (browserOrigin != origin) { browserOrigin = origin; ownerContext.invalidate(); controller.cancel() }
                    browserVisible = true; clearSecrets()
                } catch (_: Exception) { notice = "Enter the canonical independent HTTPS owner origin first." }
            }, enabled = enabledForOwnerBrowser(state), modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Open same-session owner browser") }
            OutlinedTextField(publicProposalText, {
                if (it.length <= 884) { publicProposalText = it; proposal = null; approved = false; controller.cancel() }
            }, enabled = state.available && !state.busy, label = { Text("Paste exact PUBLIC enrollment proposal base64") }, modifier = Modifier.fillMaxWidth())
            Button({
                try { proposal = decodeAndroidOwnerPublicProposal(publicProposalText, 663).also { AndroidOwnerCustodyReview.parse(it) }; approved = false }
                catch (_: Exception) { proposal = null; controller.cancel(); notice = "Public enrollment proposal text refused." }
            }, enabled = state.available && !state.busy && publicProposalText.isNotEmpty(), modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Import public enrollment proposal text") }
            state.publicSignatures?.let {
                Text("PUBLIC enrollment response. Select/copy manually back into the same owner browser page. Root recovery material never belongs there.")
                SelectionContainer { Text(it) }
            }
            AndroidOwnerCustodyFlowPane(state, controller, {
                independent().also { currentIdentity.set(it) }
            }, ownerContext, typedContext, ::action, {
                check(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED))
                val fresh = token; handler.post { token = "" }
                decodeAndroidOwnerRecoveryToken(fresh)
            }, { text -> handler.post { notice = text } }, { name, bytes -> pendingExport = "public" to bytes; exportPicker.launch(name) })
        }, modifier = Modifier.fillMaxSize())
    browserOrigin?.let { selectedOrigin ->
        AndroidOwnerCustodyOwnerWebView(selectedOrigin, onClose = { browserVisible = false },
            onSessionChanged = { ownerContext.invalidate(); controller.cancel(); clearSecrets() }, visible = browserVisible,
            archiveKit = { controller.approvedBrowserArchive(independent().also { currentIdentity.set(it) }) },
            verifyArchiveRecovery = controller::verifyBrowserArchiveRecovery, ownerContext = ownerContext,
            onRetire = { browserVisible = false; browserOrigin = null; ownerContext.invalidate(); controller.cancel(); clearSecrets() })
    }
    }
}

private fun enabledForOwnerBrowser(state: AndroidOwnerCustodyController.Snapshot) = !state.busy

@Composable internal fun AndroidOwnerCustodyPane(
    state: AndroidOwnerCustodyController.Snapshot, account: String, origin: String, fingerprint: String,
    token: String, revealed: String, retained: Boolean, approved: Boolean,
    hasBackup: Boolean, hasCard: Boolean, hasProposal: Boolean, notice: String,
    changeAccount: (String) -> Unit, changeOrigin: (String) -> Unit, changeFingerprint: (String) -> Unit,
    changeToken: (String) -> Unit, changeRetained: (Boolean) -> Unit, changeApproved: (Boolean) -> Unit,
    create: () -> Unit, reveal: () -> Unit, hideReveal: () -> Unit, exportBackup: () -> Unit, exportCard: () -> Unit,
    importBackup: () -> Unit, importCard: () -> Unit, recover: () -> Unit, importProposal: () -> Unit,
    review: () -> Unit, sign: () -> Unit, exportSignatures: () -> Unit, cancel: () -> Unit,
    extra: @Composable () -> Unit = {},
    modifier: Modifier = Modifier
) {
    val enabled = state.available && !state.busy
    Column(modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Android owner setup", style = MaterialTheme.typography.headlineSmall)
        Text("Create or recover your own encrypted owner root on Android. This is a recoverable software root, separate from the phone's hardware device/content keys. A compromised phone is a shared failure domain. Root recovery and archive recovery are separate kits.")
        Text("Enter the account and HTTPS origin independently. For recovery and signing, enter the full fingerprint from your separately retained public card or another independent channel. Imported files never fill these fields.")
        OutlinedTextField(account, changeAccount, enabled = enabled, label = { Text("Independent account UUID") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(origin, changeOrigin, enabled = enabled, label = { Text("Independent HTTPS owner origin") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(fingerprint, changeFingerprint, enabled = enabled, label = { Text("Independent full root fingerprint (64 lowercase hex)") }, modifier = Modifier.fillMaxWidth())
        Button(create, enabled = enabled && account.isNotEmpty() && origin.isNotEmpty(), modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Create encrypted owner kit") }
        state.identity?.let {
            Text("Kit account: ${it.account}\nKit origin: ${it.origin}\nRoot generation: 1\nFull root fingerprint: ${it.fingerprint}\nPublic encrypted-backup UUID: ${state.backupId}")
        }
        Text("Retain an encrypted backup outside app-private storage and keep the recovery token/card separately. A saved local kit alone is not recovery. Record the token before opening a file picker: leaving this screen closes the reveal and cannot silently regenerate it. The token is never placed in a clipboard, Intent, log, or saved state.")
        Button(reveal, enabled = enabled && state.canReveal, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Reveal recovery token privately once") }
        if (revealed.isNotEmpty()) {
            Text("Record this token separately now. This screen blocks screenshots, but UI, keyboard, accessibility and OS buffers cannot be guaranteed to erase every copy.")
            Text(revealed)
            Button(hideReveal, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("I recorded this token separately; hide") }
        }
        if (state.identity != null) {
            Button(exportBackup, enabled = enabled && state.canExportKit, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Save encrypted backup to chosen destination") }
            Button(exportCard, enabled = enabled && state.canExportKit, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Save separate public recovery card") }
        }
        Button(importBackup, enabled = enabled, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text(if (hasBackup) "Replace retained encrypted backup" else "Import retained encrypted backup") }
        Button(importCard, enabled = enabled, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text(if (hasCard) "Replace retained public recovery card" else "Import retained public recovery card") }
        Text("I independently retained the encrypted backup and separately retained its recovery token and public card.")
        Checkbox(retained, changeRetained, enabled = enabled, modifier = Modifier.semantics { contentDescription = "Independent encrypted backup and separate recovery token/card retention" })
        Text("Fresh recovery token input asks the IME to avoid personalized learning and extract mode. UI/IME/OS copies cannot be fully zeroized. No password-derived or silently cached recovery is used.")
        val onToken by rememberUpdatedState(changeToken)
        AndroidView(factory = { context -> AndroidOwnerCustodyRecoveryInput(context).apply {
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { onToken(s?.toString() ?: "") }
                override fun afterTextChanged(s: Editable?) = Unit
            })
        } }, update = { input -> input.isEnabled = enabled; if (input.text.toString() != token) input.setText(token) }, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp))
        Button(recover, enabled = enabled && retained && hasBackup && hasCard && token.length == 79 && fingerprint.length == 64,
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Run fresh independent recovery check") }
        Text("Enrollment and encrypted-root custody signing use a bounded public challenge. Authenticated current owner account/user/session and time are required; an imported timestamp or a phone device session supplies no owner authority.")
        Button(importProposal, enabled = enabled, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text(if (hasProposal) "Replace public enrollment proposal" else "Import public enrollment proposal") }
        Button(review, enabled = enabled && state.recoveryVerified && hasProposal, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Review exact enrollment and custody operation") }
        state.review?.let {
            Text("Operation: root enrollment and encrypted-root custody\nAccount: ${it.account}\nHTTPS origin: ${it.origin}\nRoot generation: 1\nRoot fingerprint: ${it.fingerprint}\nOwner user: ${it.user}\nOwner session: ${it.session}\nChallenge: ${it.challengeId}\nIssued UTC milliseconds: ${it.issuedMs}\nExpiry UTC milliseconds: ${it.expiresMs}")
            Text("I approve this exact enrollment and encrypted-root custody operation once. This does not approve body transfer or send a message.")
            Checkbox(approved, changeApproved, enabled = enabled, modifier = Modifier.semantics { contentDescription = "Separate one-shot owner enrollment and custody approval" })
            Button(sign, enabled = enabled && approved && token.length == 79, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Sign once with fresh recovery token") }
        }
        if (state.publicSignatures != null) Button(exportSignatures, enabled = enabled, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Save public signature response") }
        Text(state.status)
        if (notice.isNotEmpty()) Text(notice)
        extra()
        Button(cancel, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Close owner ceremony") }
    }
}
