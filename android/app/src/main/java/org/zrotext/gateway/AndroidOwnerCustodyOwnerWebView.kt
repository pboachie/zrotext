// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.net.http.SslError
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.webkit.CookieManager
import android.webkit.PermissionRequest
import android.webkit.SslErrorHandler
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.ValueCallback
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.withStateAtLeast
import kotlinx.coroutines.launch
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicBoolean

/** One independently selected HTTPS owner origin. No native JavaScript bridge or root access.
 * CookieManager remains app-local so native HTTPS uses the same authenticated owner session.
 * Web content remains untrusted for owner identity, recovery tokens and native approval.
 */
internal class AndroidOwnerCustodyOwnerBrowser(context: Context, private val origin: String,
    private val changed: () -> Unit,
    private val chooseArchiveFile: (ValueCallback<Array<Uri>>) -> Unit = { it.onReceiveValue(null) },
    private val choosePublicFile: (ValueCallback<Array<Uri>>) -> Unit = { it.onReceiveValue(null) }
) : WebView(context) {
    private val retired = AtomicBoolean()
    private val pageHandler = Handler(Looper.getMainLooper())
    private val timersPaused = AtomicBoolean()
    private var pickerExpiresElapsed = 0L
    private var pickerDeadline: Runnable? = null
    init {
        AndroidOwnerCustodyIdentity.validateAccountOrigin(UUID(0, 1), origin)
        setWebContentsDebuggingEnabled(false)
        isSaveEnabled = false
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        settings.javaScriptEnabled = true // Existing owner login/MFA forms are same-origin scripts.
        settings.domStorageEnabled = false
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
        settings.javaScriptCanOpenWindowsAutomatically = false
        settings.setSupportMultipleWindows(false)
        settings.safeBrowsingEnabled = true
        settings.cacheMode = WebSettings.LOAD_NO_CACHE
        CookieManager.getInstance().setAcceptThirdPartyCookies(this, false)
        setDownloadListener { _, _, _, _, _ -> changed() }
        webChromeClient = object : WebChromeClient() {
            override fun onPermissionRequest(request: PermissionRequest) { request.deny() }
            override fun onShowFileChooser(view: WebView, callback: ValueCallback<Array<Uri>>,
                params: FileChooserParams): Boolean {
                when (importPurpose(params.mode, params.isCaptureEnabled, params.acceptTypes)) {
                    1 -> choosePublicFile(callback)
                    2 -> chooseArchiveFile(callback)
                    else -> callback.onReceiveValue(null)
                }
                return true
            }
        }
        webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (allowed(origin, request.url.toString())) return false
                changed(); return true
            }
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                if (allowed(origin, request.url.toString())) return null
                changed()
                return WebResourceResponse("text/plain", "utf-8", 403, "Origin refused",
                    mapOf("Cache-Control" to "no-store"), ByteArrayInputStream(ByteArray(0)))
            }
            override fun onPageStarted(view: WebView, url: String?, favicon: Bitmap?) {
                changed()
                if (url == null || !allowed(origin, url)) view.stopLoading()
            }
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                handler.cancel(); view.stopLoading(); changed()
            }
        }
        loadUrl("$origin/owner/devices")
    }

    /** Clears the rendering surface without exporting or changing another origin's cookies. */
    fun close() {
        if (!retired.compareAndSet(false, true)) return
        pickerDeadline?.let(pageHandler::removeCallbacks); pickerDeadline = null; pickerExpiresElapsed = 0
        if (timersPaused.getAndSet(false)) resumeTimers()
        changed(); stopLoading(); onPause(); clearHistory(); removeAllViews(); destroy()
    }

    /** A real background transition discards this rendering realm. Only our own
     * SAF transition may keep a dormant page after its fixed cleanup handler ACK.
     * This event transfers no authority, cookies, key bytes or signing requests.
     */
    internal fun discardOnPause(ownedPicker: Boolean, stillPaused: () -> Boolean = { true }, onRetired: () -> Unit) {
        if (retired.get()) return
        val main = Handler(Looper.getMainLooper())
        val settled = AtomicBoolean()
        fun settle(cleaned: Boolean) {
            if (settled.compareAndSet(false, true) && !retired.get()) {
                if (!ownedPicker || !cleaned) { close(); onRetired() }
                else if (stillPaused()) {
                    onPause()
                    // This owner screen mounts the app's single WebView. Timers are
                    // process-wide; always restore them on resume/realm disposal.
                    if (timersPaused.compareAndSet(false, true)) pauseTimers()
                }
            }
        }
        if (ownedPicker) {
            pickerExpiresElapsed = Math.addExact(SystemClock.elapsedRealtime(), 120_000)
            pickerDeadline?.let(pageHandler::removeCallbacks)
            pickerDeadline = Runnable { if (!retired.get() && pickerExpiresElapsed != 0L) { close(); onRetired() } }
            pageHandler.postDelayed(checkNotNull(pickerDeadline), 120_000)
        }
        val deadline = Runnable { settle(false) }
        if (ownedPicker) main.postDelayed(deadline, 500)
        try {
            evaluateJavascript("(function(){if(window.ZtOwnerCustodyPauseReady!==true)return false;window.dispatchEvent(new Event('zrotext-owner-custody-pause'));return true;})()") {
                main.removeCallbacks(deadline); settle(it == "true")
            }
        } catch (_: Exception) { settle(false) }
        if (!ownedPicker) settle(false)
    }

    internal fun resumeAfterPicker(): Boolean {
        if (retired.get()) return false
        if (pickerExpiresElapsed != 0L && SystemClock.elapsedRealtime() >= pickerExpiresElapsed) { close(); return false }
        pickerDeadline?.let(pageHandler::removeCallbacks); pickerDeadline = null; pickerExpiresElapsed = 0
        if (timersPaused.getAndSet(false)) resumeTimers()
        onResume(); return true
    }

    companion object {
        internal fun importPurpose(mode: Int, capture: Boolean, accepts: Array<String>): Int {
            if (mode != WebChromeClient.FileChooserParams.MODE_OPEN || capture) return 0
            if (accepts.contentEquals(arrayOf(AndroidOwnerCustodyArchiveImportProvider.MIME))) return 2
            return if (accepts.none { it == AndroidOwnerCustodyArchiveImportProvider.MIME }) 1 else 0
        }

        internal fun allowed(origin: String, target: String): Boolean {
            val expected = origin.toHttpUrlOrNull() ?: return false
            val selected = target.toHttpUrlOrNull() ?: return false
            return selected.scheme == "https" && selected.host == expected.host && selected.port == expected.port &&
                selected.username.isEmpty() && selected.password.isEmpty()
        }

        /** Only bounded encrypted/public ceremony files, never a recovery token or raw root.
         * Full identity, grammar and signature verification remain ceremony obligations.
         */
        internal fun publicImport(input: InputStream): Boolean {
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (true) {
                val count = input.read(buffer, 0, minOf(buffer.size, 20_481 - out.size()))
                if (count == -1) break
                if (count <= 0 || out.size() + count > 20_480) return false
                out.write(buffer, 0, count)
            }
            val bytes = out.toByteArray()
            // A 64-character plaintext scalar is not a binary public signature.
            if (bytes.size == 64) return !bytes.all { it.toInt().toChar() in "0123456789abcdefABCDEF" }
            if (bytes.size == 65) return bytes[0] == 4.toByte()
            if (bytes.size in 296..512) {
                val text = bytes.toString(Charsets.US_ASCII)
                if (text.matches(Regex("Enrollment signature: [0-9a-f]{128}\\r?\\nCustody signature: [0-9a-f]{128}\\r?\\n?"))) return true
            }
            if (bytes.size < 5) return false
            val magic = bytes.copyOfRange(0, 4).toString(Charsets.US_ASCII)
            val version = bytes[4].toInt()
            return when (magic) {
                "ZTRB" -> version == 1 && bytes.size in 237..748
                "ZTRC" -> version == 1 && bytes.size in 134..645
                "ZTAB" -> version == 1 && bytes.size in 334..845
                "ZTPK" -> version == 1 && bytes.size == 223
                "ZTRE" -> version == 1 && bytes.size in 152..663
                "ZTMA" -> version == 2 && bytes.size in 218..16_384
                "ZTCG", "ZTCA", "ZTCF" -> version == 1 && bytes.size in 152..20_480
                else -> false
            }
        }

        internal fun readPublicBytes(input: InputStream): ByteArray? {
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            try {
                while (true) {
                    val count = input.read(buffer, 0, minOf(buffer.size, 20_481 - out.size()))
                    if (count == -1) break
                    if (count <= 0 || out.size() + count > 20_480) return null
                    out.write(buffer, 0, count)
                }
                val bytes = out.toByteArray()
                if (publicImport(ByteArrayInputStream(bytes))) return bytes
                bytes.fill(0); return null
            } finally { buffer.fill(0) }
        }
    }
}

private class AndroidOwnerArchiveInputGrant(val kit: AndroidOwnerCustodyArchiveKit,
    val authority: AndroidOwnerCustodyAuthority, val callback: ValueCallback<Array<Uri>>) {
    val identity get() = kit.identity.root
}

/** Deliberately opened login/owner surface. Closing never implies logout or signing approval. */
@Composable
internal fun AndroidOwnerCustodyOwnerWebView(origin: String, onClose: () -> Unit,
    onSessionChanged: () -> Unit = {}, visible: Boolean = true, modifier: Modifier = Modifier,
    archiveKit: () -> AndroidOwnerCustodyArchiveKit? = { null },
    ownerContext: AndroidOwnerCustodyOwnerContext? = null,
    verifyArchiveRecovery: (AndroidOwnerCustodyArchiveKit, ByteArray) -> Boolean = { _, _ -> false },
    onRetire: () -> Unit = {}) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scope = rememberCoroutineScope()
    val updatedChanged = rememberUpdatedState(onSessionChanged)
    val updatedArchiveKit = rememberUpdatedState(archiveKit)
    val updatedArchiveProof = rememberUpdatedState(verifyArchiveRecovery)
    val updatedRetire = rememberUpdatedState(onRetire)
    val importOwner = remember(origin) { UUID.randomUUID() }
    val epoch = remember(origin) { AtomicLong() }
    val disposed = remember(origin) { AtomicBoolean() }
    val resumed = remember(origin) { AtomicBoolean(lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
    val main = remember(origin) { Handler(Looper.getMainLooper()) }
    val worker = remember(origin) { Executors.newSingleThreadExecutor() }
    var chooser by remember(origin) { mutableStateOf<ValueCallback<Array<Uri>>?>(null) }
    var archiveConsent by remember(origin) { mutableStateOf<AndroidOwnerArchiveInputGrant?>(null) }
    var archivePending by remember(origin) { mutableStateOf<AndroidOwnerArchiveInputGrant?>(null) }
    var archiveRequest by remember(origin) { mutableStateOf<ValueCallback<Array<Uri>>?>(null) }
    var awaitingArchivePicker by remember(origin) { mutableStateOf(false) }
    fun clearStaged() {
        AndroidOwnerCustodyPublicImportProvider.clear(importOwner)
        AndroidOwnerCustodyArchiveImportProvider.clear(importOwner)
    }
    fun cancelArchive() {
        archiveRequest?.onReceiveValue(null); archiveRequest = null
        archiveConsent = null; archivePending = null
        awaitingArchivePicker = false
    }
    fun stillApproved(grant: AndroidOwnerArchiveInputGrant): Boolean = runCatching {
        val current = checkNotNull(updatedArchiveKit.value())
        current.identity == grant.kit.identity && current.digest == grant.kit.digest && current.backupId == grant.kit.backupId
    }.getOrDefault(false)
    val archivePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val grant = archivePending
        awaitingArchivePicker = false
        if (grant != null) scope.launch {
            // Activity results may arrive in STARTED: authenticate only after native UI resumes.
            lifecycle.withStateAtLeast(Lifecycle.State.RESUMED) {
                resumed.set(true)
                val ticket = epoch.get()
                worker.execute {
                    val staged = runCatching {
                        check(!disposed.get() && resumed.get() && epoch.get() == ticket && uri?.scheme == "content")
                        val currentKit = checkNotNull(updatedArchiveKit.value())
                        require(currentKit.identity == grant.kit.identity && currentKit.digest == grant.kit.digest &&
                            currentKit.backupId == grant.kit.backupId && grant.identity.origin == origin)
                        val authority = checkNotNull(ownerContext).refresh(grant.identity)
                        require(grant.authority.sameSession(authority))
                        val bytes = checkNotNull(context.contentResolver.openInputStream(checkNotNull(uri)))
                            .use(AndroidOwnerCustodyArchiveImportProvider::readExact)
                        try {
                            check(!disposed.get() && resumed.get() && epoch.get() == ticket)
                            require(authority.sameSession(checkNotNull(ownerContext.currentAuthority())))
                            AndroidOwnerCustodyArchiveImportProvider.stage(context, importOwner, bytes, verify = { proof ->
                                if (!updatedArchiveProof.value(grant.kit, proof)) false else {
                                    val after = ownerContext.refresh(grant.identity)
                                    require(grant.authority.sameSession(after) && stillApproved(grant))
                                    true
                                }
                            }, available = {
                                !disposed.get() && resumed.get() && epoch.get() == ticket &&
                                    ownerContext.currentAuthority()?.let(authority::sameSession) == true && stillApproved(grant)
                            })
                        } finally { bytes.fill(0) }
                    }.getOrNull()
                    main.post {
                        if (archivePending === grant) {
                            archivePending = null
                            val valid = staged != null && !disposed.get() && resumed.get() && epoch.get() == ticket &&
                                ownerContext?.currentAuthority()?.let(grant.authority::sameSession) == true && stillApproved(grant)
                            if (!valid) clearStaged()
                            archiveRequest = null
                            grant.callback.onReceiveValue(if (valid) arrayOf(checkNotNull(staged)) else null)
                        } else clearStaged()
                    }
                }
            }
        }
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val callback = chooser; chooser = null
        val staged = if (callback == null || uri?.scheme != "content") null else runCatching {
            context.contentResolver.openInputStream(uri)?.use(AndroidOwnerCustodyOwnerBrowser::readPublicBytes)?.let { bytes ->
                try { AndroidOwnerCustodyPublicImportProvider.stage(context, importOwner, bytes) }
                finally { bytes.fill(0) }
            }
        }.getOrNull()
        callback?.onReceiveValue(staged?.let { arrayOf(it) })
    }
    val browser = remember(origin) {
        AndroidOwnerCustodyOwnerBrowser(context, origin, {
            epoch.incrementAndGet(); clearStaged()
            main.post { if (!disposed.get()) { cancelArchive(); updatedChanged.value() } }
        }, choosePublicFile = { callback ->
            chooser?.onReceiveValue(null); chooser = callback
            try { picker.launch(arrayOf("application/octet-stream", "text/plain")) }
            catch (_: Exception) { chooser = null; callback.onReceiveValue(null) }
        }, chooseArchiveFile = { callback ->
            cancelArchive(); clearStaged()
            archiveRequest = callback
            val ticket = epoch.incrementAndGet()
            worker.execute {
                val grant = runCatching {
                    check(!disposed.get() && resumed.get() && epoch.get() == ticket)
                    val selectedKit = checkNotNull(updatedArchiveKit.value())
                    val identity = selectedKit.identity.root
                    require(identity.origin == origin)
                    val authority = checkNotNull(ownerContext).refresh(identity)
                    AndroidOwnerArchiveInputGrant(selectedKit, authority, callback)
                }.getOrNull()
                main.post {
                    if (archiveRequest === callback) {
                        if (grant != null && !disposed.get() && resumed.get() && epoch.get() == ticket) archiveConsent = grant
                        else cancelArchive()
                    }
                }
            }
        })
    }
    DisposableEffect(browser, lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                resumed.set(true)
                if (!browser.resumeAfterPicker()) updatedRetire.value()
            }
            if (event == Lifecycle.Event.ON_PAUSE) {
                resumed.set(false); epoch.incrementAndGet(); clearStaged()
                // The picker has no private grant. Its return must freshly authenticate again.
                if (!awaitingArchivePicker) cancelArchive()
                browser.discardOnPause(awaitingArchivePicker || chooser != null, { !resumed.get() }) { updatedRetire.value() }
            }
        }
        lifecycle.addObserver(observer)
        onDispose {
            disposed.set(true); epoch.incrementAndGet(); resumed.set(false)
            chooser?.onReceiveValue(null); chooser = null; cancelArchive(); clearStaged()
            lifecycle.removeObserver(observer); worker.shutdownNow(); browser.close()
        }
    }
    archiveConsent?.let { grant ->
        AlertDialog(onDismissRequest = { cancelArchive() },
            title = { Text("Send separate archive recovery key?") },
            text = { Text("Sending this separate archive recovery key permits $origin and this browser to decrypt the ENTIRE ACCOUNT archive. The subsequent browser checkbox is additional consent; the key already grants decryption authority. Native AEAD recovery must verify the selected bytes before delivery.\nAccount: ${grant.identity.account}\nOwner session: ${grant.authority.session}\nRoot fingerprint: ${grant.identity.fingerprint}\nArchive key ID: ${grant.kit.identity.keyId}\nArchive point: ${grant.kit.identity.point}\nArchive backup ID: ${grant.kit.backupId}\nEncrypted archive SHA256: ${grant.kit.digest}\nChoose only the separate archive key.", modifier = Modifier.heightIn(max = 320.dp).verticalScroll(rememberScrollState())) },
            dismissButton = { Button({ cancelArchive() }) { Text("Cancel") } },
            confirmButton = { Button({
                archiveConsent = null; archivePending = grant
                val ticket = epoch.get()
                worker.execute {
                    val valid = runCatching {
                        val authority = checkNotNull(ownerContext).refresh(grant.identity)
                        require(grant.authority.sameSession(authority) && stillApproved(grant))
                        check(!disposed.get() && resumed.get() && epoch.get() == ticket)
                    }.isSuccess
                    main.post {
                        if (valid && archivePending === grant && !disposed.get() && resumed.get() && epoch.get() == ticket) {
                            awaitingArchivePicker = true
                            try { archivePicker.launch(arrayOf(AndroidOwnerCustodyArchiveImportProvider.MIME)) }
                            catch (_: Exception) { cancelArchive() }
                        } else if (archivePending === grant) cancelArchive()
                    }
                }
            }) { Text("Choose separate archive key") } })
    }
    Column {
        if (visible) {
            Text("Owner sign-in at $origin. Native recovery and signing approval remain separate.")
            Button(onClick = onClose) { Text("Return to native owner setup") }
        }
        // Keep the same page/ephemeral browser approval key alive while native UI overlays it.
        // GONE can trigger document.visibilitychange and close the browser ceremony.
        AndroidView(factory = { browser }, update = {
            it.alpha = if (visible) 1f else 0f; it.isEnabled = visible
            it.importantForAccessibility = if (visible) View.IMPORTANT_FOR_ACCESSIBILITY_AUTO else View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
        }, modifier = modifier.fillMaxWidth().heightIn(min = 360.dp, max = 560.dp))
    }
}
