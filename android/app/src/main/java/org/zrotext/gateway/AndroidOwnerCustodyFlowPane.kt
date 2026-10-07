// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

/** Mounted inside the secure owner pane. Only public proposals/identities remain as UI state.
 * Separate private archive recovery is read/written directly through explicit SAF destinations.
 */
@Composable internal fun AndroidOwnerCustodyFlowPane(
    state: AndroidOwnerCustodyController.Snapshot, controller: AndroidOwnerCustodyController,
    independent: () -> AndroidOwnerCustodyIdentity,
    context: AndroidOwnerCustodyOwnerContext,
    typedContext: AndroidOwnerCustodyFlowContextProvider,
    action: (() -> Unit) -> Unit,
    takeFreshToken: () -> ByteArray,
    notice: (String) -> Unit,
    export: (String, ByteArray) -> Unit
) {
    val android = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val enabled = state.available && !state.busy
    var kind by remember { mutableStateOf(AndroidOwnerCustodyFlowKind.LINE) }
    var publicText by remember { mutableStateOf("") }
    var consent by remember { mutableStateOf(false) }
    var archiveRetained by remember { mutableStateOf(false) }
    var archiveConsent by remember { mutableStateOf(false) }
    var recoveryDestination by remember { mutableStateOf<Uri?>(null) }
    var archiveSource by remember { mutableStateOf<Uri?>(null) }
    var archiveRecoverySource by remember { mutableStateOf<Uri?>(null) }
    var keyId by remember { mutableStateOf("") }
    var point by remember { mutableStateOf("") }
    var device by remember { mutableStateOf("") }
    var line by remember { mutableStateOf("") }
    var generation by remember { mutableStateOf("") }
    var peer by remember { mutableStateOf("") }
    var pairedFingerprint by remember { mutableStateOf("") }
    var checkpointVersion by remember { mutableStateOf("") }
    var checkpointDigest by remember { mutableStateOf("") }
    var phoneFingerprint by remember { mutableStateOf("") }
    var phoneExportSource by remember { mutableStateOf<Uri?>(null) }
    val reviewed = remember { AtomicReference<Pair<ByteArray, AndroidOwnerCustodyFlowSelection>?>(null) }
    fun revoke() { consent = false; archiveRetained = false; archiveConsent = false; reviewed.set(null) }
    fun scopeChanged() { controller.cancel(); revoke() }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_PAUSE || event == Lifecycle.Event.ON_STOP || event == Lifecycle.Event.ON_DESTROY) revoke()
        }
        lifecycle.addObserver(observer)
        onDispose { revoke(); lifecycle.removeObserver(observer) }
    }
    val destination = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        recoveryDestination = uri; revoke()
        notice(if (uri == null) "Separate archive recovery destination cancelled. No archive was created."
        else "Separate private archive recovery destination selected. The file is empty until separately approved creation; selecting it is not a backup or recovery proof. Freshly recover the root after returning from the picker.")
    }
    val archivePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> archiveSource = uri; revoke() }
    val recoveryPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> archiveRecoverySource = uri; revoke() }
    val phonePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> phoneExportSource = uri; revoke() }
    Text("Line, archive and reader authority", style = MaterialTheme.typography.titleMedium)
    Text("Keep the same owner browser page open while reviewing a public proposal here. A live original owner session and authoritative current public context are required. Imported JSON or a phone device session supplies no authority. Each operation uses separate consent and a freshly entered root token.")
    for (operation in AndroidOwnerCustodyFlowKind.entries) Button({
        kind = operation; publicText = ""; revoke(); controller.cancel()
    }, enabled = enabled, modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text(if (kind == operation) "Selected: ${operation.label}" else operation.label) }
    if (kind != AndroidOwnerCustodyFlowKind.ARCHIVE) OutlinedTextField(publicText, {
        if (it.length <= 27308) { publicText = it; scopeChanged() }
    }, enabled = enabled, label = { Text("Paste exact typed PUBLIC proposal base64") }, modifier = Modifier.fillMaxWidth())
    if (kind != AndroidOwnerCustodyFlowKind.ARCHIVE) {
        Text("Independently select the paired device, line, generation and peer. Use your accepted manifest checkpoint; genesis uses version 0 and a digest of 64 zeroes. Imported proposal text never fills these fields.")
        for ((label, value, setter) in listOf(
            Triple("Independent paired device UUID", device, { v: String -> device = v }),
            Triple("Independent line UUID", line, { v: String -> line = v }),
            Triple("Independent binding generation", generation, { v: String -> generation = v }),
            Triple("Independent exact peer", peer, { v: String -> peer = v }),
            Triple("Independent paired phone signing fingerprint", pairedFingerprint, { v: String -> pairedFingerprint = v }),
            Triple("Independent accepted predecessor version", checkpointVersion, { v: String -> checkpointVersion = v }),
            Triple("Independent accepted predecessor digest", checkpointDigest, { v: String -> checkpointDigest = v })
        )) OutlinedTextField(value, { setter(it); scopeChanged() }, enabled = enabled, label = { Text(label) }, modifier = Modifier.fillMaxWidth())
        if (kind == AndroidOwnerCustodyFlowKind.GENESIS) {
            OutlinedTextField(phoneFingerprint, { phoneFingerprint = it; scopeChanged() }, enabled = enabled,
                label = { Text("Phone export fingerprint compared directly on the phone") }, modifier = Modifier.fillMaxWidth())
            Button({ phonePicker.launch(arrayOf("application/octet-stream")) }, enabled = enabled,
                modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text(if (phoneExportSource == null) "Import independent public phone key export" else "Replace independent public phone key export") }
        }
    }
    if (kind == AndroidOwnerCustodyFlowKind.ARCHIVE) {
        Text("Archive creation generates a NEW independent high-entropy 32-byte recovery file. Choose its separate private destination before recovery/review. Keep it apart from the encrypted archive and public receipt. Anyone with both files can decrypt the account archive. This file is deliberately exported privately; the root token is never reused or exported.")
        Button({ destination.launch("separate-private-archive-recovery.bin") }, enabled = enabled,
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text(if (recoveryDestination == null) "Choose separate private archive recovery destination" else "Replace private archive recovery destination") }
        Text("I approve writing the new PRIVATE archive recovery material to that separate destination once. Destination selection alone does not mean I retained it.")
        Checkbox(archiveConsent, { archiveConsent = it }, enabled = enabled && recoveryDestination != null)
    }
    Button({
        consent = false
        val selected = kind; val candidateText = publicText
        val selectedDevice = device; val selectedLine = line; val selectedGeneration = generation; val selectedPeer = peer
        val selectedPaired = pairedFingerprint; val selectedVersion = checkpointVersion; val selectedDigest = checkpointDigest
        val selectedPhoneSource = phoneExportSource; val selectedPhoneFingerprint = phoneFingerprint
        action {
            val identity = independent()
            val authority = context.refresh(identity)
            val proposal = if (selected == AndroidOwnerCustodyFlowKind.ARCHIVE) byteArrayOf() else decodeAndroidOwnerPublicProposal(candidateText, selected.maximum)
            val independentSelection = if (selected == AndroidOwnerCustodyFlowKind.ARCHIVE) null else {
                fun uuid(text: String) = UUID.fromString(text).also { require(it.toString() == text) }
                val exportedPhone = if (selected == AndroidOwnerCustodyFlowKind.GENESIS) android.contentResolver.openInputStream(checkNotNull(selectedPhoneSource)).use {
                    readAndroidOwnerCustodyFile(checkNotNull(it), 223).also { bytes -> require(bytes.size == 223) }
                } else null
                AndroidOwnerCustodyFlowSelection(uuid(selectedDevice), uuid(selectedLine), selectedGeneration.toLong(), selectedPeer,
                    selectedPaired, selectedVersion.toLong(), selectedDigest, exportedPhone, selectedPhoneFingerprint)
            }
            val expected = if (selected == AndroidOwnerCustodyFlowKind.ARCHIVE)
                createAndroidOwnerArchiveContext(controller.publicRootPin(), identity, authority)
            else typedContext.current(selected, proposal, identity, checkNotNull(independentSelection))
            controller.reviewTyped(selected, proposal, expected, identity)
            if (independentSelection != null) reviewed.set(proposal.copyOf() to independentSelection)
        }
    }, enabled = enabled && state.recoveryVerified && (kind != AndroidOwnerCustodyFlowKind.ARCHIVE || recoveryDestination != null),
        modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Fetch current owner context and review exact typed operation") }
    state.flowReview?.let { review ->
        SelectionContainer { Text(review.disclosure()) }
        Text("I approve ONLY this exact ${review.kind.label} operation once. Body transfer, account-wide browser archive decryption, line MFA, server acceptance and phone installation acknowledgment remain separate.")
        Checkbox(consent, { consent = it }, enabled = enabled)
        Button({
            val approval = consent; consent = false
            val privateDestination = recoveryDestination; val privateApproval = archiveConsent; archiveConsent = false
            val restoredSource = archiveRecoverySource
            action {
                val identity = independent()
                context.refresh(identity) // Read no token before this potentially blocking live check.
                val selectedContext = if (review.kind != AndroidOwnerCustodyFlowKind.ARCHIVE) checkNotNull(reviewed.get()) else null
                if (review.kind != AndroidOwnerCustodyFlowKind.ARCHIVE) {
                    val current = checkNotNull(selectedContext)
                    controller.requireCurrentTypedContext(typedContext.current(review.kind, current.first, identity, current.second))
                }
                val rootToken = takeFreshToken()
                var separate = byteArrayOf()
                try {
                    if (review.kind == AndroidOwnerCustodyFlowKind.GENESIS) {
                        separate = android.contentResolver.openInputStream(checkNotNull(restoredSource)).use {
                            readAndroidOwnerArchiveRecoveryFile(checkNotNull(it))
                        }
                    }
                    controller.signTyped(rootToken, separate, approval,
                        postContextCheck = selectedContext?.let { checked -> {
                            typedContext.current(review.kind, checked.first, identity, checked.second)
                        } },
                        privateArchiveExport = if (review.kind == AndroidOwnerCustodyFlowKind.ARCHIVE) { _, privateBytes, permitted ->
                            require(privateApproval && privateDestination != null && permitted())
                            android.contentResolver.openOutputStream(privateDestination, "wt").use { output ->
                                check(permitted()); checkNotNull(output).write(privateBytes); output.flush()
                            }
                            check(permitted())
                            val retained = android.contentResolver.openInputStream(privateDestination).use {
                                readAndroidOwnerArchiveRecoveryFile(checkNotNull(it))
                            }
                            try { require(retained.contentEquals(privateBytes)); permitted() } finally { retained.fill(0) }
                        } else null)
                } finally { rootToken.fill(0); separate.fill(0) }
            }
        }, enabled = enabled && consent && (review.kind != AndroidOwnerCustodyFlowKind.ARCHIVE || archiveConsent && recoveryDestination != null),
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Approve typed operation with fresh root recovery") }
    }
    state.publicArtifact?.let { public ->
        Text("Signed PUBLIC response base64. Manually select/copy this public text back into the same browser page; no clipboard access is automatic.")
        SelectionContainer { Text(Base64.getEncoder().encodeToString(public)) }
        Button({ export("owner-typed-public-response.bin", public.copyOf()) }, enabled = enabled,
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Save signed public response file") }
    }
    state.archiveIdentity?.let {
        val public = runCatching { controller.approvedBrowserArchive(it.root) }.getOrNull()
        Text("Archive account: ${it.root.account}\nArchive origin: ${it.root.origin}\nIndependent archive key ID: ${it.keyId}\nIndependent archive point: ${it.point}\nEncrypted archive backup ID: ${public?.backupId}\nEncrypted archive SHA256: ${public?.digest}")
    }
    if (state.archiveCanExport) {
        Button({ export("encrypted-account-archive.ztab", controller.encryptedArchive()) }, enabled = enabled,
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Save encrypted archive backup separately") }
        Button({ export("public-archive-receipt.txt", controller.archiveReceipt()) }, enabled = enabled,
            modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Save separate public archive receipt") }
    }
    Text("Fresh independent archive recovery", style = MaterialTheme.typography.titleMedium)
    Text("Import externally retained ciphertext and the separate private raw32 recovery file, and independently enter the archive key ID and point from your separate receipt. Public header/digest comparison alone is not recovery. File pickers close current native review; recover the root after returning, then run this archive check before genesis.")
    OutlinedTextField(keyId, { keyId = it; controller.cancel(); revoke() }, enabled = enabled, label = { Text("Independent archive key ID (64 lowercase hex)") }, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(point, { point = it; controller.cancel(); revoke() }, enabled = enabled, label = { Text("Independent archive point SEC1 (130 lowercase hex)") }, modifier = Modifier.fillMaxWidth())
    Button({ archivePicker.launch(arrayOf("application/octet-stream")) }, enabled = enabled,
        modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text(if (archiveSource == null) "Import retained encrypted archive" else "Replace retained encrypted archive") }
    Button({ recoveryPicker.launch(arrayOf("application/octet-stream")) }, enabled = enabled,
        modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text(if (archiveRecoverySource == null) "Select separately retained PRIVATE archive recovery file" else "Replace separate PRIVATE archive recovery file") }
    Text("I independently retained these separate archive files and compared the archive identity from my retained receipt.")
    Checkbox(archiveRetained, { archiveRetained = it }, enabled = enabled)
    Button({
        val selectedArchive = archiveSource; val selectedRecovery = archiveRecoverySource
        val independentlyRetained = archiveRetained; val independentId = keyId; val independentPoint = point
        action {
            val identity = AndroidOwnerCustodyArchiveIdentity(independent(), independentId, independentPoint)
            val backup = android.contentResolver.openInputStream(checkNotNull(selectedArchive)).use { readAndroidOwnerCustodyFile(checkNotNull(it), 845) }
            val recovery = android.contentResolver.openInputStream(checkNotNull(selectedRecovery)).use { readAndroidOwnerArchiveRecoveryFile(checkNotNull(it)) }
            try { controller.recoverArchive(backup, recovery, identity, independentlyRetained) } finally { recovery.fill(0) }
        }
    }, enabled = enabled && state.recoveryVerified && archiveRetained && archiveSource != null && archiveRecoverySource != null,
        modifier = Modifier.fillMaxWidth().sizeIn(minHeight = 48.dp)) { Text("Run fresh separate archive AEAD recovery check") }
    Text(if (state.archiveRecoveryVerified) "Archive recoverability verified for the independently selected identity. Browser decryption permission is still separate." else "Archive recovery is unverified. Creation, export and header comparison do not make it ready.")
}
