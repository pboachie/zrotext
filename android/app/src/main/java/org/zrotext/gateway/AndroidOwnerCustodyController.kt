// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

/** Supplied only by an HTTPS authenticated OWNER-session adapter, never from a file or wall clock.
 * A phone device bearer and an owner browser session are different authorities.
 */
internal data class AndroidOwnerCustodyAuthority(val account: UUID, val user: UUID, val session: UUID,
    val utcMs: Long, val anchoredElapsedMs: Long, val uncertaintyMs: Long) {
    init {
        require(listOf(account, user, session).all { it != UUID(0, 0) })
        require(utcMs > 0 && anchoredElapsedMs >= 0 && uncertaintyMs in 0..2000)
    }
    fun bytes(value: UUID): ByteArray = ByteBuffer.allocate(16).putLong(value.mostSignificantBits).putLong(value.leastSignificantBits).array()
    fun sameSession(other: AndroidOwnerCustodyAuthority) = account == other.account && user == other.user && session == other.session
    override fun toString() = "AndroidOwnerCustodyAuthority(authenticated)"
}

/** Native-reviewed enrollment/custody only; these are the bytes native will sign once. */
internal data class AndroidOwnerCustodyReview(val account: UUID, val user: UUID, val session: UUID,
    val challengeId: UUID, val origin: String, val fingerprint: String, val issuedMs: Long, val expiresMs: Long) {
    companion object {
        fun parse(bytes: ByteArray): AndroidOwnerCustodyReview {
            require(bytes.size in 152..663 && bytes.copyOfRange(0, 5).contentEquals(byteArrayOf(90, 84, 82, 69, 1)))
            val length = ByteBuffer.wrap(bytes, 149, 2).short.toInt() and 65535
            require(length in 1..512 && bytes.size == 151 + length)
            fun uuid(at: Int): UUID { val b = ByteBuffer.wrap(bytes, at, 16); return UUID(b.long, b.long).also { require(it != UUID(0, 0)) } }
            val origin = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes, 151, length)).toString()
            val issued = ByteBuffer.wrap(bytes, 133, 8).long; val expires = ByteBuffer.wrap(bytes, 141, 8).long
            require(issued > 0 && expires > issued && expires - issued <= 300000)
            val result = AndroidOwnerCustodyReview(uuid(5), uuid(21), uuid(37), uuid(53), origin,
                AndroidOwnerCustodyKit.hex(bytes.copyOfRange(101, 133)), issued, expires)
            AndroidOwnerCustodyIdentity(result.account, origin, result.fingerprint)
            return result
        }
    }
}

/** Process-only ceremony. Persisted bytes contain only ciphertext and public identity.
 * Fresh recovery reads independently imported files and executes a separate native AEAD check.
 * Success establishes kit recoverability, never server enrollment or phone/content authority.
 */
internal class AndroidOwnerCustodyController(
    private val native: AndroidOwnerCustodyNativePort, private val store: AndroidOwnerCustodyKitStore,
    private val elapsed: () -> Long,
    private val authority: () -> AndroidOwnerCustodyAuthority? = { null },
    private val postSignAuthority: () -> AndroidOwnerCustodyAuthority? = authority,
    private val changed: (Snapshot) -> Unit = {}
) : AutoCloseable {
    data class Snapshot(val available: Boolean, val busy: Boolean = false, val identity: AndroidOwnerCustodyIdentity? = null,
        val backupId: UUID? = null,
        val exported: Boolean = false, val recoveryVerified: Boolean = false, val canReveal: Boolean = false,
        val canExportKit: Boolean = false,
        val review: AndroidOwnerCustodyReview? = null, val publicSignatures: String? = null,
        val flowReview: AndroidOwnerCustodyFlowReview? = null, val publicArtifact: ByteArray? = null,
        val archiveIdentity: AndroidOwnerCustodyArchiveIdentity? = null, val archiveRecoveryVerified: Boolean = false,
        val archiveCanExport: Boolean = false,
        val status: String = "Create or independently recover an owner kit. Enrollment is a separate ceremony.")
    private val gate = Any()
    private val epoch = AtomicLong(0)
    private var closed = false
    private var state = Snapshot(native.available, status = if (native.available)
        "Create or independently recover an owner kit. Enrollment is a separate ceremony." else
        "Native owner custody is unavailable in this build. No owner authority was created.")
    private var kit: AndroidOwnerCustodyKit? = null
    private var revealToken: ByteArray? = null
    private var revealDeadline = 0L
    private var exposedDeadline = 0L
    private var handle = 0L
    private var typedHandle = false
    private var typedExpected: ByteArray? = null
    private var archiveKit: AndroidOwnerCustodyArchiveKit? = null
    private var reviewedAuthority: AndroidOwnerCustodyAuthority? = null
    fun snapshot(): Snapshot = synchronized(gate) { state.copy(publicArtifact = state.publicArtifact?.copyOf()) }
    private fun publish() = changed(snapshot())
    private fun valid(ticket: Long) = synchronized(gate) { !closed && epoch.get() == ticket }
    private fun start(resetRecovery: Boolean = true): Long = synchronized(gate) {
        check(!closed && native.available && !state.busy)
        clearOperation()
        val ticket = epoch.incrementAndGet()
        state = state.copy(busy = true, recoveryVerified = if (resetRecovery) false else state.recoveryVerified,
            canReveal = false, review = null, publicSignatures = null, flowReview = null, publicArtifact = null)
        ticket
    }.also { publish() }
    private fun clearOperation() {
        val old = handle; handle = 0; reviewedAuthority = null; typedHandle = false; typedExpected = null
        revealToken?.fill(0); revealToken = null; revealDeadline = 0
        exposedDeadline = 0
        if (old > 0) native.close(old)
    }
    private fun finish(ticket: Long, update: (Snapshot) -> Snapshot) {
        synchronized(gate) { check(valid(ticket)); state = update(state).copy(busy = false) }
        publish()
    }
    private fun failed(ticket: Long) {
        synchronized(gate) {
            if (!valid(ticket)) return
            clearOperation()
            state = state.copy(busy = false, recoveryVerified = false, canReveal = false, review = null,
                publicSignatures = null, flowReview = null, publicArtifact = null, archiveRecoveryVerified = false,
                status = "Owner custody action failed or its outcome is unconfirmed. Independently recover before continuing.")
        }
        publish()
    }
    fun create(account: UUID, origin: String) {
        val ticket = start()
        var result: Array<ByteArray>? = null
        try {
            AndroidOwnerCustodyIdentity.validateAccountOrigin(account, origin)
            result = native.create(ByteBuffer.allocate(16).putLong(account.mostSignificantBits).putLong(account.leastSignificantBits).array(), origin)
            require(result.size == 5 && result[2].size == 79 && result[3].size == 32 && result[4].size == 94)
            val created = AndroidOwnerCustodyKit(result[0], result[1])
            require(created.identity.account == account && created.identity.origin == origin &&
                created.identity.fingerprintBytes().contentEquals(result[3]) && created.pin.contentEquals(result[4]))
            check(valid(ticket)); store.put(created) { valid(ticket) }; check(valid(ticket))
            synchronized(gate) {
                check(valid(ticket)); kit = created; revealToken = result[2].copyOf()
                revealDeadline = Math.addExact(elapsed(), 120000)
            }
            val bundle = ByteBuffer.wrap(created.bundleId); val backupId = UUID(bundle.long, bundle.long)
            finish(ticket) { it.copy(identity = created.identity, backupId = backupId, exported = false, recoveryVerified = false, canReveal = true, canExportKit = false,
                status = "Encrypted owner kit created. Save the backup and public card, separately retain the recovery token, then import your retained copies for a fresh recovery check.") }
        } catch (failure: Exception) { failed(ticket); throw failure }
        finally { result?.getOrNull(2)?.fill(0) }
    }
    /** Deliberate one-time reveal. UI uses FLAG_SECURE and provides no clipboard/export action. */
    fun reveal(): String {
        val value = synchronized(gate) {
            check(!closed && !state.busy)
            val token = checkNotNull(revealToken)
            try {
                require(elapsed() in 0 until revealDeadline)
                exposedDeadline = Math.addExact(elapsed(), 120000)
                String(token, Charsets.US_ASCII)
            } finally { token.fill(0); revealToken = null; revealDeadline = 0; state = state.copy(canReveal = false) }
        }
        publish(); return value
    }
    /** Explicit recorded-token acknowledgement; expiry/pause/cancel can never infer it. */
    fun confirmTokenRecorded() {
        synchronized(gate) {
            check(!closed && !state.busy && exposedDeadline > 0)
            require(elapsed() in 0 until exposedDeadline)
            exposedDeadline = 0
            state = state.copy(canExportKit = true,
                status = "You explicitly recorded the token separately. Now save the encrypted backup and public card, then independently check recovery.")
        }
        publish()
    }
    fun expireReveal() {
        synchronized(gate) {
            if (revealToken == null || elapsed() in 0 until revealDeadline) return
            revealToken?.fill(0); revealToken = null; revealDeadline = 0; state = state.copy(canReveal = false)
        }
        publish()
    }
    fun encryptedBackup(): ByteArray = synchronized(gate) { check(!closed && !state.busy && state.canExportKit); checkNotNull(kit).backup() }
    fun publicCard(): ByteArray = synchronized(gate) { check(!closed && !state.busy && state.canExportKit); checkNotNull(kit).card() }
    fun publicRootReceipt(): ByteArray = synchronized(gate) {
        check(!closed && !state.busy && state.canExportKit)
        val selected = checkNotNull(kit); val bundle = ByteBuffer.wrap(selected.bundleId)
        ("ZROtext owner root receipt v1\nAccount UUID: ${selected.identity.account}\nHTTPS origin: ${selected.identity.origin}\nRoot generation: 1\nRoot fingerprint: ${selected.identity.fingerprint}\nEncrypted backup UUID: ${UUID(bundle.long, bundle.long)}\nEncrypted backup SHA256: ${AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(selected.backup()))}\nRoot pin: ${AndroidOwnerCustodyKit.hex(selected.pin)}\nThis public receipt is not server enrollment or content-transfer authority.\n").toByteArray(Charsets.UTF_8)
    }
    fun exportReadback(bytes: ByteArray) {
        synchronized(gate) {
            check(!closed && !state.busy && state.canExportKit)
            require(bytes.contentEquals(checkNotNull(kit).backup()))
            state = state.copy(exported = true, recoveryVerified = false,
                status = "Encrypted backup destination readback matched. Retain the public card and token separately; import the retained files for a fresh recovery check.")
        }
        publish()
    }
    fun exportUnconfirmed() {
        synchronized(gate) { if (closed) return; state = state.copy(exported = false, recoveryVerified = false,
            status = "Encrypted backup export was cancelled or unconfirmed. This is not recovery-ready.") }
        publish()
    }
    /** The candidate is supplied from two external files, never silently loaded from app storage. */
    fun recover(backup: ByteArray, card: ByteArray, token: ByteArray,
        expected: AndroidOwnerCustodyIdentity, separatelyRetained: Boolean) {
        var ticket: Long? = null
        try {
            require(separatelyRetained)
            val imported = AndroidOwnerCustodyKit(backup, card)
            require(imported.identity == expected)
            val operation = start(); ticket = operation
            require(native.recoveryCheck(imported, token, expected))
            check(valid(operation)); store.put(imported) { valid(operation) }; check(valid(operation))
            synchronized(gate) { check(valid(operation)); kit = imported; if (archiveKit?.identity?.root != expected) archiveKit = null }
            val bundle = ByteBuffer.wrap(imported.bundleId); val backupId = UUID(bundle.long, bundle.long)
            finish(operation) { it.copy(identity = expected, backupId = backupId, canReveal = false, recoveryVerified = true, canExportKit = true,
                archiveIdentity = archiveKit?.identity, archiveRecoveryVerified = false, archiveCanExport = archiveKit != null,
                status = "Fresh native AEAD recovery verified the independently retained kit and root identity. Server enrollment, hardware phone keys, and content-transfer consent remain separate.") }
        } catch (failure: Exception) { if (ticket == null) cancel() else failed(ticket); throw failure }
        finally { token.fill(0) }
    }
    fun review(challenge: ByteArray, expected: AndroidOwnerCustodyIdentity) {
        val ticket = start(resetRecovery = false)
        var opened = 0L
        try {
            require(challenge.size in 152..663)
            val current = checkNotNull(authority()) { "Authenticated owner-session authority required" }
            require(current.account == expected.account)
            val selected = synchronized(gate) { check(state.recoveryVerified); checkNotNull(kit).also { require(it.identity == expected) } }
            check(valid(ticket)); opened = native.open(challenge, selected, expected, current, elapsed()); require(opened > 0)
            val exact = native.review(opened)
            require(exact.contentEquals(challenge))
            val review = AndroidOwnerCustodyReview.parse(exact)
            require(review.account == expected.account && review.origin == expected.origin && review.fingerprint == expected.fingerprint &&
                review.user == current.user && review.session == current.session)
            val refreshed = checkNotNull(authority()); require(current.sameSession(refreshed)); check(valid(ticket))
            synchronized(gate) { check(valid(ticket)); handle = opened; reviewedAuthority = current; opened = 0 }
            finish(ticket) { it.copy(review = review, canReveal = false,
                status = "Review this exact enrollment and encrypted-root custody proposal. A separate approval and fresh recovery token are required for this one operation.") }
        } catch (failure: Exception) { failed(ticket); throw failure }
        finally { if (opened > 0) native.close(opened) }
    }
    fun sign(token: ByteArray, approved: Boolean) {
        var ticket: Long? = null
        var signing = 0L
        try {
            require(approved)
            val prior = synchronized(gate) {
                check(!closed && !state.busy && state.review != null)
                signing = handle; handle = 0; check(signing > 0)
                val current = checkNotNull(reviewedAuthority); reviewedAuthority = null
                ticket = epoch.incrementAndGet(); state = state.copy(busy = true, review = null, publicSignatures = null)
                current
            }
            publish()
            val current = checkNotNull(authority()); require(prior.sameSession(current)); check(valid(checkNotNull(ticket)))
            val signatures = native.sign(signing, token, current, elapsed())
            token.fill(0) // Native already clears its input; no managed secret survives the live postcheck.
            require(signatures.size == 2 && signatures.all { it.size == 64 })
            check(valid(checkNotNull(ticket))); require(current.sameSession(checkNotNull(postSignAuthority())))
            val output = "Enrollment signature: ${AndroidOwnerCustodyKit.hex(signatures[0])}\nCustody signature: ${AndroidOwnerCustodyKit.hex(signatures[1])}\n"
            finish(checkNotNull(ticket)) { it.copy(publicSignatures = output,
                status = "One public signature response created. Import it in the existing owner browser ceremony; server acceptance and MFA are still required.") }
        } catch (failure: Exception) { if (ticket == null) cancel() else failed(ticket); throw failure }
        finally { token.fill(0); if (signing > 0) native.close(signing) }
    }
    fun reviewTyped(kind: AndroidOwnerCustodyFlowKind, proposal: ByteArray,
        independentContext: AndroidOwnerCustodyFlowExpected, expected: AndroidOwnerCustodyIdentity) {
        val ticket = start(resetRecovery = false); var opened = 0L
        try {
            require(proposal.size <= kind.maximum && (kind == AndroidOwnerCustodyFlowKind.ARCHIVE || proposal.isNotEmpty()))
            val current = checkNotNull(authority()); require(current.account == expected.account)
            val selected = synchronized(gate) { check(state.recoveryVerified); checkNotNull(kit).also { require(it.identity == expected) } }
            val expectedJson = independentContext.bytes()
            if (kind == AndroidOwnerCustodyFlowKind.GENESIS) {
                val restored = synchronized(gate) { check(state.archiveRecoveryVerified); checkNotNull(archiveKit) }
                val context = org.json.JSONObject(String(expectedJson, Charsets.UTF_8))
                require(restored.identity.root == expected && context.getString("archive_reader") == restored.identity.point &&
                    context.getString("archive_backup_sha256") == restored.digest)
            }
            check(valid(ticket)); opened = native.openTyped(kind.nativeKind, proposal, expectedJson, selected, expected, current, elapsed()); require(opened > 0)
            val exact = native.reviewTyped(opened)
            require(exact.size == 2 && exact[0].contentEquals(proposal) && exact[1].contentEquals(expectedJson))
            var shown = AndroidOwnerCustodyFlowReview.parse(kind, exact[0], exact[1])
            if (kind == AndroidOwnerCustodyFlowKind.ARCHIVE) shown = shown.copy(origin = expected.origin, user = current.user, session = current.session)
            require(shown.account == expected.account && shown.origin == expected.origin && shown.fingerprint == expected.fingerprint &&
                shown.session == current.session && (shown.user == null || shown.user == current.user))
            require(current.sameSession(checkNotNull(authority()))); check(valid(ticket))
            synchronized(gate) { check(valid(ticket)); handle = opened; typedHandle = true; typedExpected = expectedJson.copyOf(); reviewedAuthority = current; opened = 0 }
            finish(ticket) { it.copy(flowReview = shown,
                status = "Review the exact typed operation and current owner session. Separate one-shot approval and a freshly entered root recovery token are required.") }
        } catch (failure: Exception) { failed(ticket); throw failure }
        finally { if (opened > 0) native.close(opened) }
    }
    fun requireCurrentTypedContext(expected: AndroidOwnerCustodyFlowExpected) {
        try { synchronized(gate) { check(!closed && !state.busy && typedHandle && state.flowReview != null); require(checkNotNull(typedExpected).contentEquals(expected.bytes())) } }
        catch (failure: Exception) { cancel(); throw failure }
    }
    /** Private archive output can only go to an explicitly preselected separate owner destination.
     * The recovery material is never cached in this controller or persisted in app-private files.
     */
    fun signTyped(token: ByteArray, archiveRecovery: ByteArray, approved: Boolean,
        postContextCheck: (() -> AndroidOwnerCustodyFlowExpected)? = null,
        privateArchiveExport: ((AndroidOwnerCustodyArchiveKit, ByteArray, () -> Boolean) -> Boolean)? = null) {
        var ticket: Long? = null; var signing = 0L
        try {
            require(approved)
            val reviewed = synchronized(gate) {
                check(!closed && !state.busy && typedHandle)
                val review = checkNotNull(state.flowReview)
                if (review.kind != AndroidOwnerCustodyFlowKind.ARCHIVE) require(postContextCheck != null)
                if (review.kind == AndroidOwnerCustodyFlowKind.ARCHIVE) require(privateArchiveExport != null)
                if (review.kind == AndroidOwnerCustodyFlowKind.GENESIS) check(state.archiveRecoveryVerified && archiveRecovery.size == 32)
                else require(archiveRecovery.isEmpty())
                val expectedJson = checkNotNull(typedExpected).copyOf()
                signing = handle; handle = 0; typedHandle = false; typedExpected = null; check(signing > 0)
                val prior = checkNotNull(reviewedAuthority); reviewedAuthority = null
                ticket = epoch.incrementAndGet(); state = state.copy(busy = true, flowReview = null, publicArtifact = null)
                Triple(review, prior, expectedJson)
            }
            publish()
            val current = checkNotNull(authority()); require(reviewed.second.sameSession(current)); check(valid(checkNotNull(ticket)))
            val archive = synchronized(gate) { if (reviewed.first.kind == AndroidOwnerCustodyFlowKind.GENESIS) checkNotNull(archiveKit).backup() else byteArrayOf() }
            val output = native.signTyped(signing, token, archive, archiveRecovery, current, elapsed())
            token.fill(0); archiveRecovery.fill(0)
            try {
                val privateDeadline = Math.addExact(elapsed(), 120000)
                check(valid(checkNotNull(ticket))); require(current.sameSession(checkNotNull(postSignAuthority())))
                postContextCheck?.let { fetch ->
                    require(fetch().bytes().contentEquals(reviewed.third))
                    check(valid(checkNotNull(ticket))); require(current.sameSession(checkNotNull(authority())))
                }
                if (reviewed.first.kind == AndroidOwnerCustodyFlowKind.ARCHIVE) {
                    require(output.size == 5 && output[2].size == 32 && output[3].size == 32 && output[4].size == 65)
                    val root = synchronized(gate) { checkNotNull(kit).identity }
                    val identity = AndroidOwnerCustodyArchiveIdentity(root, AndroidOwnerCustodyKit.hex(output[3]), AndroidOwnerCustodyKit.hex(output[4]))
                    val created = AndroidOwnerCustodyArchiveKit(output[0], identity)
                    require(output[1].contentEquals(created.receipt()))
                    val operation = checkNotNull(ticket)
                    val permitted = { valid(operation) && elapsed() in 0 until privateDeadline }
                    require(checkNotNull(privateArchiveExport)(created, output[2], permitted))
                    check(permitted()); store.putArchive(created, permitted); check(permitted())
                    synchronized(gate) { check(valid(operation)); archiveKit = created }
                    finish(operation) { it.copy(archiveIdentity = identity, archiveCanExport = true, archiveRecoveryVerified = false,
                        status = "Separate encrypted archive kit created and private recovery destination readback confirmed. Save its encrypted backup and public receipt, then independently import the retained files to verify recovery. Creation is not archive-ready.") }
                } else {
                    require(output.size == 1)
                    if (reviewed.first.kind == AndroidOwnerCustodyFlowKind.LINE) require(output[0].size == 64)
                    else require(output[0].size in 364..9751)
                    val public = output[0].copyOf()
                    finish(checkNotNull(ticket)) { it.copy(publicArtifact = public,
                        status = "One typed public artifact created after a live owner-session postcheck. Browser verification, server acceptance, MFA where required, and separate phone consent/installation still apply.") }
                }
            } finally { output.forEach { it.fill(0) } }
        } catch (failure: Exception) { if (ticket == null) cancel() else failed(ticket); throw failure }
        finally { token.fill(0); archiveRecovery.fill(0); if (signing > 0) native.close(signing) }
    }
    fun recoverArchive(backup: ByteArray, recovery: ByteArray, independent: AndroidOwnerCustodyArchiveIdentity, retained: Boolean) {
        var ticket: Long? = null
        try {
            require(retained)
            require(recovery.size == 32 && recovery.any { it != 0.toByte() })
            val imported = AndroidOwnerCustodyArchiveKit(backup, independent)
            val operation = start(resetRecovery = false); ticket = operation
            synchronized(gate) { check(state.recoveryVerified); require(checkNotNull(kit).identity == independent.root); state = state.copy(archiveRecoveryVerified = false) }
            require(native.archiveRecoveryCheck(imported.backup(), recovery, independent.root, independent.keyBytes(), independent.pointBytes()))
            check(valid(operation)); store.putArchive(imported) { valid(operation) }; check(valid(operation))
            synchronized(gate) { check(valid(operation)); archiveKit = imported }
            finish(operation) { it.copy(archiveIdentity = independent, archiveCanExport = true, archiveRecoveryVerified = true,
                status = "Fresh native archive AEAD recovery verified the independently retained encrypted archive, separate recovery file, and exact point/key identity. Root recovery and browser archive decryption consent remain separate.") }
        } catch (failure: Exception) { if (ticket == null) cancel() else failed(ticket); throw failure }
        finally { recovery.fill(0) }
    }
    fun encryptedArchive() = synchronized(gate) { check(!closed && !state.busy && state.archiveCanExport); checkNotNull(archiveKit).backup() }
    fun archiveReceipt() = synchronized(gate) { check(!closed && !state.busy && state.archiveCanExport); checkNotNull(archiveKit).receipt() }
    fun archiveIdentity() = synchronized(gate) { checkNotNull(archiveKit).identity }
    fun publicRootPin() = synchronized(gate) { check(!closed && !state.busy && state.recoveryVerified); checkNotNull(kit).pin }
    /** Immutable ciphertext/public identity previously created locally or independently recovered.
     * The browser grant still requires its own explicit comparison and FRESH selected-file AEAD proof.
     * A transient ready flag cannot survive SAF lifecycle and is not a substitute for that proof.
     */
    fun approvedBrowserArchive(expected: AndroidOwnerCustodyIdentity): AndroidOwnerCustodyArchiveKit = synchronized(gate) {
        check(!closed && !state.busy && state.archiveCanExport)
        checkNotNull(archiveKit).also { require(it.identity.root == expected) }
    }
    fun verifyBrowserArchiveRecovery(selected: AndroidOwnerCustodyArchiveKit, recovery: ByteArray): Boolean {
        val ticket = epoch.get()
        try {
            require(recovery.size == 32 && recovery.any { it != 0.toByte() })
            val expected = synchronized(gate) {
                check(!closed && !state.busy)
                checkNotNull(archiveKit).also { require(it.identity == selected.identity && it.digest == selected.digest) }
            }
            require(native.archiveRecoveryCheck(expected.backup(), recovery, expected.identity.root, expected.identity.keyBytes(), expected.identity.pointBytes()))
            check(valid(ticket)); return true
        } finally { recovery.fill(0) }
    }
    /** Stops lifecycle/cancel races; queued workers cannot publish authority or secret output. */
    fun cancel() {
        synchronized(gate) {
            if (closed) return
            epoch.incrementAndGet(); clearOperation(); native.closeAll()
            state = state.copy(busy = false, recoveryVerified = false, archiveRecoveryVerified = false, canReveal = false,
                review = null, publicSignatures = null, flowReview = null, publicArtifact = null,
                status = "Owner custody ceremony closed. Begin a fresh recovery and review before signing.")
        }
        publish()
    }
    override fun close() { cancel(); synchronized(gate) { closed = true; epoch.incrementAndGet() } }
}
