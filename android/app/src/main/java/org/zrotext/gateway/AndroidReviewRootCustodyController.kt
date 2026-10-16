// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

/** One first-root journey. No ordinary owner authority or MFA is synthesized. */
internal class AndroidReviewRootCustodyController(
    private val origin: String,
    private val context: AndroidReviewWorkspaceOwnerContext,
    private val native: AndroidReviewRootCustodyNativePort,
    kitNative: AndroidOwnerCustodyNativePort,
    private val store: AndroidReviewRootKitStore,
    private val elapsed: () -> Long,
    private val changed: () -> Unit = {}
) : AutoCloseable {
    data class Review(val enrollment: AndroidOwnerCustodyReview, val fingerprint: String, val bundle: UUID,
        val backupSha256: String, val cardSha256: String, val custodyStatementSha256: String)
    data class Snapshot(val busy: Boolean, val kit: AndroidOwnerCustodyController.Snapshot,
        val review: Review?, val signatures: String?, val status: String)
    private val gate = Any()
    private val epoch = AtomicLong(0)
    private var closed = false
    private var busy = false
    private var storageContext: AndroidReviewWorkspaceAuthority? = null
    // This delegate is used ONLY for real kit generation/export/recovery.
    // No ordinary owner Authority provider is installed; old review/sign is unused.
    private val kit = AndroidOwnerCustodyController(kitNative, object : AndroidOwnerCustodyKitStore {
        override fun put(value: AndroidOwnerCustodyKit, permitted: () -> Boolean) {
            store.put(value, checkNotNull(storageContext), permitted)
        }
    }, elapsed, changed = { changed() })
    private var selected: AndroidOwnerCustodyKit? = null
    private var handle = 0L
    private var reviewedAuthority: AndroidReviewWorkspaceAuthority? = null
    private var review: Review? = null
    private var signatures: String? = null
    private var status = "Sign in to the isolated review workspace, then create or independently recover its kit."
    fun snapshot() = synchronized(gate) { Snapshot(busy, kit.snapshot(), review, signatures, status) }
    private fun begin(): Long = synchronized(gate) {
        check(!closed && !busy && native.available); clearReview(); busy = true; epoch.incrementAndGet()
    }.also { changed() }
    private fun valid(ticket: Long) = synchronized(gate) { !closed && epoch.get() == ticket }
    private fun clearReview() {
        val old = handle; handle = 0; reviewedAuthority = null; review = null; signatures = null
        if (old > 0) native.close(old)
    }
    private fun finish(ticket: Long, message: String) {
        synchronized(gate) { check(valid(ticket)); busy = false; status = message }; changed()
    }
    private fun fail(ticket: Long) {
        synchronized(gate) {
            if (!valid(ticket)) return
            clearReview(); busy = false; selected = null
            status = "Review custody refused or unconfirmed. Recover retained copies before another approval."
        }
        kit.cancel(); changed()
    }
    fun create() {
        val ticket = begin()
        try {
            val current = context.refresh(origin); check(valid(ticket))
            require(current.rootState == AndroidReviewRootState.NoRootHistory && selected == null && !store.hasExisting(current))
            storageContext = current
            kit.create(current.account, origin)
            check(valid(ticket)); require(context.current()?.sameSession(current) == true)
            finish(ticket, "A real kit was generated. Record its token, save backup/card/receipt, then recover the retained files.")
        } catch (failure: Exception) { fail(ticket); throw failure }
    }
    fun reveal() = kit.reveal()
    fun confirmTokenRecorded() = kit.confirmTokenRecorded()
    fun expireReveal() = kit.expireReveal()
    fun backup() = kit.encryptedBackup()
    fun card() = kit.publicCard()
    fun publicReceipt() = kit.publicRootReceipt()
    fun exportReadback(value: ByteArray) = kit.exportReadback(value)
    fun exportUnconfirmed() = kit.exportUnconfirmed()

    /** Fetch context BEFORE reading secret input. Clear it before any later network request. */
    fun recover(backup: ByteArray, card: ByteArray, independent: AndroidOwnerCustodyIdentity,
        retained: Boolean, token: () -> ByteArray) {
        val ticket = begin()
        try {
            val current = context.refresh(origin); check(valid(ticket))
            require(independent.account == current.account && independent.origin == origin)
            require(retained)
            val imported = AndroidOwnerCustodyKit(backup, card); require(imported.identity == independent)
            requireRetainedKit(current, imported, null); storageContext = current
            val secret = token()
            try {
                check(valid(ticket)); check(context.current()?.sameSession(current) == true)
                kit.recover(backup, card, secret, independent, retained)
            } finally { secret.fill(0) }
            require(current.sameSession(context.refresh(origin))); check(valid(ticket))
            synchronized(gate) { check(valid(ticket)); selected = imported }
            finish(ticket, "Fresh native AEAD recovery matched the retained kit. No root is cached or server-enrolled by this check.")
        } catch (failure: Exception) { fail(ticket); throw failure }
    }
    fun review(unsignedInput: ByteArray, independent: AndroidOwnerCustodyIdentity) {
        val unsigned = unsignedInput.copyOf(); val ticket = begin(); var opened = 0L
        try {
            val current = context.refresh(origin); check(valid(ticket)); require(kit.snapshot().recoveryVerified)
            val selected = synchronized(gate) { checkNotNull(selected) }; require(selected.identity == independent)
            val parsed = AndroidOwnerCustodyReview.parse(unsigned)
            require(parsed.account == current.account && parsed.user == current.user && parsed.session == current.session &&
                parsed.origin == origin && parsed.fingerprint == independent.fingerprint)
            requireRetainedKit(current, selected, unsigned)
            opened = native.open(unsigned, selected, independent, current, elapsed()); require(opened > 0)
            require(native.review(opened).contentEquals(unsigned))
            val after = context.refresh(origin); require(current.sameSession(after))
            requireRetainedKit(after, selected, unsigned); check(valid(ticket))
            val display = Review(parsed, independent.fingerprint, uuid(selected.bundleId), hash(selected.backup()),
                hash(selected.card()), hash(statement(unsigned, selected)))
            synchronized(gate) { check(valid(ticket)); handle = opened; opened = 0; reviewedAuthority = current; review = display }
            finish(ticket, "Compare both the enrollment and exact encrypted-custody publication. Approve only this one proposal.")
        } catch (failure: Exception) { fail(ticket); throw failure }
        finally { if (opened > 0) native.close(opened) }
    }
    fun sign(approved: Boolean, token: () -> ByteArray) {
        var signing = 0L; var ticket = 0L
        try {
            require(approved)
            val prior: AndroidReviewWorkspaceAuthority
            synchronized(gate) {
                check(!closed && !busy && review != null); signing = handle; handle = 0; check(signing > 0)
                prior = checkNotNull(reviewedAuthority); reviewedAuthority = null; review = null; signatures = null
                busy = true; ticket = epoch.incrementAndGet()
            }
            changed()
            val current = context.refresh(origin); require(prior.sameSession(current)); check(valid(ticket))
            val unsigned = native.review(signing)
            val selected = synchronized(gate) { checkNotNull(selected) }; requireRetainedKit(current, selected, unsigned)
            val secret = token()
            val output = try {
                check(valid(ticket)); check(context.current()?.sameSession(current) == true)
                native.sign(signing, secret, current, elapsed())
            } finally { secret.fill(0) }
            require(output.size == 2 && output.all { it.size == 64 })
            val after = context.refresh(origin); require(current.sameSession(after))
            requireRetainedKit(after, selected, unsigned); check(valid(ticket))
            val public = "Enrollment signature: " + AndroidOwnerCustodyKit.hex(output[0]) +
                "\nCustody signature: " + AndroidOwnerCustodyKit.hex(output[1]) + "\n"
            synchronized(gate) { check(valid(ticket)); signatures = public }
            finish(ticket, "Public dual signatures created. Import them in the same review browser; password and server completion remain required.")
        } catch (failure: Exception) { if (ticket > 0) fail(ticket) else cancel(); throw failure }
        finally { if (signing > 0) native.close(signing) }
    }
    fun verifyServerPublication(): AndroidReviewRootPublication {
        val ticket=begin()
        try {
            val selected=synchronized(gate){checkNotNull(selected)}
            require(kit.snapshot().recoveryVerified)
            val receipt=context.readRoot(selected.identity,false)
            val export=context.readRoot(selected.identity,true)
            val proof=AndroidReviewRootPublication.verify(receipt,export,selected)
            check(valid(ticket))
            finish(ticket,"The actual server receipt and signed encrypted-custody export matched the independently retained kit. Phone/SMS authority remains separate.")
            return proof
        }catch(failure:Exception){fail(ticket);throw failure}
    }
    /** HTTPS invalidation callback: deliberately does not call back into context. */
    fun contextLost() {
        synchronized(gate) {
            epoch.incrementAndGet(); clearReview(); busy = false; selected = null
            status = "Review context lost. Retain files and reconcile any server mutation."
        }
        native.closeAll(); kit.cancel(); changed()
    }
    fun cancel() { contextLost(); context.invalidate() }
    override fun close() { synchronized(gate) { closed = true }; contextLost(); kit.close(); context.close() }
    companion object {
        private fun uuid(bytes: ByteArray): UUID { val b = ByteBuffer.wrap(bytes); return UUID(b.long, b.long) }
        private fun hash(bytes: ByteArray) = AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(bytes))
        private fun statement(unsigned: ByteArray, kit: AndroidOwnerCustodyKit) =
            "ZTSE/root-custody/v1\u0000".toByteArray(Charsets.US_ASCII) +
                ByteBuffer.allocate(4).putInt(unsigned.size).array() + unsigned +
                AndroidOwnerCustodyKit.hash(kit.backup()) + AndroidOwnerCustodyKit.hash(kit.card()) + kit.identity.fingerprintBytes()
        private fun requireRetainedKit(current: AndroidReviewWorkspaceAuthority, kit: AndroidOwnerCustodyKit, unsigned: ByteArray?) {
            require(kit.identity.account == current.account && kit.identity.origin == current.origin)
            when (val root = current.rootState) {
                AndroidReviewRootState.NoRootHistory -> require(unsigned == null)
                is AndroidReviewRootState.Pending -> {
                    require(AndroidReviewJson.binary(root.pin, 94).contentEquals(kit.pin) &&
                        AndroidReviewJson.binary(root.fingerprint, 32).contentEquals(kit.identity.fingerprintBytes()))
                    require(AndroidReviewJson.binary(root.backupDigest, 32).contentEquals(AndroidOwnerCustodyKit.hash(kit.backup())) &&
                        AndroidReviewJson.binary(root.cardDigest, 32).contentEquals(AndroidOwnerCustodyKit.hash(kit.card())))
                    if (unsigned != null) {
                        val parsed = AndroidOwnerCustodyReview.parse(unsigned)
                        require(parsed.challengeId == root.challenge && parsed.expiresMs <= root.expiresMs)
                        require(AndroidReviewJson.binary(root.unsignedDigest, 32).contentEquals(AndroidOwnerCustodyKit.hash(unsigned)) &&
                            AndroidReviewJson.binary(root.statementDigest, 32).contentEquals(AndroidOwnerCustodyKit.hash(statement(unsigned, kit))))
                    }
                }
                is AndroidReviewRootState.Enrolled -> {
                    require(unsigned == null); require(AndroidReviewJson.binary(root.pin, 94).contentEquals(kit.pin) &&
                        AndroidReviewJson.binary(root.fingerprint, 32).contentEquals(kit.identity.fingerprintBytes()))
                }
                else -> error("Current retained root unavailable")
            }
        }
    }
}

internal interface AndroidReviewRootKitStore {
    fun hasExisting(context: AndroidReviewWorkspaceAuthority): Boolean
    fun put(kit: AndroidOwnerCustodyKit, context: AndroidReviewWorkspaceAuthority, permitted: () -> Boolean)
}

/** Separate immutable ciphertext storage, never an ordinary owner-kit overwrite.
 * Config revision is deliberately not in the filename: A->B->A must preserve
 * this workspace's original kit rather than create a replacement.
 */
internal class AndroidReviewRootKitFiles(private val directory: java.io.File) : AndroidReviewRootKitStore {
    private fun file(context: AndroidReviewWorkspaceAuthority): java.io.File {
        fun uuid(value: UUID) = ByteBuffer.allocate(16).putLong(value.mostSignificantBits).putLong(value.leastSignificantBits).array()
        val origin = context.origin.toByteArray(Charsets.US_ASCII)
        val key = "review-owner-kit/v1\u0000".toByteArray(Charsets.US_ASCII) + uuid(context.realm) +
            AndroidReviewJson.binary(context.database, 32) + uuid(context.account) +
            ByteBuffer.allocate(2).putShort(origin.size.toShort()).array() + origin
        return java.io.File(directory, AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(key)))
    }
    override fun hasExisting(context: AndroidReviewWorkspaceAuthority): Boolean {
        val path = file(context)
        return path.exists() || java.io.File(path.path + ".bak").exists() || java.io.File(path.path + ".new").exists()
    }
    override fun put(kit: AndroidOwnerCustodyKit, context: AndroidReviewWorkspaceAuthority, permitted: () -> Boolean) {
        require(kit.identity.account == context.account && kit.identity.origin == context.origin)
        val base = file(context); val encoded = kit.encode()
        synchronized(monitors.computeIfAbsent(base.canonicalPath) { Any() }) {
            check(permitted())
            if (!directory.isDirectory && !directory.mkdirs()) error("Review kit storage unavailable")
            java.io.RandomAccessFile(java.io.File(base.path + ".lock"), "rw").use { lock -> lock.channel.lock().use {
                if (java.io.File(base.path + ".bak").exists() || java.io.File(base.path + ".new").exists())
                    error("Review kit commit needs independent reconciliation")
                val atomic = android.util.AtomicFile(base)
                if (base.exists()) {
                    check(base.isFile)
                    val prior = atomic.openRead().use { readAndroidOwnerCustodyFile(it, AndroidOwnerCustodyKit.MAX_RECORD) }
                    require(AndroidOwnerCustodyKit.decode(prior).matches(kit)); check(permitted()); return
                }
                val stream = atomic.startWrite()
                try {
                    stream.write(encoded); stream.flush(); stream.fd.sync(); check(permitted())
                    atomic.finishWrite(stream); check(permitted())
                    if (java.io.File(base.path + ".bak").exists() || java.io.File(base.path + ".new").exists() ||
                        !atomic.openRead().use { readAndroidOwnerCustodyFile(it, AndroidOwnerCustodyKit.MAX_RECORD) }.contentEquals(encoded))
                        error("Review kit commit unconfirmed")
                } catch (failure: Throwable) { atomic.failWrite(stream); throw failure }
            } }
        }
    }
    companion object {
        private val monitors = java.util.concurrent.ConcurrentHashMap<String, Any>()
        fun create(context: android.content.Context) = AndroidReviewRootKitFiles(
            java.io.File(context.noBackupFilesDir, "review-owner-custody-v1").canonicalFile)
    }
}
