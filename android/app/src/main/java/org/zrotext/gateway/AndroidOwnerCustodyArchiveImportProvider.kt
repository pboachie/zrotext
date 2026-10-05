// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.res.AssetFileDescriptor
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Binder
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.system.ErrnoException
import android.system.OsConstants
import java.io.FileNotFoundException
import java.io.InputStream
import java.util.UUID

/** Separately consented account archive input, never a root/token import.
 * Same-UID metadata opens are bounded; exactly one callback consumer may deliver
 * the frozen 32-byte recovery sequentially within the original 30-second grant.
 */
class AndroidOwnerCustodyArchiveImportProvider : ContentProvider() {
    override fun onCreate() = true
    override fun getType(uri: Uri): String { selected(uri, false).metadata(); return MIME }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        selected(uri, false).metadata()
        val columns = projection?.copyOf() ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        require(columns.size <= DOCUMENT_COLUMNS.size && columns.all { it in DOCUMENT_COLUMNS })
        return MatrixCursor(columns).apply {
            addRow(columns.map { column -> when (column) {
                DocumentsContract.Document.COLUMN_DOCUMENT_ID -> uri.lastPathSegment
                OpenableColumns.DISPLAY_NAME -> "separate-archive-recovery.bin"
                OpenableColumns.SIZE -> 32
                DocumentsContract.Document.COLUMN_MIME_TYPE -> MIME
                DocumentsContract.Document.COLUMN_FLAGS -> 0
                else -> null
            } }.toTypedArray<Any?>())
        }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException("Archive input unavailable")
        return AndroidOwnerCustodyArchiveImportDescriptor.open(checkNotNull(context), registerHandle(uri))
    }

    internal fun registerHandle(uri: Uri): AndroidOwnerCustodyArchiveImportDescriptor.Handle =
        selected(uri, true).register()

    override fun openAssetFile(uri: Uri, mode: String) = AssetFileDescriptor(openFile(uri, mode), 0, 32)
    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException("Read-only archive input")
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) =
        throw UnsupportedOperationException("Read-only archive input")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) =
        throw UnsupportedOperationException("Read-only archive input")

    private fun selected(uri: Uri, pending: Boolean): Grant {
        val selected = checkNotNull(context)
        if (Binder.getCallingUid() != Process.myUid() || uri.scheme != "content" ||
            uri.authority != selected.packageName + SUFFIX || uri.query != null || uri.fragment != null ||
            uri.pathSegments.size != 4 || uri.pathSegments[0] != "tree" || uri.pathSegments[2] != "document" ||
            uri.pathSegments[1] != uri.pathSegments[3]) throw FileNotFoundException("Archive input unavailable")
        val id = uri.pathSegments[3]
        // Consumed grants retain same-UID immutable metadata until close/deadline.
        // Only entries can create a descriptor; metadata cannot resurrect a URI.
        return synchronized(gate) { (if (pending) entries else grants)[id] }
            ?: throw FileNotFoundException("Archive input unavailable")
    }

    companion object {
        internal const val MIME = "application/vnd.zrotext.archive-recovery.v1"
        private const val SUFFIX = ".owner-archive-import"
        private const val LIFETIME_MS = 30_000L
        private const val MAX_DESCRIPTOR_OPENS = 8
        private val gate = Any()
        private val DOCUMENT_COLUMNS = setOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE, DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_LAST_MODIFIED, DocumentsContract.Document.COLUMN_FLAGS)
        private val deadlines = Handler(Looper.getMainLooper())
        private val entries = HashMap<String, Grant>()
        private val grants = HashMap<String, Grant>()

        private class InactiveHandle : RuntimeException()
        private class Grant(val id: String, val owner: UUID, val bytes: ByteArray,
            val createdMs: Long, val available: () -> Boolean) : AndroidOwnerCustodyArchiveImportDescriptor.Access {
            val handles = HashSet<AndroidOwnerCustodyArchiveImportDescriptor.Handle>()
            var opened = 0
            var consumer: AndroidOwnerCustodyArchiveImportDescriptor.Handle? = null
            var delivered = 0
            var closed = false
            lateinit var deadline: Runnable

            fun live() {
                val allowed = runCatching(available).getOrDefault(false)
                val age = Math.subtractExact(SystemClock.elapsedRealtime(), createdMs)
                // The authority callback may itself cancel this grant. Recheck
                // closure after it returns, including same-thread invalidation.
                if (closed || age !in 0 until LIFETIME_MS || !allowed)
                    throw FileNotFoundException("Archive input unavailable")
            }

            fun metadata() {
                try { synchronized(gate) { live() } }
                catch (_: Exception) { discard(this); throw FileNotFoundException("Archive input unavailable") }
            }

            fun register(): AndroidOwnerCustodyArchiveImportDescriptor.Handle {
                var capacity = false
                try { return synchronized(gate) {
                    live()
                    if (entries[id] !== this || consumer != null || opened >= MAX_DESCRIPTOR_OPENS) {
                        capacity = true; throw FileNotFoundException("Archive input unavailable")
                    }
                    AndroidOwnerCustodyArchiveImportDescriptor.Handle(this).also { opened++; handles.add(it) }
                } } catch (_: Exception) {
                    if (!capacity) discard(this)
                    throw FileNotFoundException("Archive input unavailable")
                }
            }

            private fun <T> use(handle: AndroidOwnerCustodyArchiveImportDescriptor.Handle, operation: () -> T): T {
                try { return synchronized(gate) {
                    if (closed || handle !in handles) throw InactiveHandle()
                    live(); operation()
                } } catch (_: InactiveHandle) { throw ErrnoException("Archive input", OsConstants.EBADF) }
                catch (_: Exception) { discard(this); throw ErrnoException("Archive input", OsConstants.EACCES) }
            }

            override fun size(handle: AndroidOwnerCustodyArchiveImportDescriptor.Handle): Long = use(handle) { 32L }

            override fun read(handle: AndroidOwnerCustodyArchiveImportDescriptor.Handle,
                offset: Long, size: Int, data: ByteArray): Int {
                var siblings = emptyList<AndroidOwnerCustodyArchiveImportDescriptor.Handle>()
                try {
                    return use(handle) {
                        require(offset >= 0 && size >= 0 && size <= data.size)
                        if (size == 0) return@use 0
                        if (consumer == null) {
                            require(offset == 0L && entries[id] === this)
                            consumer = handle; entries.remove(id)
                            siblings = handles.filter { it !== handle }
                            handles.removeAll(siblings.toSet())
                        }
                        check(consumer === handle && offset == delivered.toLong())
                        val selected = minOf(size, 32 - delivered)
                        bytes.copyInto(data, 0, delivered, delivered + selected)
                        delivered += selected
                        if (delivered == 32) bytes.fill(0)
                        selected
                    }
                } finally {
                    // Permissions were removed under the grant lock before copying.
                    // Closing kernel handles occurs outside every grant/handle lock.
                    siblings.forEach { it.revoke() }
                }
            }

            override fun release(handle: AndroidOwnerCustodyArchiveImportDescriptor.Handle) {
                val selected = synchronized(gate) { handles.remove(handle); consumer === handle }
                if (selected) discard(this)
            }
            override fun failed(handle: AndroidOwnerCustodyArchiveImportDescriptor.Handle) {
                val selected = synchronized(gate) { handle in handles || consumer === handle }
                if (selected) discard(this)
            }
        }

        /** Read the chosen source once; no unchecked URI reaches web content. */
        internal fun readExact(input: InputStream): ByteArray {
            val bytes = ByteArray(32)
            try {
                var used = 0
                while (used < bytes.size) {
                    val count = input.read(bytes, used, bytes.size - used)
                    require(count > 0); used += count
                }
                require(input.read() == -1 && bytes.any { it != 0.toByte() })
                return bytes
            } catch (_: Exception) { bytes.fill(0); throw IllegalArgumentException("Archive input unavailable") }
        }

        /** Exact native AEAD proof and independent consent precede this grant.
         * Proof uses a copy because JNI clears it; callbacks hold no private arrays.
         */
        internal fun stage(context: Context, owner: UUID, bytes: ByteArray,
            verify: (ByteArray) -> Boolean, available: () -> Boolean): Uri {
            require(owner != UUID(0, 0) && bytes.size == 32)
            val frozen = bytes.copyOf()
            if (frozen.all { it == 0.toByte() }) { frozen.fill(0); throw IllegalArgumentException("Archive input unavailable") }
            val proof = frozen.copyOf()
            val verified = try { verify(proof) } catch (_: Exception) { false } finally { proof.fill(0) }
            if (!verified) { frozen.fill(0); throw IllegalArgumentException("Archive input unavailable") }
            val id = UUID.randomUUID().toString()
            val tree = DocumentsContract.buildTreeDocumentUri(context.packageName + SUFFIX, id)
            val uri = DocumentsContract.buildDocumentUriUsingTree(tree, id)
            val grant = Grant(id, owner, frozen, SystemClock.elapsedRealtime(), available)
            grant.deadline = Runnable { discard(grant) }
            try {
                check(DocumentsContract.isDocumentUri(context, uri))
                expire()
                synchronized(gate) {
                    check(grants.values.none { it.owner == owner } && grants.size < 4)
                    entries[id] = grant; grants[id] = grant
                    // Track before authority callbacks: a reentrant owner clear
                    // must find and revoke this grant before it can be published.
                    grant.live()
                    check(deadlines.postDelayed(grant.deadline, LIFETIME_MS))
                }
                context.contentResolver.query(uri, null, null, null, null)?.use { check(it.moveToFirst()) }
                    ?: error("Archive input unavailable")
                return uri
            } catch (_: Exception) {
                discard(grant); throw IllegalStateException("Archive input unavailable")
            }
        }

        internal fun clear(owner: UUID) {
            val selected = synchronized(gate) { grants.values.filter { it.owner == owner } }
            selected.forEach(::discard)
        }

        private fun expire() {
            val now = SystemClock.elapsedRealtime()
            val selected = synchronized(gate) { grants.values.filter { now - it.createdMs !in 0 until LIFETIME_MS } }
            selected.forEach(::discard)
        }

        private fun discard(grant: Grant) {
            val selected = synchronized(gate) {
                if (grant.closed) return
                grant.closed = true; grant.bytes.fill(0)
                if (entries[grant.id] === grant) entries.remove(grant.id)
                if (grants[grant.id] === grant) grants.remove(grant.id)
                deadlines.removeCallbacks(grant.deadline)
                grant.handles.toList().also { grant.handles.clear() }
            }
            selected.forEach { it.revoke() }
        }
    }
}
