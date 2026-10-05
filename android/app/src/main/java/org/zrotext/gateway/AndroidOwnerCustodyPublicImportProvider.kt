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
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.provider.OpenableColumns
import java.io.ByteArrayInputStream
import java.io.FileNotFoundException
import java.util.UUID

/** App-private, process-only frozen public import bytes. No backing input-provider URI,
 * persistent file, recovery token or private-root serialization is ever exposed.
 * The manifest must register this provider as unexported, without URI grants.
 */
class AndroidOwnerCustodyPublicImportProvider : ContentProvider() {
    override fun onCreate() = true
    override fun getType(uri: Uri) = "application/octet-stream"

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        val bytes = snapshot(uri)
        return try {
            MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)).apply {
                addRow(arrayOf<Any>("public-owner-import.bin", bytes.size))
            }
        } finally { bytes.fill(0) }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException("Public import unavailable")
        val selected = snapshotEntry(uri)
        return AndroidOwnerCustodyMemoryDescriptor.open(checkNotNull(context), selected.owner,
            selected.bytes, selected.createdMs, LIFETIME_MS)
    }

    override fun openAssetFile(uri: Uri, mode: String): AssetFileDescriptor {
        if (mode != "r") throw FileNotFoundException("Public import unavailable")
        val selected = snapshot(uri)
        val size = selected.size.toLong()
        selected.fill(0)
        // Report exact metadata in addition to the proxy descriptor's stat size.
        return AssetFileDescriptor(openFile(uri, mode), 0, size)
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException("Read-only public import")
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) =
        throw UnsupportedOperationException("Read-only public import")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) =
        throw UnsupportedOperationException("Read-only public import")

    private fun snapshot(uri: Uri): ByteArray = snapshotEntry(uri).bytes

    private fun snapshotEntry(uri: Uri): Entry {
        val selected = checkNotNull(context)
        if (Binder.getCallingUid() != Process.myUid() || uri.scheme != "content" ||
            uri.authority != selected.packageName + SUFFIX || uri.query != null || uri.fragment != null ||
            uri.pathSegments.size != 1) throw FileNotFoundException("Public import unavailable")
        val id = uri.pathSegments.single()
        return synchronized(gate) {
            expire(SystemClock.elapsedRealtime())
            entries[id]?.let { Entry(it.owner, it.bytes.copyOf(), it.createdMs) }
                ?: throw FileNotFoundException("Public import unavailable")
        }
    }

    companion object {
        private const val SUFFIX = ".owner-public-import"
        private const val MAX_ENTRIES = 16
        private const val LIFETIME_MS = 120_000L
        private val gate = Any()
        private class Entry(val owner: UUID, val bytes: ByteArray, val createdMs: Long)
        private val entries = HashMap<String, Entry>()

        internal fun stage(context: Context, owner: UUID, bytes: ByteArray): Uri {
            require(owner != UUID(0, 0) && bytes.size in 1..20_480)
            val frozen = bytes.copyOf()
            if (!AndroidOwnerCustodyOwnerBrowser.publicImport(ByteArrayInputStream(frozen))) {
                frozen.fill(0); throw IllegalArgumentException("Public import unavailable")
            }
            val now = SystemClock.elapsedRealtime()
            val id = UUID.randomUUID().toString()
            val uri = Uri.Builder().scheme("content").authority(context.packageName + SUFFIX).appendPath(id).build()
            try {
                synchronized(gate) {
                    expire(now)
                    check(entries.size < MAX_ENTRIES) { "Public import unavailable" }
                    entries[id] = Entry(owner, frozen, now)
                }
            } catch (_: Exception) { frozen.fill(0); throw IllegalStateException("Public import unavailable") }
            // Missing provider wiring must not return the original mutable URI as a fallback.
            try {
                context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use {
                    check(it.moveToFirst() && it.getInt(it.getColumnIndexOrThrow(OpenableColumns.SIZE)) == frozen.size)
                } ?: error("Public import unavailable")
            }
            catch (_: Exception) {
                synchronized(gate) { entries.remove(id)?.bytes?.fill(0) }
                throw IllegalStateException("Public import unavailable")
            }
            return uri
        }

        internal fun clear(owner: UUID) {
            synchronized(gate) {
                entries.entries.removeAll { entry ->
                    if (entry.value.owner == owner) { entry.value.bytes.fill(0); true } else false
                }
            }
            AndroidOwnerCustodyMemoryDescriptor.clear(owner)
        }

        private fun expire(now: Long) {
            entries.entries.removeAll { entry ->
                val age = now - entry.value.createdMs
                if (age !in 0..LIFETIME_MS) { entry.value.bytes.fill(0); true } else false
            }
        }
    }
}
