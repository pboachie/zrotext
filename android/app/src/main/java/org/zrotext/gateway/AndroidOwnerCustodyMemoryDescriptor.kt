// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.SystemClock
import android.os.storage.StorageManager
import android.system.ErrnoException
import android.system.OsConstants
import java.io.FileNotFoundException
import java.util.UUID

/** Read-only seekable descriptors backed by bounded process memory, never a file.
 * Proxy callbacks run on a dedicated thread so a UI/provider read cannot deadlock.
 * Ownership survives URI consumption: every active copy remains revocable.
 */
internal object AndroidOwnerCustodyMemoryDescriptor {
    private val gate = Any()
    private val active = HashSet<Frozen>()
    private val deadlines = Handler(Looper.getMainLooper())
    private val callbackThread by lazy { HandlerThread("owner-import-io").apply { start() } }
    private val callbacks by lazy { Handler(callbackThread.looper) }

    /** Takes ownership of an already frozen buffer, wiping it on every failed exit. */
    fun open(context: Context, owner: UUID, bytes: ByteArray, createdMs: Long, lifetimeMs: Long,
        available: () -> Boolean = { true }): ParcelFileDescriptor {
        val selected = Frozen(owner, bytes, createdMs, lifetimeMs, available)
        try {
            require(owner != UUID(0, 0) && bytes.size in 1..20_480 && lifetimeMs in 1..120_000)
            synchronized(gate) { check(active.size < 64); active.add(selected) }
            selected.schedule()
            // Revocation may precede registration after a private URI is consumed.
            // Validate its epoch/session now; later clears can find the active copy.
            selected.onGetSize()
            val manager = checkNotNull(context.getSystemService(StorageManager::class.java))
            val descriptor = manager.openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY, selected, callbacks)
            selected.attach(descriptor)
            return descriptor
        } catch (_: Exception) {
            selected.revoke()
            throw FileNotFoundException("Owner import unavailable")
        }
    }

    fun clear(owner: UUID) {
        val copies = synchronized(gate) { active.filter { it.owner == owner } }
        copies.forEach(Frozen::revoke)
    }

    internal class Frozen(val owner: UUID, private val bytes: ByteArray,
        private val createdMs: Long, private val lifetimeMs: Long,
        private val available: () -> Boolean) : ProxyFileDescriptorCallback() {
        private val lock = Any()
        private var closed = false
        private var descriptor: ParcelFileDescriptor? = null
        private val deadline = Runnable { revoke() }

        internal fun schedule() {
            val age = Math.subtractExact(SystemClock.elapsedRealtime(), createdMs)
            require(age in 0 until lifetimeMs)
            check(deadlines.postDelayed(deadline, lifetimeMs - age))
        }

        internal fun attach(selected: ParcelFileDescriptor) {
            val accepted = synchronized(lock) { if (closed) false else { descriptor = selected; true } }
            if (!accepted) { selected.close(); throw FileNotFoundException("Owner import unavailable") }
        }

        private fun requireAvailable() {
            val allowed = runCatching {
                val age = Math.subtractExact(SystemClock.elapsedRealtime(), createdMs)
                age in 0 until lifetimeMs && available()
            }.getOrDefault(false)
            if (!allowed) { revoke(); throw ErrnoException("Owner import", OsConstants.EACCES) }
        }

        override fun onGetSize(): Long {
            requireAvailable()
            return synchronized(lock) {
                if (closed) throw ErrnoException("Owner import", OsConstants.EBADF)
                bytes.size.toLong()
            }
        }

        override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
            if (offset < 0 || size < 0 || size > data.size) {
                revoke(); throw ErrnoException("Owner import", OsConstants.EINVAL)
            }
            requireAvailable()
            return synchronized(lock) {
                if (closed) throw ErrnoException("Owner import", OsConstants.EBADF)
                if (offset >= bytes.size || size == 0) return@synchronized 0
                val count = minOf(size, bytes.size - offset.toInt())
                bytes.copyInto(data, 0, offset.toInt(), offset.toInt() + count)
                count
            }
        }

        override fun onWrite(offset: Long, size: Int, data: ByteArray): Int {
            revoke(); throw ErrnoException("Owner import", OsConstants.EBADF)
        }

        override fun onFsync() { onGetSize() }
        override fun onRelease() { revoke() }

        internal fun revoke() {
            val selected = synchronized(lock) {
                if (closed) return
                closed = true; bytes.fill(0)
                descriptor.also { descriptor = null }
            }
            deadlines.removeCallbacks(deadline)
            synchronized(gate) { active.remove(this) }
            selected?.let { runCatching { it.close() } }
        }
    }
}
