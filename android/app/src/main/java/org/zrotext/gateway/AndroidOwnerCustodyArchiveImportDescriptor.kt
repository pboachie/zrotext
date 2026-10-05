// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.system.ErrnoException
import android.system.OsConstants
import java.io.FileNotFoundException

/** These private metadata handles contain no recovery bytes. The shared grant
 * chooses the only callback permitted to deliver its sequential payload.
 */
internal object AndroidOwnerCustodyArchiveImportDescriptor {
    private val thread by lazy { HandlerThread("owner-archive-io").apply { start() } }
    private val callbacks by lazy { Handler(thread.looper) }
    private val closingThread by lazy { HandlerThread("owner-archive-close").apply { start() } }
    private val closing by lazy { Handler(closingThread.looper) }

    internal interface Access {
        fun size(handle: Handle): Long
        fun read(handle: Handle, offset: Long, size: Int, data: ByteArray): Int
        fun release(handle: Handle)
        fun failed(handle: Handle)
    }

    internal class Handle(private val access: Access) : ProxyFileDescriptorCallback() {
        private val lock = Any()
        private var closed = false
        private var descriptor: ParcelFileDescriptor? = null

        private fun checkOpen() { synchronized(lock) {
            if (closed) throw ErrnoException("Archive input", OsConstants.EBADF)
        } }
        internal fun attach(selected: ParcelFileDescriptor) {
            val accepted = synchronized(lock) { if (closed) false else { descriptor = selected; true } }
            if (!accepted) { close(selected); throw FileNotFoundException("Archive input unavailable") }
        }
        override fun onGetSize(): Long { checkOpen(); return access.size(this) }
        override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
            checkOpen(); return access.read(this, offset, size, data)
        }
        override fun onWrite(offset: Long, size: Int, data: ByteArray): Int {
            access.failed(this); throw ErrnoException("Archive input", OsConstants.EBADF)
        }
        override fun onFsync() { onGetSize() }
        override fun onRelease() {
            synchronized(lock) { closed = true; descriptor = null }
            access.release(this)
        }
        internal fun failed() { access.failed(this); revoke() }
        internal fun revoke() {
            val selected = synchronized(lock) {
                if (closed) return
                closed = true; descriptor.also { descriptor = null }
            }
            selected?.let(::close)
        }
    }

    internal fun open(context: Context, handle: Handle): ParcelFileDescriptor {
        try {
            // Check a clear that raced registration before platform creation.
            handle.onGetSize()
            val manager = checkNotNull(context.getSystemService(StorageManager::class.java))
            val selected = manager.openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY, handle, callbacks)
            handle.attach(selected)
            return selected
        } catch (_: Exception) {
            handle.failed()
            throw FileNotFoundException("Archive input unavailable")
        }
    }

    private fun close(descriptor: ParcelFileDescriptor) {
        // Authority callbacks can cancel reentrantly under the grant lock.
        // Always close on a dedicated thread, after immediate permission
        // revocation, so kernel release never waits under a grant/handle lock.
        check(closing.post { runCatching { descriptor.close() } })
    }
}
