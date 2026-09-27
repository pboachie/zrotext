// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.util.concurrent.ConcurrentHashMap

/**
 * Single bounded encrypted record in noBackupFilesDir. AtomicFile alone supplies no locking:
 * a canonical-path monitor and a separate persistent file lock cover read/verify/CAS/write.
 * This provides crash consistency, not protection against restoration of an old valid snapshot.
 */
internal class Draft02AtomicRootStorage private constructor(directory: File, private val key: Draft02RootStorageKey) :
    Draft02TrustStore.Storage {
    private val directory = directory.canonicalFile
    private val monitor = monitors.computeIfAbsent(this.directory.path) { Any() }
    private val base = File(this.directory, "root-state")
    private val atomic = AtomicFile(base)

    override fun <T> locked(action: Draft02TrustStore.Session.() -> T): T = synchronized(monitor) {
        try {
            if (!directory.isDirectory && !directory.mkdirs()) throw IOException("Root storage directory unavailable")
            RandomAccessFile(File(directory, "root-state.lock"), "rw").use { file ->
                file.channel.lock().use { action(Session()) }
            }
        } catch (failure: Draft02TrustStore.Failure) { throw failure }
          catch (_: IOException) { throw Draft02TrustStore.Failure(Draft02TrustStore.Status.IO_FAILURE) }
          catch (_: GeneralSecurityException) { throw Draft02TrustStore.Failure(Draft02TrustStore.Status.KEY_LOST) }
          catch (_: ProviderException) { throw Draft02TrustStore.Failure(Draft02TrustStore.Status.IO_FAILURE) }
          catch (_: SecurityException) { throw Draft02TrustStore.Failure(Draft02TrustStore.Status.IO_FAILURE) }
    }

    private inner class Session : Draft02TrustStore.Session {
        override fun keyState() = key.state()
        override fun createKey() = key.create()
        override fun seal(plaintext: ByteArray) = key.seal(plaintext)
        override fun open(ciphertext: ByteArray) = key.open(ciphertext)
        override fun read(): ByteArray? {
            // Never interpret interrupted first enrollment or an unexpected legacy backup as unenrolled.
            if (File(base.path + ".bak").exists()) throw Draft02TrustStore.Failure(Draft02TrustStore.Status.RECOVERY_REQUIRED)
            if (!base.exists()) {
                if (File(base.path + ".new").exists()) throw Draft02TrustStore.Failure(Draft02TrustStore.Status.RECOVERY_REQUIRED)
                return null
            }
            return atomic.openRead().use { stream ->
                stream.readBytesBounded(Draft02TrustStore.MAX_BYTES)
            }
        }
        override fun write(ciphertext: ByteArray, preCommit: () -> Unit) {
            require(ciphertext.size <= Draft02TrustStore.MAX_BYTES)
            val stream = atomic.startWrite()
            try {
                stream.write(ciphertext)
                stream.flush()
                stream.fd.sync()
                preCommit()
                atomic.finishWrite(stream)
                // AtomicFile reports some finalization failures only through platform logging.
                if (File(base.path + ".new").exists() || !base.isFile ||
                    !base.inputStream().use { it.readBytesBounded(Draft02TrustStore.MAX_BYTES) }.contentEquals(ciphertext))
                    throw IOException("Root storage commit not confirmed")
            } catch (failure: Throwable) {
                atomic.failWrite(stream)
                throw failure
            }
        }
    }

    companion object {
        private val monitors = ConcurrentHashMap<String, Any>()
        fun create(context: Context): Draft02AtomicRootStorage = isolated(context, "primary")

        /** Test namespaces must be new; neither this adapter nor the controller exposes a reset path. */
        internal fun isolated(context: Context, namespace: String): Draft02AtomicRootStorage {
            require(namespace.matches(Regex("[a-z0-9-]{1,80}")))
            val scope = "draft02-compared-root-$namespace"
            val key = Draft02RootStorageKey("org.zrotext.$scope",
                ("ZTSE/local-root-store/v1\u0000" + context.packageName + "\u0000" + scope).toByteArray(Charsets.UTF_8))
            return Draft02AtomicRootStorage(File(context.noBackupFilesDir, scope), key)
        }
        private fun java.io.InputStream.readBytesBounded(limit: Int): ByteArray {
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (true) {
                val count = read(buffer)
                if (count < 0) break
                if (output.size() + count > limit) throw Draft02TrustStore.Failure(Draft02TrustStore.Status.CORRUPT)
                output.write(buffer, 0, count)
            }
            return output.toByteArray()
        }
    }
}
