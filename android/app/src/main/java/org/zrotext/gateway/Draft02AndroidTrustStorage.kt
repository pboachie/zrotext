// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context

/**
 * Primary compared-root storage, using the existing hardware-only key and atomic file contract.
 * Construction and inspection do not create a key. Only deliberate receipt enrollment invokes
 * Session.createKey. Closing this handle neither deletes the key nor resets the persisted root.
 */
internal class Draft02AndroidTrustStorage(context: Context) : Draft02TrustStore.Storage, AutoCloseable {
    private val storage = Draft02AtomicRootStorage.create(checkNotNull(context.applicationContext))
    private val gate = Any()
    @Volatile private var closed = false
    private var executing = false

    override fun <T> locked(action: Draft02TrustStore.Session.() -> T): T = synchronized(gate) {
        requireAvailable()
        if (executing) unavailable()
        executing = true
        try {
            storage.locked {
                val session = ScopedSession(this, Thread.currentThread())
                try { action(session) }
                finally { session.expire() }
            }
        } finally { executing = false }
    }

    private inner class ScopedSession(
        private val delegate: Draft02TrustStore.Session,
        private val thread: Thread
    ) : Draft02TrustStore.Session {
        @Volatile private var active = true
        fun expire() { active = false }
        private fun requireLive() {
            if (!active || Thread.currentThread() !== thread) unavailable()
            requireAvailable()
        }
        private fun <T> checked(action: () -> T): T {
            requireLive()
            val value = action()
            requireLive()
            return value
        }
        override fun keyState() = checked { delegate.keyState() }
        override fun read() = checked { delegate.read() }
        override fun createKey() = checked { delegate.createKey() }
        override fun seal(plaintext: ByteArray) = checked { delegate.seal(plaintext) }
        override fun open(ciphertext: ByteArray) = checked { delegate.open(ciphertext) }
        override fun write(ciphertext: ByteArray, preCommit: () -> Unit) = checked {
            delegate.write(ciphertext) {
                requireLive()
                preCommit()
                requireLive()
            }
        }
    }

    private fun requireAvailable() { if (closed) unavailable() }
    private fun unavailable(): Nothing = throw Draft02TrustStore.Failure(Draft02TrustStore.Status.IO_FAILURE)

    /** The host must disable admission before closing its storage resources. */
    override fun close() = synchronized(gate) { closed = true }
    override fun toString() = "Draft02AndroidTrustStorage(redacted)"
}
