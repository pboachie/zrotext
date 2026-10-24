// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** One owned callback registration lifetime. Full validation happens OUTSIDE storage; a thread
 * captures its actual callback epoch around that validation. Another action cannot renew it.
 * This supplies only a storage lifetime fence, never a SIM installation or effect permission.
 */
internal class EnrollmentStorageLifetime : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val epoch = AtomicLong(1)
    private val capturedEpoch = AtomicLong(0)
    private val ticket = ThreadLocal<Long>()
    fun changed() {
        while (!closed.get()) {
            val prior = epoch.get()
            if (prior == Long.MAX_VALUE) { close(); return }
            if (epoch.compareAndSet(prior, prior + 1)) return
        }
    }
    fun validateOutsideStorage(full: () -> Unit) {
        ticket.remove()
        check(!closed.get())
        val expected = epoch.get()
        val captured = capturedEpoch.get()
        check(if (captured == 0L) capturedEpoch.compareAndSet(0, expected) || capturedEpoch.get() == expected else captured == expected)
        full()
        check(!closed.get() && epoch.get() == expected && capturedEpoch.get() == expected)
        ticket.set(expected)
        requireCurrent()
    }
    /** RAM only: no monitor, Room, root storage, Keystore or Android/framework operation. */
    fun requireCurrent() { check(!closed.get() && capturedEpoch.get() == epoch.get() && ticket.get() == epoch.get()) }
    override fun close() { closed.set(true); ticket.remove() }
    override fun toString() = "EnrollmentStorageLifetime(callback-scoped)"
}
