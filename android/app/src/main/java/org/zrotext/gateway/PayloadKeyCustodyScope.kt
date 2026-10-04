// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Process-only ownership, never a key generation, execution grant or hardware attestation. */
internal object PayloadKeyCustodyEntry {
    private val active = ThreadLocal<Any>()

    fun requireUnscopedEntry() {
        check(active.get() == null) { "Nested payload custody unavailable" }
    }

    fun <R> withDeviceMonitor(owner: Any, operation: () -> R): R {
        requireUnscopedEntry() // Must precede the device monitor, not only the file lock.
        return synchronized(owner) { operation() }
    }

    fun enter(): Any {
        requireUnscopedEntry()
        return Any().also(active::set)
    }

    fun requireOwner(token: Any, thread: Thread) {
        check(Thread.currentThread() === thread && active.get() === token) {
            "Payload custody scope unavailable"
        }
    }

    fun leave(token: Any) {
        check(active.get() === token) { "Payload custody scope unavailable" }
        active.remove()
    }
}

/** Only the trusted key-store adapter supplies material; callers receive its public facade. */
internal interface PayloadKeyCustodySource<T> {
    fun load(): T
    fun keyId(material: T): ByteArray
    fun requireSameIdentity(initial: T, current: T)
}

/** Uses the retained record access. It never acquires a device or lifecycle lock. */
internal class PayloadKeyCustodyScope internal constructor(private val token: Any,
    private val thread: Thread, private var validate: (() -> Unit)?) {
    fun requireCurrent() {
        PayloadKeyCustodyEntry.requireOwner(token, thread)
        check(validate != null) { "Payload custody scope unavailable" }
    }

    fun revalidate() {
        requireCurrent()
        checkNotNull(validate).invoke()
    }

    fun expire() {
        PayloadKeyCustodyEntry.requireOwner(token, thread)
        validate = null
    }
}
