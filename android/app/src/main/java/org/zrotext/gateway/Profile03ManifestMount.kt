// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** User-initiated read-only recovery on the actual current socket; never starts a session,
 * creates a key, opens a consent ceremony or discards any retained attempt. */
internal object Profile03ManifestMount {
    private class Entry(val owner: Any, val current: () -> Boolean, val check: () -> Unit)
    @Volatile private var entry: Entry? = null
    @Synchronized fun attach(owner: Any, current: () -> Boolean, read: () -> Unit) {
        check(current()); entry = Entry(owner, current, read)
    }
    fun checkSetup() { val active = checkNotNull(entry); check(active.current()); active.check() }
    @Synchronized fun detach(owner: Any) { if (entry?.owner === owner) entry = null }
}
