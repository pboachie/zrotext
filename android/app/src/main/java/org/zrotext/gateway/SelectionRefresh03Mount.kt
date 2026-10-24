// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/** Only the live shipping03 connection owns this callback. No saved bytes or UI boolean can
 * attach a service, publish a selected-SIM lease or manufacture an authenticated connection.
 */
internal object SelectionRefresh03Mount {
    private class Entry(val owner: Any, val current: () -> Boolean, val accept: (SamePhoneSelectionReview.Pending) -> Unit)
    @Volatile private var entry: Entry? = null
    @Synchronized fun attach(owner: Any, current: () -> Boolean, accept: (SamePhoneSelectionReview.Pending) -> Unit) {
        check(current()); entry = Entry(owner, current, accept)
    }
    @Synchronized fun detach(owner: Any) { if (entry?.owner === owner) entry = null }
    fun submit(pending: SamePhoneSelectionReview.Pending) {
        val observed = checkNotNull(entry)
        pending.requireCurrent(); check(observed.current() && entry === observed)
        observed.accept(pending)
        check(observed.current() && entry === observed)
    }
}
