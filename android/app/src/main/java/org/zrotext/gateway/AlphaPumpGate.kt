// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

/**
 * Decides when the alpha evidence pump may touch the Room journal. An idle
 * authenticated session must not run journal work on a timer, so a pump runs
 * only at session start, at grant expiry, or after a journal write, grant
 * reservation or ack reports that an alpha event may be queued.
 */
internal class AlphaPumpGate {
    private var quarantineDue = false
    private var retireDue = false
    private var queryDue = false

    /** One quarantine, orphan retirement and pending query per session start. */
    @Synchronized
    fun onSessionStart() {
        quarantineDue = true
        retireDue = true
        queryDue = true
    }

    /** An expired grant may have left an orphaned submit intent to retire. */
    @Synchronized
    fun onGrantExpiry() {
        retireDue = true
        queryDue = true
    }

    /** A journal write, grant reservation or ack may have queued an alpha event. */
    @Synchronized
    fun requestQuery() {
        queryDue = true
    }

    /** A new connection or halt drops work that belongs to the old session. */
    @Synchronized
    fun onConnectionReset() {
        quarantineDue = false
        retireDue = false
        queryDue = false
    }

    /**
     * Consumes the pending decision, or returns null when the journal must not
     * be touched at all. Every flag is consumed atomically with the query.
     */
    @Synchronized
    fun takeWork(): AlphaPumpWork? =
        if (queryDue) {
            queryDue = false
            AlphaPumpWork(quarantineDue.also { quarantineDue = false },
                retireDue.also { retireDue = false })
        } else null
}

/** Maintenance bounds for one pump run: quarantine foreign evidence, retire orphans. */
internal data class AlphaPumpWork(val quarantineForeign: Boolean, val retireOrphans: Boolean)

/**
 * Journal writers (SMS callbacks, no-radio proofs) run outside the service
 * lifecycle. They report here so a live authenticated session can pump new
 * alpha evidence without a periodic poll. The listener is replaced on every
 * new session and cleared on halt; it fences itself by connection generation.
 */
internal object JournalWriteSignal {
    @Volatile
    private var listener: (() -> Unit)? = null

    fun replace(next: (() -> Unit)?) {
        listener = next
    }

    /** Called after a journal write that may have queued an unacknowledged alpha event. */
    fun alphaEventRecorded() {
        listener?.invoke()
    }
}
