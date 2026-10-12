// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.Executor

/**
 * Unused API33+ complete-list observation adapter. Construction is inert; no Android factory,
 * singleton, lifecycle hook, signer, storage or radio consumer is installed here.
 *
 * The supplied main dispatcher must run registration on main and report dispatch acceptance.
 * The read executor remains caller-owned. Explicit permission/selection/lifecycle withdrawal
 * must be attached by a separately reviewed consumer before this can support any authority.
 * Neither a snapshot nor its actual row count is a signing or installation permission.
 */
internal class CompleteSubscriptionObservationAdapter(
    private val apiLevel: () -> Int,
    private val source: ProfileObservationSource,
    private val mainDispatch: ((() -> Unit) -> Boolean),
    private val reads: Executor
) : AutoCloseable {
    private inner class OwnedRegistration(val selectedId: Int) {
        val observer = CompleteSubscriptionObserver(
            CompleteSubscriptionSource { readComplete(this) }, MAX_OBSERVED_ROWS)
        val token = observer.beginRegistration()
        var startClaimed = false
        var succeeded = false
        var initialCallback = false
        var callbackRevision = 0L
        var handle: AutoCloseable? = null
    }

    private inner class ReadTicket(
        val registration: OwnedRegistration,
        val revision: Long,
        val selectedId: Int
    )

    private val lock = Any()
    private var current: OwnedRegistration? = null
    private var closed = false

    /** Bounded local cleanup diagnostic; never records subscription IDs or platform messages. */
    @Volatile internal var cleanupFailureObserved = false
        private set

    fun select(subscriptionId: Int?) {
        val replacement: OwnedRegistration?
        val oldHandle: AutoCloseable?
        synchronized(lock) {
            if (closed) return
            if (subscriptionId != null && subscriptionId >= 0 &&
                current?.selectedId == subscriptionId) return
            oldHandle = current?.let(::detachLocked)
            replacement = subscriptionId?.takeIf { it >= 0 }?.let { OwnedRegistration(it) }
            current = replacement
        }
        closeHandle(oldHandle)
        replacement?.let { owned ->
            try {
                if (!mainDispatch { start(owned) }) retire(owned)
            } catch (failure: Exception) {
                preserveInterrupt(failure)
                retire(owned)
            }
        }
    }

    fun observe(): CompleteSelectionSnapshot? {
        val ticket = synchronized(lock) { current?.let(::ticketLocked) } ?: return null
        return observe(ticket)
    }

    /** Memory only, including after a blocking platform read or listener cleanup. */
    fun isCurrent(snapshot: CompleteSelectionSnapshot): Boolean = synchronized(lock) {
        current?.let { it.succeeded && it.initialCallback && it.observer.isCurrent(snapshot) } == true
    }

    /** Local privacy declaration only. No framework reread or live authority is issued here. */
    fun privacyProjection(snapshot: CompleteSelectionSnapshot): CompleteSetPrivacyProjectionV2? {
        val owned = synchronized(lock) {
            current?.takeIf { it.succeeded && it.initialCallback && it.observer.isCurrent(snapshot) }
        } ?: return null
        // UUID generation and canonical hashing must not delay callback/selection withdrawal.
        val projection = CompleteSetPrivacyProjectionV2.issue(owned.observer, snapshot) ?: return null
        return synchronized(lock) {
            projection.takeIf { current === owned && owned.succeeded && owned.initialCallback &&
                owned.observer.isCurrent(snapshot) && projection.isCurrent() }
        }
    }

    fun permissionLost() = withdraw(permanently = false)
    fun stop() = withdraw(permanently = false)
    override fun close() = withdraw(permanently = true)

    private fun withdraw(permanently: Boolean) {
        val handle = synchronized(lock) {
            if (permanently) closed = true
            current?.let(::detachLocked)
        }
        closeHandle(handle)
    }

    private fun start(owned: OwnedRegistration) {
        val claimed = synchronized(lock) {
            if (current !== owned || owned.startClaimed) false
            else { owned.startClaimed = true; true }
        }
        if (!claimed) return
        val handle = try {
            if (apiLevel() < 33 || !source.permissionGranted()) {
                retire(owned)
                return
            }
            if (!owns(owned)) return
            source.register { changed(owned) }
        } catch (failure: Exception) {
            // The source owns cleanup of a listener whose registration never returned a handle.
            preserveInterrupt(failure)
            retire(owned)
            return
        }
        val retained = synchronized(lock) {
            if (current === owned && owned.observer.registrationSucceeded(owned.token)) {
                owned.handle = handle
                owned.succeeded = true
                true
            } else {
                if (current === owned) detachLocked(owned)
                false
            }
        }
        if (!retained) {
            closeHandle(handle)
            return
        }
        val ticket = synchronized(lock) { ticketLocked(owned) }
        ticket?.let(::schedule)
    }

    private fun changed(owned: OwnedRegistration) {
        var handle: AutoCloseable? = null
        val ticket = synchronized(lock) {
            if (current !== owned) return
            if (owned.callbackRevision == Long.MAX_VALUE) {
                handle = detachLocked(owned)
                null
            } else {
                owned.callbackRevision++
                if (!owned.observer.subscriptionsChanged(owned.token)) {
                    handle = detachLocked(owned)
                    null
                } else {
                    owned.initialCallback = true
                    ticketLocked(owned)
                }
            }
        }
        closeHandle(handle)
        ticket?.let(::schedule)
    }

    private fun schedule(ticket: ReadTicket) {
        if (!synchronized(lock) { ownsTicketLocked(ticket) }) return
        try {
            reads.execute { observe(ticket) }
        } catch (failure: Exception) {
            preserveInterrupt(failure)
            retire(ticket.registration, ticket.revision)
        }
    }

    private fun observe(ticket: ReadTicket): CompleteSelectionSnapshot? {
        if (!synchronized(lock) { ownsTicketLocked(ticket) }) return null
        val snapshot = ticket.registration.observer.observeSelected(ticket.selectedId)
        if (snapshot == null) {
            // An old read crossing a callback must not retire its new revision or replacement.
            retire(ticket.registration, ticket.revision)
            return null
        }
        return synchronized(lock) {
            snapshot.takeIf { ownsTicketLocked(ticket) &&
                ticket.registration.observer.isCurrent(snapshot) }
        }
    }

    private fun readComplete(owned: OwnedRegistration): CompleteSubscriptionRead? {
        if (!owns(owned)) return null
        return try {
            val beforeApi = apiLevel()
            if (beforeApi < 33 || !source.permissionGranted() || !owns(owned)) return null
            val all = source.readComplete() ?: return null
            // Refuse the whole result before this adapter maps any rows. Never truncate peers.
            if (all.size > MAX_OBSERVED_ROWS) return null
            val rows = all.map {
                SubscriptionObservationRow(it.subscriptionId,
                    if (it.embedded) ObservedSubscriptionKind.EMBEDDED else ObservedSubscriptionKind.PHYSICAL,
                    it.cardId, it.portIndex, it.logicalSlotIndex)
            }
            val afterApi = apiLevel()
            if (afterApi != beforeApi || afterApi < 33 || !source.permissionGranted() || !owns(owned)) return null
            CompleteSubscriptionRead(afterApi, ordinaryPermissionGranted = true,
                readable = true, complete = true, rows = rows)
        } catch (failure: Exception) {
            preserveInterrupt(failure)
            null
        }
    }

    private fun owns(owned: OwnedRegistration) = synchronized(lock) { current === owned }

    private fun ticketLocked(owned: OwnedRegistration): ReadTicket? =
        if (current === owned && owned.succeeded && owned.initialCallback)
            ReadTicket(owned, owned.callbackRevision, owned.selectedId) else null

    private fun ownsTicketLocked(ticket: ReadTicket) = current === ticket.registration &&
        ticket.registration.succeeded && ticket.registration.initialCallback &&
        ticket.registration.callbackRevision == ticket.revision &&
        ticket.registration.selectedId == ticket.selectedId

    private fun retire(owned: OwnedRegistration, revision: Long? = null) {
        val handle = synchronized(lock) {
            if (current !== owned || (revision != null && owned.callbackRevision != revision)) null
            else detachLocked(owned)
        }
        closeHandle(handle)
    }

    /** Caller holds only the adapter lock; retirement precedes all framework cleanup. */
    private fun detachLocked(owned: OwnedRegistration): AutoCloseable? {
        check(current === owned)
        current = null
        owned.observer.registrationFailed(owned.token)
        owned.succeeded = false
        owned.initialCallback = false
        return owned.handle.also { owned.handle = null }
    }

    private fun closeHandle(handle: AutoCloseable?) {
        try { handle?.close() }
        catch (failure: Exception) {
            cleanupFailureObserved = true
            preserveInterrupt(failure)
        }
    }

    private fun preserveInterrupt(failure: Exception) {
        if (failure is InterruptedException) Thread.currentThread().interrupt()
    }

    /** One-way test seam; it accepts no saved epoch, observation or authority. */
    internal fun advanceCallbackRevisionToLimitForTest() = synchronized(lock) {
        current?.callbackRevision = Long.MAX_VALUE
    }

    private companion object { const val MAX_OBSERVED_ROWS = 256 }
}
