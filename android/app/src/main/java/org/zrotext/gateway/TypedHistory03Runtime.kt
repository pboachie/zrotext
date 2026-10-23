// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import java.util.UUID
import java.util.concurrent.Executors

/** Passive first-command producer and exact outcome uploader. Closure-proof transport
 * and positive radio authority remain separate.
 * No legacy AlphaPump, key operation, pin, owner or physical permission is used here. */
internal object TypedHistory03Runtime {
    private val worker = Executors.newSingleThreadExecutor { task ->
        Thread(task, "typed-history03").also { it.isDaemon = true }
    }
    private val queueLock = Any()
    private val pending = TypedHistory03ScanQueue()
    private var running = false
    private var wakeVersion = 0L
    // Explicit sync walks bounded pages. This is navigation only, never evidence/authority.
    private var syncHost: TypedHistory03Connections.Host? = null
    private var syncAfter = ""
    private val syncRunning = java.util.concurrent.atomic.AtomicBoolean(false)

    fun connected(context: Context) = enqueue(context, null)
    fun callbackRecorded(context: Context, attempt: String) = enqueue(context, attempt)

    /** A user action authorizes at most one bounded page of exact historical replays.
     * Neither reconnect nor a passive scan is an instruction to retry uncertain I/O. */
    fun syncSavedReports(context: Context, status: (String) -> Unit) {
        if (!syncRunning.compareAndSet(false, true)) { status("Delivery update sync is already pending."); return }
        val app = context.applicationContext
        val selected = TypedHistory03Connections.current() ?: run {
            syncRunning.set(false); status("Connect this phone to sync saved delivery updates."); return
        }
        worker.execute {
            try {
                // The explicit action keeps the actual actor selected at the click. A later
                // connection/realm cannot adopt a queued user's sync decision.
                val host = selected.also { it.requireCurrent() }
                if (syncHost !== host) { syncHost = host; syncAfter = "" }
                val journal = SmsJournalDatabase.get(app)
                val slots = TypedOutcome03Pages.select(syncAfter, host::requireCurrent) { after ->
                    journal.typedOutcomes03().unacknowledged(host.identity.accountId, host.identity.deviceId,
                        host.identity.originHash, TypedSubmit03Record.base(host.point()), after)
                }
                var acknowledged = 0
                for (slot in slots) {
                    syncAfter = slot
                    val fact = journal.typedHistory03().source(slot) ?: continue
                    try { if (TypedOutcome03Uploader.report(journal, host, fact, explicitReplay = true)) acknowledged++ }
                    catch (_: Exception) { /* The exact original burn remains pending. */ }
                }
                if (slots.size < 16) syncAfter = ""
                status(if (slots.isEmpty()) "No saved delivery updates to sync."
                    else "Synced $acknowledged delivery updates. Unconfirmed updates remain saved.")
            } catch (_: Exception) { status("Delivery updates remain saved. Reconnect this phone and sync again.") }
            finally { syncRunning.set(false) }
        }
    }

    /** The caller's genuine RAM lifetime is withdrawn synchronously BEFORE queue/writer
     * waits. This entry does not acquire a clock, sign a proof or report server success. */
    fun closeBeforeEntry(context: Context, original: TypedSubmit03Record, withdraw: () -> Unit) {
        withdraw()
        val app = context.applicationContext
        val closure = UUID.randomUUID().toString()
        worker.execute {
            try {
                val journal = SmsJournalDatabase.get(app)
                journal.typedSubmits03().beginClosing(original, closure)?.let { enqueue(app, it.attemptId) }
            } catch (_: Exception) {
                // Missing writer/result is UNKNOWN. The withdrawn RAM lifetime never returns.
            }
        }
    }

    private fun enqueue(context: Context, attempt: String?) {
        val app = context.applicationContext
        val launch = synchronized(queueLock) {
            wakeVersion++
            pending.enqueue(attempt)
            if (running) false else { running = true; true }
        }
        if (launch) worker.execute { drain(app) }
    }

    private fun drain(app: Context) {
        var seenWake = synchronized(queueLock) { wakeVersion }
        try {
            while (true) {
                val host = TypedHistory03Connections.current() ?: return
                val task = synchronized(queueLock) {
                    seenWake = wakeVersion
                    pending.nextQueued() ?: if (pending.needsScan()) "" else null
                } ?: return
                val journal = SmsJournalDatabase.get(app)
                if (task.isNotEmpty()) {
                    try { prepareAttempt(journal, host, task) } catch (_: Exception) { /* Original history stays pending. */ }
                    continue
                }
                val traversal = synchronized(queueLock) { pending.page(host) }
                val commandPage = journal.typedHistory03().pendingAttempts(host.identity.accountId, host.identity.deviceId,
                    host.identity.originHash, TypedSubmit03Record.base(host.point()), traversal.after)
                val reportPage = journal.typedOutcomes03().pendingAutomaticAttempts(host.identity.accountId, host.identity.deviceId,
                    host.identity.originHash, TypedSubmit03Record.base(host.point()), traversal.after)
                val page = (commandPage + reportPage).distinct().sorted().take(16)
                for (attempt in page) try { prepareAttempt(journal, host, attempt) } catch (_: Exception) { /* No rearm. */ }
                synchronized(queueLock) { pending.complete(traversal, page) }
            }
        } catch (_: Exception) {
            // A storage/read failure is UNKNOWN, not an autonomous retry loop.
        } finally {
            val newWake = synchronized(queueLock) {
                running = false
                // Original facts/requests are durable. A later actual callback/host connection
                // can scan them; no completed command is reconstructed or automatically resent.
                pending.hasWork() && wakeVersion != seenWake
            }
            if (newWake && TypedHistory03Connections.current() != null) {
                val launch = synchronized(queueLock) { if (running) false else { running = true; true } }
                if (launch) worker.execute { drain(app) }
            }
        }
    }

    private fun prepareAttempt(journal: SmsJournalDatabase, host: TypedHistory03Connections.Host, attempt: String) {
        val row = journal.typedSubmits03().get(attempt) ?: return
        host.requireOriginal(row)
        if (row.phase == "pre_entry_closing" && !row.conflict) {
            val request = freshRead(journal, host, row, checkNotNull(row.closingId), "closure") ?: return
            val current = journal.typedSubmits03().get(attempt) ?: return
            val retained = journal.typedHistory03().clock(request.requestId) ?: return
            journal.typedSubmits03().finishClosing(current, retained, request)
        }
        for (source in journal.typedHistory03().sources(attempt)) {
            try {
                val retained = if (source.assertionB64url != null) source else {
                    val current = journal.typedSubmits03().get(attempt) ?: return
                    host.requireOriginal(current)
                    val sample = freshRead(journal, host, current, source.eventId, "assertion") ?: continue
                    journal.typedHistory03().retainFirstAssertion(source, sample) ?: continue
                }
                TypedOutcome03Uploader.report(journal, host, retained, explicitReplay = false)
            } catch (_: Exception) { /* No automatic replay of a possibly entered report. */ }
        }
    }

    /** New read, not a retry: only a subject whose exact command does not exist may enter.
     * A cold/UNKNOWN original request stays burned and never becomes this fresh nonce. */
    private fun freshRead(journal: SmsJournalDatabase, host: TypedHistory03Connections.Host,
        row: TypedSubmit03Record, subject: String, kind: String): TypedHistory03Clock.Sample? {
        Capture03IngressGate.requireOutside()
        host.requireOriginal(row)
        val id = UUID.randomUUID().toString()
        val query = TypedHistory03Wire.Query(id, row.messageId, row.attemptId)
        val candidate = TypedHistory03Request(id, row.attemptId, row.messageId, row.commandSha256, subject, kind,
            row.accountId, row.deviceId, checkNotNull(row.originalOriginSha256), row.originalEnrolledPoint,
            host.epoch, host.lineVersion, TypedSubmit03Record.base(TypedHistory03Wire.request(host.epoch, query)))
        val dao = journal.typedHistory03()
        if (!dao.reserveClock(row, candidate, host::requireCurrent)) return null
        val entry = dao.enterClock(candidate, host::requireCurrent) ?: return null
        val entered = checkNotNull(dao.clock(id))
        val sample = host.request(row, entry)
        // Historical retention may complete after withdrawal; it cannot publish a new clock.
        if (!dao.retainClockReply(entered, sample.bytes())) return null
        sample.nowFor(row, checkNotNull(dao.clock(id)))
        return sample
    }
}
