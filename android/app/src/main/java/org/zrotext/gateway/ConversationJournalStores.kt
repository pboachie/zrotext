// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Room

/**
 * Owns the two dormant journals. The host opens them on its worker only after a deliberate user
 * action, and disables admission before close. A DAO is storage, never permission to capture/send.
 * No connection, installation, consent, capture or key provisioning occurs here.
 */
internal class ConversationJournalStores(context: Context) : AutoCloseable {
    enum class Reason { CLOSED, STORAGE_UNAVAILABLE }
    class Failure(val reason: Reason) : IllegalStateException("Conversation journals unavailable")

    private val application = checkNotNull(context.applicationContext)
    private val gate = Any()
    private var closed = false
    private class Opened(val handles: Handles, val capture: ConversationCaptureDatabase,
                         val sends: ConversationSendDatabase)
    private var opened: Opened? = null

    /** Opens and validates both existing schemas before exposing either DAO. */
    fun openForUserAction(): Handles = synchronized(gate) {
        if (closed) throw Failure(Reason.CLOSED)
        opened?.let { return@synchronized it.handles }
        var capture: ConversationCaptureDatabase? = null
        var sends: ConversationSendDatabase? = null
        try {
            capture = Room.databaseBuilder(application, ConversationCaptureDatabase::class.java, CAPTURE_FILE)
                .addMigrations(ConversationCaptureDatabase.MIGRATION_1_2,
                    ConversationCaptureDatabase.MIGRATION_2_3).build()
            capture.openHelper.writableDatabase
            sends = Room.databaseBuilder(application, ConversationSendDatabase::class.java, SEND_FILE).build()
            sends.openHelper.writableDatabase
            Handles(this).also { opened = Opened(it, capture, sends) }
        } catch (_: Exception) {
            // A failed second open must not leak the first database or erase either durable fence.
            try { sends?.close() } catch (_: Exception) { /* Still close the first database. */ }
            try { capture?.close() } catch (_: Exception) { /* No handle was published. */ }
            throw Failure(Reason.STORAGE_UNAVAILABLE)
        }
    }

    internal class Handles internal constructor(
        private val owner: ConversationJournalStores
    ) {
        val capture: ConversationCaptureDao get() = owner.capture(this)
        val sends: ConversationSendDao get() = owner.sends(this)
        fun requireOpen() = owner.requireOpen(this)
        override fun toString() = "ConversationJournalHandles(redacted)"
    }

    private fun requireOpen(handles: Handles) = synchronized(gate) {
        if (closed || opened?.handles !== handles) throw Failure(Reason.CLOSED)
    }
    private fun capture(handles: Handles) = synchronized(gate) {
        requireOpen(handles)
        checkNotNull(opened).capture.journal()
    }
    private fun sends(handles: Handles) = synchronized(gate) {
        requireOpen(handles)
        checkNotNull(opened).sends.sends()
    }

    /** Idempotent; a captured old DAO does not bypass the host's admission lifecycle fence. */
    override fun close() = synchronized(gate) {
        if (closed) return@synchronized
        closed = true
        val old = opened
        opened = null
        if (old != null) {
            try { old.sends.close() } finally { old.capture.close() }
        }
    }
    override fun toString() = "ConversationJournalStores(redacted)"

    companion object {
        internal const val CAPTURE_FILE = "zrotext-conversation-capture.db"
        internal const val SEND_FILE = "zrotext-conversation-send.db"
    }
}
