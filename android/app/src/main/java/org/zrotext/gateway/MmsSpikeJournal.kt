// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer

/** One append-only journal line. No recipient or media content, only a hash token. */
internal data class MmsSpikeEvent(
    val attemptId: String,
    val transactionId: String,
    val kind: String,
    val atMs: Long,
    val detail: String
)

/**
 * Append-only local journal for the outbound MMS spike. This is deliberately
 * not the Room evidence store: the spike ends before the protocol work begins,
 * and its file can be removed with it. Events are derived, never rewritten.
 */
internal object MmsSpikeJournal {
    const val COMPOSED = "composed"
    const val CALL_RETURNED = "call_returned"
    const val SENT_OK = "sent_ok"
    const val SENT_ERROR = "sent_error"
    const val TIMEOUT_UNKNOWN = "timeout_unknown"
    const val UNKNOWN_RESULT = "unknown_result"

    private val KINDS = setOf(COMPOSED, CALL_RETURNED, SENT_OK, SENT_ERROR,
        TIMEOUT_UNKNOWN, UNKNOWN_RESULT)
    private val TERMINAL = setOf(SENT_OK, SENT_ERROR, TIMEOUT_UNKNOWN, UNKNOWN_RESULT)
    private val ATTEMPT_ID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private val TRANSACTION_ID = Regex("^[A-Za-z0-9-]{1,64}$")
    private val DETAIL = Regex("^[ -~]{0,120}$")
    private val lock = Any()

    fun validationError(event: MmsSpikeEvent): String? = when {
        !event.attemptId.lowercase().matches(ATTEMPT_ID) -> "attempt id must be a UUID"
        !event.transactionId.matches(TRANSACTION_ID) -> "invalid transaction id"
        event.kind !in KINDS -> "unknown event kind"
        event.atMs <= 0 -> "timestamp must be positive"
        !event.detail.matches(DETAIL) -> "detail must be short printable ASCII"
        else -> null
    }

    /** Appends one event durably; a torn write is detected by [replay]. */
    fun append(file: File, event: MmsSpikeEvent) {
        check(validationError(event) == null)
        val line = "${event.attemptId}\t${event.transactionId}\t${event.kind}" +
            "\t${event.atMs}\t${event.detail}\n"
        synchronized(lock) {
            file.parentFile?.mkdirs()
            FileOutputStream(file, true).channel.use { channel ->
                channel.write(ByteBuffer.wrap(line.toByteArray(Charsets.US_ASCII)))
                channel.force(true)
            }
        }
    }

    /**
     * Returns the longest valid prefix of the journal. A line that fails
     * validation ends the replay: later lines cannot be trusted after a torn
     * or corrupt write.
     */
    fun replay(file: File): List<MmsSpikeEvent> {
        if (!file.exists()) return emptyList()
        val events = ArrayList<MmsSpikeEvent>()
        for (line in file.readLines(Charsets.US_ASCII)) {
            if (line.isEmpty()) continue
            val fields = line.split('\t')
            if (fields.size != 5) return events
            val atMs = fields[3].toLongOrNull() ?: return events
            val event = MmsSpikeEvent(fields[0], fields[1], fields[2], atMs, fields[4])
            if (validationError(event) != null) return events
            events.add(event)
        }
        return events
    }

    /** Derives the attempt state from evidence; absence never proves absence of a radio call. */
    fun attemptState(events: List<MmsSpikeEvent>): String {
        val terminalKinds = events.filter { it.kind in TERMINAL }.map { it.kind }.distinct()
        return when {
            terminalKinds.size > 1 -> "unknown"
            terminalKinds.contains(SENT_OK) -> "submitted"
            terminalKinds.contains(SENT_ERROR) -> "failed"
            terminalKinds.isNotEmpty() -> "unknown"
            events.any { it.kind == CALL_RETURNED } -> "submitting"
            events.isNotEmpty() -> "pending"
            else -> "none"
        }
    }
}
