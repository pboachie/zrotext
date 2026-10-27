// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import java.util.concurrent.atomic.AtomicBoolean

/** Permanent first-I/O burn, not an effect capability. It is inserted only for the exact
 * genuinely NEW typed attempt; absence never repairs an old attempt or renews a command. */
@Entity(tableName = "typed_submit03_requests", indices = [Index(value = ["eventId"], unique = true)])
internal data class TypedSubmit03Request(@PrimaryKey val attemptId: String, val eventId: String,
    val commandSha256: String, val connectionEpoch: Long, val requestB64url: String) {
    fun bytes() = TypedSubmit03Record.unbase(requestB64url)
    fun requireOriginal(row: TypedSubmit03Record) {
        row.requireShape()
        val command = row.command()
        require(row.originalOriginSha256 != null && attemptId == row.attemptId && eventId == row.eventId &&
            commandSha256 == row.commandSha256 && connectionEpoch > 0)
        val raw = bytes(); require(raw.size <= 4096)
        val f = Profile03Json.objectValue(raw)
        require(f.keys == setOf("v", "type", "connection_epoch", "event_id", "message_id", "attempt_id",
            "fetch_transcript_sha256", "segment_count", "observed_ms") && f["v"] == Profile03Json.Integer(1) &&
            f["type"] == "payload_profile_submit03" && f["connection_epoch"] == Profile03Json.Integer(connectionEpoch) &&
            f["event_id"] == command.eventId && f["message_id"] == command.messageId && f["attempt_id"] == command.attemptId &&
            f["fetch_transcript_sha256"] == Profile03ElectionEncoding.encode(command.fetchSha256) &&
            f["segment_count"] == Profile03Json.Integer(command.segmentCount.toLong()) &&
            f["observed_ms"] == command.observedMs.toString())
    }
    override fun toString() = "TypedSubmit03Request(permanent-first-I/O-burn)"
}

/** Single-process ticket only after the actual writer returns from committing its burn.
 * It permits at most one send of these public bytes, never a platform operation. */
internal class TypedSubmit03TransportEntry internal constructor(val request: TypedSubmit03Request,
    val original: TypedSubmit03Record) {
    private val unused = AtomicBoolean(true)
    fun consume(): ByteArray {
        check(unused.compareAndSet(true, false))
        request.requireOriginal(original)
        return request.bytes()
    }
}
