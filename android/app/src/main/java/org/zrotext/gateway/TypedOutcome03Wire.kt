// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest

/** Passive, exact original211 evidence. The current outer epoch routes the authenticated
 * actor only; it is never substituted into the original command or its commitment. */
internal object TypedOutcome03Wire {
    fun request(original: TypedSubmit03Command, assertion: TypedOutcome03Command, epoch: Long): ByteArray {
        assertion.requireCommand(original); require(epoch > 0)
        // JSONObject is used only to emit owned scalars, then the strict receiving grammar
        // checks the complete result (including the required aggregate null).
        val fields = org.json.JSONObject()
            .put("v", 1).put("type", "payload_profile_outcome03").put("connection_epoch", epoch)
            .put("event_id", assertion.eventId).put("message_id", original.messageId)
            .put("attempt_id", original.attemptId).put("submit_event_id", original.eventId)
            .put("submit_command_sha256", Profile03ElectionEncoding.encode(original.commitment()))
            .put("fetch_transcript_sha256", Profile03ElectionEncoding.encode(original.fetchSha256))
            .put("submit_observed_ms", original.observedMs.toString()).put("segment_count", original.segmentCount)
            .put("evidence", TypedOutcome03Command.EVIDENCE[assertion.evidence])
            .put("observed_ms", assertion.assertionMs.toString())
            .put("segment_index", assertion.segmentIndex ?: org.json.JSONObject.NULL)
        return fields.toString().toByteArray(Charsets.UTF_8).also { requireRequest(it, original, assertion, epoch) }
    }

    fun requireRequest(raw: ByteArray, original: TypedSubmit03Command, assertion: TypedOutcome03Command, epoch: Long) {
        assertion.requireCommand(original); require(epoch > 0 && raw.size in 2..4096)
        val f = Profile03Json.outcomeRequestObject(raw)
        require(f.keys == REQUEST_KEYS && f["v"] == Profile03Json.Integer(1) &&
            f["type"] == "payload_profile_outcome03" && f["connection_epoch"] == Profile03Json.Integer(epoch))
        require(f["event_id"] == assertion.eventId && f["message_id"] == original.messageId &&
            f["attempt_id"] == original.attemptId && f["submit_event_id"] == original.eventId &&
            same(Profile03Json.binary(f, "submit_command_sha256", 32, 32), original.commitment()) &&
            same(Profile03Json.binary(f, "fetch_transcript_sha256", 32, 32), original.fetchSha256) &&
            Profile03Json.decimal(f, "submit_observed_ms") == original.observedMs &&
            f["segment_count"] == Profile03Json.Integer(original.segmentCount.toLong()) &&
            f["evidence"] == TypedOutcome03Command.EVIDENCE[assertion.evidence] &&
            Profile03Json.decimal(f, "observed_ms") == assertion.assertionMs)
        require(f["segment_index"] == (assertion.segmentIndex?.let { Profile03Json.Integer(it.toLong()) } ?: Profile03Json.Null))
    }

    class Ack private constructor(private val exact: ByteArray, val eventId: String, val recordedMs: Long,
        val historyOnly: Boolean, val resultingState: String?) {
        fun bytes() = exact.copyOf()
        override fun toString() = "TypedOutcome03Ack(immutable-history-only)"
        companion object {
            fun decode(raw: ByteArray, original: TypedSubmit03Command, assertion: TypedOutcome03Command, epoch: Long): Ack {
                assertion.requireCommand(original); require(epoch > 0 && raw.size in 2..4096)
                val owned = raw.copyOf()
                val f = Profile03Json.outcomeAckObject(owned)
                require(f.keys == ACK_KEYS && f["v"] == Profile03Json.Integer(1) &&
                    f["type"] == "payload_profile_outcome_ack03" && f["connection_epoch"] == Profile03Json.Integer(epoch) &&
                    f["event_id"] == assertion.eventId && f["message_id"] == original.messageId &&
                    f["attempt_id"] == original.attemptId && f["submit_event_id"] == original.eventId &&
                    same(Profile03Json.binary(f, "submit_command_sha256", 32, 32), original.commitment()) &&
                    same(Profile03Json.binary(f, "event_sha256", 32, 32), assertion.commitment()))
                val recorded = Profile03Json.decimal(f, "recorded_ms")
                val disposition = Profile03Json.text(f, "disposition")
                require(disposition in setOf("recorded", "history_only"))
                val state = f["resulting_state"].let { if (it === Profile03Json.Null) null else it as? String ?: error("Outcome state") }
                require(state == null || state in STATES)
                return Ack(owned, assertion.eventId, recorded, disposition == "history_only", state)
            }
        }
    }
    private val REQUEST_KEYS = setOf("v", "type", "connection_epoch", "event_id", "message_id", "attempt_id",
        "submit_event_id", "submit_command_sha256", "fetch_transcript_sha256", "submit_observed_ms", "segment_count",
        "evidence", "observed_ms", "segment_index")
    private val ACK_KEYS = setOf("v", "type", "connection_epoch", "event_id", "message_id", "attempt_id", "submit_event_id",
        "submit_command_sha256", "event_sha256", "recorded_ms", "disposition", "resulting_state")
    private val STATES = setOf("submitting", "submitted", "delivered", "delivery_unknown", "unknown", "failed")
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
}
