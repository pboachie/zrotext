// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

/** Exact public command/ACK grammar. Only the actual same-socket one-use request owner may
 * admit this candidate to the full current/interval verifier. Decoding creates no permit. */
internal object TypedSubmit03Wire {
    class Ack private constructor(private val exact: ByteArray, private val commandSha: ByteArray,
        val eventId: String, val acceptedMs: Long, val submitOnce: Boolean,
        private val current: ByteArray?, private val interval: ConversationInterval03Permission?) {
        fun bytes() = exact.copyOf()
        fun currentProjection(): ByteArray = checkNotNull(current).copyOf()
        fun intervalPermission(): ConversationInterval03Permission = checkNotNull(interval)
        fun requireOriginal(command: TypedSubmit03Command) {
            require(eventId == command.eventId && same(commandSha, command.commitment()))
        }
        override fun toString() = "TypedSubmit03Ack(candidate-no-platform-authority)"
        companion object {
            fun decode(raw: ByteArray, command: TypedSubmit03Command, input: SealedDispatch03Frames.Grant,
                actual: SealedDispatchExecutor.Session): Ack {
                val owned = raw.copyOf()
                val grant = SealedDispatch03Frames.grant(input.json())
                requireCommand(command, grant, actual)
                val f = Profile03Json.submitAckObject(owned)
                require(f.keys == ACK_KEYS && f["v"] == Profile03Json.Integer(1) &&
                    f["type"] == "payload_profile_submit_ack03" && f["connection_epoch"] == Profile03Json.Integer(actual.connectionEpoch) &&
                    f["state"] == "submitting")
                for ((name, expected) in listOf("event_id" to command.eventId, "message_id" to command.messageId,
                    "attempt_id" to command.attemptId)) require(Profile03Json.text(f, name) == expected)
                require(same(Profile03Json.binary(f, "submit_command_sha256", 32, 32), command.commitment()) &&
                    same(Profile03Json.binary(f, "fetch_transcript_sha256", 32, 32), command.fetchSha256) &&
                    f["segment_count"] == Profile03Json.Integer(command.segmentCount.toLong()) &&
                    Profile03Json.decimal(f, "observed_ms") == command.observedMs)
                val accepted = Profile03Json.decimal(f, "accepted_ms")
                val disposition = Profile03Json.text(f, "disposition")
                if (disposition == "history_only") {
                    require(f["current"] === Profile03Json.Null && f["interval_permission"] === Profile03Json.Null)
                    return Ack(owned, command.commitment(), command.eventId, accepted, false, null, null)
                }
                require(disposition == "submit_once")
                val projection = Profile03Json.render(Profile03Json.nested(f, "current"))
                val interval = ConversationInterval03Permission.decodeSubmit(Profile03Json.nested(f, "interval_permission"))
                Profile03SubmitPermission03.requireSubmit(projection, interval, grant, command)
                require(accepted <= Profile03Json.decimal(Profile03Json.nested(f, "current"), "compared_ms"))
                return Ack(owned, command.commitment(), command.eventId, accepted, true, projection, interval)
            }
        }
    }

    fun request(command: TypedSubmit03Command, grant: SealedDispatch03Frames.Grant,
        actual: SealedDispatchExecutor.Session): ByteArray {
        requireCommand(command, grant, actual)
        return Profile03Json.render(linkedMapOf("v" to Profile03Json.Integer(1), "type" to "payload_profile_submit03",
            "connection_epoch" to Profile03Json.Integer(actual.connectionEpoch), "event_id" to command.eventId,
            "message_id" to command.messageId, "attempt_id" to command.attemptId,
            "fetch_transcript_sha256" to Profile03ElectionEncoding.encode(command.fetchSha256),
            "segment_count" to Profile03Json.Integer(command.segmentCount.toLong()), "observed_ms" to command.observedMs.toString()))
            .also { require(it.size <= 4096) }
    }

    fun requireCommand(command: TypedSubmit03Command, grant: SealedDispatch03Frames.Grant,
        actual: SealedDispatchExecutor.Session) {
        require(actual.connectionEpoch > 0 && actual.deploymentEpoch > 0 && grant.accountId == actual.accountId &&
            grant.deviceId == actual.deviceId && grant.connectionEpoch == actual.connectionEpoch &&
            grant.deploymentEpoch == actual.deploymentEpoch && command.accountId == actual.accountId.toString() &&
            command.deviceId == actual.deviceId.toString() && command.messageId == grant.messageId.toString() &&
            command.attemptId == grant.attemptId.toString() && command.segmentCount in 1..grant.segmentCount &&
            same(command.fetchSha256, TypedSubmit03Command.sha(SealedEnvelopeFetch03.transcript(grant))))
        UUID.fromString(command.eventId).also { require(it != UUID(0, 0) && it.toString() == command.eventId) }
    }

    private val ACK_KEYS = setOf("v", "type", "connection_epoch", "event_id", "message_id", "attempt_id",
        "submit_command_sha256", "fetch_transcript_sha256", "segment_count", "observed_ms", "accepted_ms", "state",
        "disposition", "current", "interval_permission")
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
}
