// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject

internal object TypedOutcome03TestFixture {
    fun completed(db: SmsJournalDatabase, f: TypedHistory03Fixture): Pair<TypedSubmit03Record, TypedHistory03Source> {
        val first = f.entered(db)
        check(db.typedSubmits03().recordCallback(first.attemptId, 0, false, android.app.Activity.RESULT_OK, null, -7))
        val row = checkNotNull(db.typedSubmits03().get(first.attemptId))
        val source = db.typedHistory03().sources(row.attemptId).single()
        val (sample, _) = f.read(db, row, source.eventId)
        return row to checkNotNull(db.typedHistory03().retainFirstAssertion(source, sample))
    }
    fun upload(row: TypedSubmit03Record, fact: TypedHistory03Source, epoch: Long) = TypedOutcome03Upload(
        java.util.UUID.randomUUID().toString(), fact.eventId, fact.attemptId, fact.slot, row.commandSha256,
        checkNotNull(fact.assertionB64url), checkNotNull(fact.assertionSha256), checkNotNull(row.originalOriginSha256),
        row.originalEnrolledPoint, epoch, TypedSubmit03Record.base(TypedOutcome03Wire.request(row.command(),
            TypedOutcome03Command.decode(TypedSubmit03Record.unbase(checkNotNull(fact.assertionB64url))), epoch)))
    fun ack(command: TypedSubmit03Command, assertion: TypedOutcome03Command, epoch: Long,
        disposition: String = "recorded", state: String? = "submitted") = JSONObject()
        .put("v", 1).put("type", "payload_profile_outcome_ack03").put("connection_epoch", epoch)
        .put("event_id", assertion.eventId).put("message_id", command.messageId).put("attempt_id", command.attemptId)
        .put("submit_event_id", command.eventId).put("submit_command_sha256", Profile03ElectionEncoding.encode(command.commitment()))
        .put("event_sha256", Profile03ElectionEncoding.encode(assertion.commitment())).put("recorded_ms", "3000101")
        .put("disposition", disposition).put("resulting_state", state ?: JSONObject.NULL)
    fun reply(f: TypedHistory03Fixture, row: TypedSubmit03Record, fact: TypedHistory03Source) {
        f.respond = { request ->
            check(request.getString("type") == "payload_profile_outcome03")
            val assertion = TypedOutcome03Command.decode(TypedSubmit03Record.unbase(checkNotNull(fact.assertionB64url)))
            f.host.acceptOutcome(ack(row.command(), assertion, f.epoch).toString().toByteArray())
        }
    }
}
