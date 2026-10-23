// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

/** Separate submit projection correlation. This is public metadata, never a current,
 * journal or platform capability. The actual full reader must verify every original proof,
 * installed ancestry, local interval and physical/key lifetime under its current socket. */
internal object Profile03SubmitPermission03 {
    fun requireSubmit(projection: ByteArray, interval: ConversationInterval03Permission,
        input: SealedDispatch03Frames.Grant, command: TypedSubmit03Command) {
        val grant = SealedDispatch03Frames.grant(input.json())
        val fields = Profile03Json.objectValue(projection)
        requireShape(fields)
        require(id(fields, "request_id").toString() == command.eventId &&
            command.attemptId == grant.attemptId.toString() && command.messageId == grant.messageId.toString() &&
            same(Profile03Json.binary(fields, "fetch_transcript_sha256", 32, 32), command.fetchSha256) &&
            same(command.fetchSha256, TypedSubmit03Command.sha(SealedEnvelopeFetch03.transcript(grant))) &&
            same(Profile03Json.binary(fields, "device_session_digest", 32, 32), command.originalSessionSha256))
        interval.requireRequest("submit", UUID.fromString(command.eventId))
        val compared = Profile03Json.decimal(fields, "compared_ms")
        require(interval.phase == "active" && compared == interval.comparedMs && compared < grant.expiresAtMs &&
            Profile03Json.decimal(fields, "permission_expires_ms") == grant.expiresAtMs &&
            interval.permissionExpiresMs == grant.expiresAtMs)
    }

    fun requireShape(fields: Map<String, Any>) {
        require(fields.keys == KEYS && fields["v"] == Profile03Json.Integer(1) &&
            fields["kind"] == "submit_manifest_permission03" && fields["request_kind"] == "submit" &&
            fields["envelope_profile"] == Profile03Json.Integer(3) && fields["manifest_profile"] == Profile03Json.Integer(3))
        val physical = Profile03Json.nested(fields, "physical_selection")
        when (physical["kind"]) {
            "original_v2" -> require(physical.keys == setOf("kind"))
            "owner_refresh03" -> {
                require(physical.keys == setOf("kind", "refresh_id", "bundle", "accepted_ms", "installed_ms"))
                id(physical, "refresh_id")
                Profile03Json.binary(physical, "bundle", 745, 745)
                require(Profile03Json.decimal(physical, "installed_ms") >= Profile03Json.decimal(physical, "accepted_ms"))
            }
            else -> throw IllegalArgumentException("Closed submit physical selection03")
        }
    }

    private val KEYS = setOf("v", "kind", "request_kind", "request_id", "fetch_transcript_sha256", "envelope_profile",
        "manifest_profile", "account_id", "user_id", "owner_session_id", "device_id", "line_id", "selection_epoch",
        "origin_digest", "owner_session_digest", "device_session_digest", "site_id", "instance_id", "connection_epoch",
        "deployment_epoch", "old_binding_id", "old_binding_generation", "old_binding_proof_digest", "binding_id",
        "binding_generation", "reader_key_id", "device_signing_key_id", "approval_key_id", "root_fingerprint", "trust_generation",
        "manifest_version", "manifest_digest", "election_digest", "election_bundle_sha256", "compared_ms", "permission_expires_ms",
        "evidence", "current_manifest03", "manifest_ancestry_sha256", "physical_selection")
    private fun id(fields: Map<String, Any>, name: String) =
        UUID.fromString(Profile03ClosedUnaccepted.uuid(Profile03Json.text(fields, name)))
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
}
