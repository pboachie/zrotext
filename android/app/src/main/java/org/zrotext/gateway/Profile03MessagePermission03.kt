// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.security.MessageDigest
import java.util.UUID

/** Correlation and closed grammar only. The device-signed HTTPS source, actual local
 * installed ancestry/physical handle, interval and one-use grant remain independent.
 * Nothing decoded here installs history, reconstructs custody or authorizes an effect.
 */
internal object Profile03MessagePermission03 {
    fun requireFetch(projection: ByteArray, interval: ConversationInterval03Permission,
        input: SealedDispatch03Frames.Grant) {
        val grant = SealedDispatch03Frames.grant(input.json())
        val fields = Profile03Json.objectValue(projection)
        requireShape(fields)
        require(Profile03Json.text(fields, "request_kind") == "fetch" &&
            id(fields, "request_id") == grant.attemptId &&
            same(Profile03Json.binary(fields, "fetch_transcript_sha256", 32, 32),
                sha(SealedEnvelopeFetch03.transcript(grant))))
        val compared = Profile03Json.decimal(fields, "compared_ms")
        val deadline = Profile03Json.decimal(fields, "permission_expires_ms")
        interval.requireRequest("fetch", grant.attemptId)
        require(interval.phase == "active" && compared == interval.comparedMs && compared < deadline &&
            deadline == grant.expiresAtMs && interval.permissionExpiresMs == grant.expiresAtMs)
    }

    /** The distinct consumer calls this before any retained-proof/Room/key lookup.
     * Existing first-only/full-history/device grammars never accept these fields.
     */
    fun requireShape(fields: Map<String, Any>) {
        require(fields.keys == KEYS && fields["v"] == Profile03Json.Integer(1) &&
            fields["kind"] == "message_manifest_permission03" && fields["request_kind"] == "fetch" &&
            fields["envelope_profile"] == Profile03Json.Integer(3) && fields["manifest_profile"] == Profile03Json.Integer(3))
        val physical = Profile03Json.nested(fields, "physical_selection")
        when (physical["kind"]) {
            "original_v2" -> require(physical.keys == setOf("kind"))
            "owner_refresh03" -> {
                require(physical.keys == setOf("kind", "refresh_id", "bundle", "accepted_ms", "installed_ms"))
                id(physical, "refresh_id")
                Profile03Json.binary(physical, "bundle", 745, 745)
                val accepted = Profile03Json.decimal(physical, "accepted_ms")
                require(Profile03Json.decimal(physical, "installed_ms") >= accepted)
            }
            else -> throw IllegalArgumentException("Closed physical selection03")
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
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)
}
