// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Closed correlation and real synthetic interval signatures. Empty original evidence is
 * intentional: a decoded candidate never becomes full current or platform authority. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedSubmit03WireTest {
    internal class Fixture(val v: ConversationInterval03TestFixture = ConversationInterval03TestFixture()) : AutoCloseable {
        val f get() = v.f
        val command = TypedSubmit03Command.create(f.line.account.toString(), f.line.device.toString(), UUID(0, 880).toString(),
            f.message.toString(), f.attempt.toString(), Profile03ExecutionFixture.sha(SealedEnvelopeFetch03.transcript(f.grant)),
            v.deviceSession, 1, f.now)
        fun interval(command: TypedSubmit03Command = this.command) = v.permission(kind = "submit", request = UUID.fromString(command.eventId))
            .put("permission_expires_ms", f.grant.expiresAtMs.toString())
        fun projection(command: TypedSubmit03Command = this.command): JSONObject = JSONObject().put("v", 1).put("kind", "submit_manifest_permission03").put("request_kind", "submit")
            .put("request_id", command.eventId).put("fetch_transcript_sha256", b64(command.fetchSha256))
            .put("envelope_profile", 3).put("manifest_profile", 3).put("account_id", f.line.account).put("user_id", f.ownerUser)
            .put("owner_session_id", f.ownerSession).put("device_id", f.line.device).put("line_id", f.line.line).put("selection_epoch", "1")
            .put("origin_digest", b64(f.origins.protocolDigest())).put("owner_session_digest", b64(v.statement().ownerSessionDigest))
            .put("device_session_digest", b64(v.deviceSession)).put("site_id", "synthetic-site").put("instance_id", "synthetic-instance")
            .put("connection_epoch", f.session.connectionEpoch.toString()).put("deployment_epoch", "1")
            .put("old_binding_id", f.oldBinding).put("old_binding_generation", "1").put("old_binding_proof_digest", b64(f.accepted.oldBindingProofDigest))
            .put("binding_id", f.newBinding).put("binding_generation", "2").put("reader_key_id", b64(Profile03ExecutionFixture.keyId(f.reader, false)))
            .put("device_signing_key_id", b64(Profile03ExecutionFixture.keyId(f.enrollment, true)))
            .put("approval_key_id", b64(Profile03ExecutionFixture.keyId(f.approval, true))).put("root_fingerprint", b64(f.fingerprint))
            .put("trust_generation", "1").put("manifest_version", "2").put("manifest_digest", b64(f.authority.digest))
            .put("election_digest", b64(f.accepted.electionCommitment)).put("election_bundle_sha256", b64(f.accepted.electionBundleSha256))
            .put("compared_ms", f.now.toString()).put("permission_expires_ms", f.grant.expiresAtMs.toString())
            .put("current_manifest03", b64(f.next)).put("manifest_ancestry_sha256", b64(ByteArray(32) { 21 }))
            .put("evidence", JSONObject()).put("physical_selection", JSONObject().put("kind", "original_v2"))
        fun ack(command: TypedSubmit03Command = this.command) = JSONObject().put("v", 1).put("type", "payload_profile_submit_ack03")
            .put("connection_epoch", f.session.connectionEpoch).put("event_id", command.eventId).put("message_id", command.messageId)
            .put("attempt_id", command.attemptId).put("submit_command_sha256", b64(command.commitment()))
            .put("fetch_transcript_sha256", b64(command.fetchSha256)).put("segment_count", 1).put("observed_ms", command.observedMs.toString())
            .put("accepted_ms", f.now.toString()).put("state", "submitting").put("disposition", "submit_once")
            .put("current", projection(command)).put("interval_permission", interval(command))
        fun decode(json: JSONObject = ack()) = TypedSubmit03Wire.Ack.decode(json.toString().toByteArray(), command, f.grant, f.session)
        fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
        override fun close() = v.close()
    }

    @Test fun requestAndAckKeepTheirExactDifferentFieldsetsAndOriginalCommandIdentity() {
        Fixture().use { x ->
            val raw = TypedSubmit03Wire.request(x.command, x.f.grant, x.f.session)
            val fields = Profile03Json.objectValue(raw)
            assertEquals(9, fields.size)
            assertEquals("payload_profile_submit03", fields["type"])
            assertEquals(x.command.observedMs.toString(), fields["observed_ms"])
            val originalAck = x.ack()
            val originalBytes = originalAck.toString().toByteArray()
            val ack = x.decode(originalAck)
            assertTrue(ack.submitOnce)
            val interval = ack.intervalPermission()
            interval.verifyCurrent(x.v.selected(), Profile03ExecutionFixture.point(x.f.reader), x.f.origins.protocolDigest(), x.f.now)
            assertEquals(0, x.f.line.db.typedSubmits03().submitRequest(x.command.attemptId)?.let { 1 } ?: 0)
            assertNull(x.f.line.db.typedSubmits03().get(x.command.attemptId))
            val owned = ack.bytes(); owned.fill(0)
            assertArrayEquals(originalBytes, ack.bytes())
        }
    }

    @Test fun historicalAckRequiresBothNullProjectionsAndCannotSupplyCurrentPermission() {
        Fixture().use { x ->
            val historical = x.ack().put("disposition", "history_only").put("current", JSONObject.NULL).put("interval_permission", JSONObject.NULL)
            val raw = historical.toString().toByteArray()
            val ack = x.decode(historical)
            assertFalse(ack.submitOnce)
            assertThrows(IllegalStateException::class.java) { ack.currentProjection() }
            assertThrows(IllegalStateException::class.java) { ack.intervalPermission() }
            assertThrows(IllegalArgumentException::class.java) { Profile03Json.objectValue(raw) }
            assertThrows(Exception::class.java) { x.decode(x.ack().put("disposition", "history_only").put("current", JSONObject.NULL)) }
            assertThrows(Exception::class.java) { x.decode(x.ack().put("current", JSONObject.NULL).put("interval_permission", JSONObject.NULL)) }
        }
    }

    @Test fun duplicateNamesScalarCoercionAnotherEventAndShortenedOrMismatchedDeadlinesRefuse() {
        Fixture().use { x ->
            val raw = x.ack().toString()
            assertThrows(Exception::class.java) {
                TypedSubmit03Wire.Ack.decode(raw.replaceFirst("{", "{\"event_id\":\"${x.command.eventId}\",").toByteArray(), x.command, x.f.grant, x.f.session) }
            for ((name, value) in listOf<Pair<String, Any>>("event_id" to UUID(0, 881).toString(), "connection_epoch" to "1",
                "segment_count" to "1", "observed_ms" to x.command.observedMs, "state" to "submitted", "unexpected" to "value"))
                assertThrows(Exception::class.java) { x.decode(x.ack().put(name, value)) }
            val end = x.f.grant.expiresAtMs
            for (name in listOf("current", "interval_permission")) {
                val changed = x.ack(); changed.getJSONObject(name).put("permission_expires_ms", (end - 1).toString())
                assertThrows(Exception::class.java) { x.decode(changed) }
                val time = x.ack(); time.getJSONObject(name).put("compared_ms", (x.f.now - 1).toString())
                assertThrows(Exception::class.java) { x.decode(time) }
            }
        }
    }

    @Test fun submitAndFetchDecodersCannotCoerceEachOthersKindsOrOriginalSessionCommitment() {
        Fixture().use { x ->
            val candidate = x.decode()
            assertThrows(IllegalArgumentException::class.java) {
                Profile03MessagePermission03.requireShape(Profile03Json.objectValue(candidate.currentProjection())) }
            val interval = Profile03Json.nested(Profile03Json.submitAckObject(x.ack().toString().toByteArray()), "interval_permission")
            assertThrows(IllegalArgumentException::class.java) { ConversationInterval03Permission.decode(interval) }
            val changed = x.ack()
            changed.getJSONObject("current").put("kind", "message_manifest_permission03").put("request_kind", "fetch")
            assertThrows(Exception::class.java) { x.decode(changed) }
            val rebound = x.ack()
            rebound.getJSONObject("current").put("device_session_digest", x.b64(ByteArray(32) { 48 }))
            assertThrows(Exception::class.java) { x.decode(rebound) }
        }
    }
    @Test fun acceptedTimeMustNotFollowFinalComparisonButMayPrecedeThePhonesConservativeObservation() {
        Fixture().use { x ->
            assertThrows(Exception::class.java) { x.decode(x.ack().put("accepted_ms", (x.f.now + 1).toString())) }
            // The phone's authenticated upper bound may be ahead of the primary by its RTT.
            assertTrue(x.decode(x.ack().put("accepted_ms", (x.command.observedMs - 1).toString())).submitOnce)
        }
    }
}
