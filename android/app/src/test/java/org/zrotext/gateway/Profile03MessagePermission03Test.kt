// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Public response correlation and genuine synthetic interval proofs only. A candidate
 * projection is not authenticated transport, installed ancestry, hardware or a phone ACK.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03MessagePermission03Test {
    private fun projection(v: ConversationInterval03TestFixture): JSONObject {
        val f = v.f
        return JSONObject().put("v", 1).put("kind", "message_manifest_permission03").put("request_kind", "fetch")
            .put("request_id", f.attempt).put("fetch_transcript_sha256", b64(Profile03ExecutionFixture.sha(SealedEnvelopeFetch03.transcript(f.grant))))
            .put("envelope_profile", 3).put("manifest_profile", 3).put("account_id", f.line.account).put("user_id", f.ownerUser)
            .put("owner_session_id", f.ownerSession).put("device_id", f.line.device).put("line_id", f.line.line).put("selection_epoch", "1")
            .put("origin_digest", b64(Profile03ExecutionFixture.unhex(f.session.originHash)))
            .put("owner_session_digest", b64(v.statement().ownerSessionDigest)).put("device_session_digest", b64(v.deviceSession))
            .put("site_id", "synthetic-site").put("instance_id", "synthetic-instance").put("connection_epoch", f.line.epoch.toString())
            .put("deployment_epoch", "1").put("old_binding_id", f.oldBinding).put("old_binding_generation", "1")
            .put("old_binding_proof_digest", b64(f.accepted.oldBindingProofDigest)).put("binding_id", f.newBinding).put("binding_generation", "2")
            .put("reader_key_id", b64(Profile03ExecutionFixture.keyId(f.reader, false)))
            .put("device_signing_key_id", b64(Profile03ExecutionFixture.keyId(f.enrollment, true)))
            .put("approval_key_id", b64(Profile03ExecutionFixture.keyId(f.approval, true))).put("root_fingerprint", b64(f.fingerprint))
            .put("trust_generation", "1").put("manifest_version", "2").put("manifest_digest", b64(f.authority.digest))
            .put("election_digest", b64(f.accepted.electionCommitment)).put("election_bundle_sha256", b64(f.accepted.electionBundleSha256))
            .put("compared_ms", f.now.toString()).put("permission_expires_ms", f.grant.expiresAtMs.toString())
            .put("current_manifest03", b64(f.next)).put("manifest_ancestry_sha256", b64(ByteArray(32) { 21 }))
            // Intentionally absent original proof details: correlation alone cannot promote this candidate.
            .put("evidence", JSONObject()).put("physical_selection", JSONObject().put("kind", "original_v2"))
    }
    private fun permission(v: ConversationInterval03TestFixture) =
        v.permission().put("permission_expires_ms", v.f.grant.expiresAtMs.toString())
    private fun check(v: ConversationInterval03TestFixture, current: JSONObject = projection(v),
        interval: JSONObject = permission(v), grant: SealedDispatch03Frames.Grant = v.f.grant) =
        Profile03MessagePermission03.requireFetch(current.toString().toByteArray(), v.decode(interval), grant)
    private fun packet(v: ConversationInterval03TestFixture, current: JSONObject = projection(v),
        interval: JSONObject = permission(v)) = JSONObject().put("v", 1).put("envelope", b64(v.f.envelope))
        .put("reviewed_intent", b64(v.f.intentV2Bytes)).put("reviewed_signature", b64(v.f.intentV2Signature))
        .put("accepted_ms", v.f.admittedAt.toString()).put("interval_starts_ms", "100000").put("interval_expires_ms", "100800")
        .put("selection_epoch", "1").put("current", current).put("interval_permission", interval)

    @Test fun exactAttemptTranscriptAndBothDeadlinesCorrelateWithoutInstallingOrPromotingAnyProjection(): Unit = ConversationInterval03TestFixture().use { v ->
        val before = v.f.line.db.profile03Elections().find(v.f.challenge.toString())
        check(v)
        val p = Profile03FetchPacket.decode(packet(v).toString().toByteArray(), v.f.grant)
        Profile03MessagePermission03.requireFetch(p.currentProjection(), p.intervalPermission(), v.f.grant)
        // Genuine independent interval crypto is still a different check, under actual synthetic v2 RAM continuity.
        val roles = p.intervalPermission().verifyCurrent(v.selected(), Profile03ExecutionFixture.point(v.f.reader),
            Profile03ExecutionFixture.unhex(v.f.session.originHash), v.f.now)
        assertArrayEquals(Profile03ExecutionFixture.point(v.f.eventSigning), roles.phonePoint())
        assertEquals(before, v.f.line.db.profile03Elections().find(v.f.challenge.toString()))
        assertNull(v.f.line.db.attempts().getAttempt(v.f.attempt.toString()))
        v.f.line.callback()
        assertThrows(Exception::class.java) { p.intervalPermission().verifyCurrent(v.selected(), Profile03ExecutionFixture.point(v.f.reader),
            Profile03ExecutionFixture.unhex(v.f.session.originHash), v.f.now) }
    }

    @Test fun everyGrantTranscriptFieldIsCommittedAndAnotherAttemptCannotReuseTheResponse(): Unit = ConversationInterval03TestFixture().use { v ->
        val original = v.f.grant
        val changes = mutableListOf<JSONObject>()
        for (name in listOf("account_id", "device_id", "line_id", "message_id", "attempt_id"))
            changes.add(JSONObject(original.json()).put(name, UUID(0, 999)))
        for (name in listOf("connection_epoch", "deployment_epoch", "binding_generation", "attempt_generation", "expires_at_ms", "trust_generation", "manifest_version")) {
            val json = JSONObject(original.json()); changes.add(json.put(name, json.getLong(name) + 1))
        }
        for (name in listOf("reader_key_id", "envelope_sha256", "unsigned_sha256", "manifest_digest", "root_fingerprint", "election_digest")) {
            val json = JSONObject(original.json()); val bytes = java.util.Base64.getUrlDecoder().decode(json.getString(name))
            bytes[0] = (bytes[0].toInt() xor 1).toByte(); changes.add(json.put(name, b64(bytes)))
        }
        changes.add(JSONObject(original.json()).put("segment_count", 2))
        for (changed in changes) {
            val grant = SealedDispatch03Frames.grant(changed.toString())
            assertThrows(Exception::class.java) { check(v, grant = grant) }
        }
        check(v)
    }

    @Test fun currentAndIntervalMustCoverExactlyTheUnchangedGrantAndSamePrimaryComparison(): Unit = ConversationInterval03TestFixture().use { v ->
        val expiry = v.f.grant.expiresAtMs
        for (deadline in listOf(expiry - 1, expiry + 1)) {
            assertThrows(Exception::class.java) { check(v, projection(v).put("permission_expires_ms", deadline.toString())) }
            assertThrows(Exception::class.java) { check(v, interval = permission(v).put("permission_expires_ms", deadline.toString())) }
            assertThrows(Exception::class.java) { check(v, projection(v).put("permission_expires_ms", deadline.toString()),
                permission(v).put("permission_expires_ms", deadline.toString())) }
        }
        assertThrows(Exception::class.java) { check(v, projection(v).put("compared_ms", (v.f.now - 1).toString())) }
        assertThrows(Exception::class.java) { check(v, projection(v).put("compared_ms", expiry.toString()), permission(v).put("compared_ms", expiry.toString())) }
        for (value in listOf<Any>(expiry, "0$expiry", "0", "-1"))
            assertThrows(Exception::class.java) { check(v, projection(v).put("permission_expires_ms", value)) }
    }

    @Test fun oldDeviceCaptureOrChangedClosedFieldsNeverEnterTheNewFetchGrammar(): Unit = ConversationInterval03TestFixture().use { v ->
        for (kind in listOf("message_permission03", "device_manifest_selection03", "device_selection03", "capture_permission03"))
            assertThrows(Exception::class.java) { check(v, projection(v).put("kind", kind)) }
        for (name in projection(v).keys().asSequence().toList()) {
            val changed = projection(v); changed.remove(name)
            assertThrows(Exception::class.java) { check(v, changed) }
        }
        for (changed in listOf(projection(v).put("extra", "unsupported"), projection(v).put("selection_expires_ms", "100450"),
            projection(v).put("request_kind", "capture"), projection(v).put("request_id", UUID(0, 0)),
            projection(v).put("request_id", "00000000-0000-0000-0000-00000000000B"),
            projection(v).put("fetch_transcript_sha256", b64(ByteArray(32))), projection(v).put("v", "1")))
            assertThrows(Exception::class.java) { check(v, changed) }
        val wrongInterval = permission(v).put("request_id", UUID(0, 999))
        assertThrows(Exception::class.java) { check(v, interval = wrongInterval) }
        val oldPacket = packet(v).toString().replace("\"request_kind\":\"fetch\"", "\"request_kind\":\"interval_status\"")
        assertThrows(Exception::class.java) { Profile03FetchPacket.decode(oldPacket.toByteArray(), v.f.grant) }
    }

    @Test fun physicalUnionIsRequiredAndClosedButEvenAWellFramedRefreshIsStillOnlyPublicEvidence(): Unit = ConversationInterval03TestFixture().use { v ->
        val vector = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-selection-refresh-01.json")!!.use {
            JSONObject(it.bufferedReader().readText())
        }
        val bundle = Profile03ExecutionFixture.unhex(vector.getString("bundle"))
        val refresh = JSONObject().put("kind", "owner_refresh03").put("refresh_id", UUID(0, 77)).put("bundle", b64(bundle))
            .put("accepted_ms", "100000").put("installed_ms", "100001")
        check(v, projection(v).put("physical_selection", refresh)) // Shape/correlation never creates its opaque issuer lease.
        for (physical in listOf(JSONObject().put("kind", "original_v2").put("refresh_id", UUID(0, 77)),
            JSONObject().put("kind", "unknown"), JSONObject(refresh.toString()).put("extra", "unsupported"),
            JSONObject(refresh.toString()).put("bundle", b64(bundle.copyOf(744))),
            JSONObject(refresh.toString()).put("installed_ms", "99999"), JSONObject(refresh.toString()).apply { remove("refresh_id") }))
            assertThrows(Exception::class.java) { check(v, projection(v).put("physical_selection", physical)) }
    }

    @Test fun decodedDuplicatesAndMalformedDigestStorageRefuseBeforeAnyCandidateCanBeCompared(): Unit = ConversationInterval03TestFixture().use { v ->
        val current = projection(v).toString()
        for (bytes in listOf(current.replace("\"request_id\":", "\"request_id\":\"${v.f.attempt}\",\"request_id\":").toByteArray(),
            current.replace("\"fetch_transcript_sha256\":", "\"fetch_transcript_sha256\":\"AA\",\"fetch_transcript_sha256\":").toByteArray(),
            current.replace("\"request_kind\":", "\"request_kind\":null,\"request_kind\":").toByteArray(),
            ByteArray(Profile03Json.MAX_BYTES + 1)))
            assertThrows(Exception::class.java) { Profile03MessagePermission03.requireFetch(bytes, v.decode(permission(v)), v.f.grant) }
        val original = Profile03ExecutionFixture.sha(SealedEnvelopeFetch03.transcript(v.f.grant))
        for (digest in listOf(b64(original) + "=", "AA", b64(original).replace('-', '+').replace('_', '/') + "+"))
            assertThrows(Exception::class.java) { check(v, projection(v).put("fetch_transcript_sha256", digest)) }
    }

    private fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
}
