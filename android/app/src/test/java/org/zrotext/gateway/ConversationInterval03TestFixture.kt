// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/** Public-proof/current-adapter component fixture with the real synthetic v2 RAM issuer.
 * It is not an authenticated server, Android hardware custody or a shipping install ACK.
 */
internal class ConversationInterval03TestFixture(val f: Profile03ExecutionFixture = Profile03ExecutionFixture(distinctEventSigner = true),
    val deviceSession: ByteArray = ByteArray(32) { 31 }) : AutoCloseable {
    val physical = ByteArray(32) { 32 }
    fun statement(id: Long = 14, end: Long = 100_800, issued: Long = 100_000): ConversationInterval03.Statement {
        val peer = "+12".toByteArray(Charsets.US_ASCII)
        val statement = ByteBuffer.allocate(695).put(byteArrayOf(90, 84, 67, 65, 3, 3, 3, 0))
            .put(f.account).put(f.device).put(f.lineId).put(ReviewedIntent03.uuid(f.newBinding))
            .put(ReviewedIntent03.uuid(UUID(0, id))).put(ReviewedIntent03.uuid(UUID(0, id + 100)))
            .put(ReviewedIntent03.uuid(f.ownerUser)).put(ReviewedIntent03.uuid(f.ownerSession)).put(ReviewedIntent03.uuid(UUID(0, id + 200)))
            .putLong(2).putLong(1).putLong(2).putLong(1).putLong(issued).putLong(issued + 700).putLong(issued).putLong(end)
            .put(Profile03ExecutionFixture.keyId(f.reader, false)).put(Profile03ExecutionFixture.keyId(f.archive, false))
            .put(Profile03ExecutionFixture.keyId(f.eventSigning, true)).put(Profile03ExecutionFixture.keyId(f.signer, true))
            .put(f.fingerprint).put(f.authority.digest).put(f.accepted.electionCommitment).put(f.accepted.electionBundleSha256)
            .put(Profile03ExecutionFixture.sha(ReviewedIntent03.framed("ZTSE/line/payload-profile/owner-session/v1",
                f.account + ReviewedIntent03.uuid(f.ownerUser) + ReviewedIntent03.uuid(f.ownerSession))))
            .put(Profile03ExecutionFixture.unhex(f.session.originHash)).put(deviceSession).put(physical)
            .put(Profile03ExecutionFixture.sha(ReviewedIntent03.uuid(UUID(0, id + 300))))
            .put(25).put(ConversationInterval03.DISCLOSURE_VERSION.toByteArray(Charsets.US_ASCII))
            .put(Profile03ExecutionFixture.sha(ConversationInterval03.DISCLOSURE.toByteArray(Charsets.UTF_8)))
            .put(peer.size.toByte()).put(peer).put(0).array()
        return ConversationInterval03.Statement.decode(statement)
    }
    fun proof(s: ConversationInterval03.Statement = statement()): ConversationInterval03Proof {
        val owner = Profile03ExecutionFixture.rawSign(f.signer, ConversationInterval03.requestTranscript(s))
        val phone = Profile03ExecutionFixture.rawSign(f.eventSigning, ConversationInterval03.approvalTranscript(s, owner))
        val installed = Profile03ExecutionFixture.rawSign(f.eventSigning, ConversationInterval03.installedTranscript(s, owner, phone))
        return ConversationInterval03Proof(s, owner, s.issuedMs + 1, phone, s.issuedMs + 2, installed, s.issuedMs + 3)
    }
    fun permission(proof: ConversationInterval03Proof = proof(), phase: String = "active", kind: String = "fetch",
        request: UUID = f.attempt): JSONObject = JSONObject().put("v", 1).put("kind", "interval_permission03")
        .put("request_kind", kind).put("request_id", request).put("interval_id", proof.statement.interval)
        .put("statement_sha256", b64(proof.statement.sha256())).put("statement", b64(proof.statement.bytes()))
        .put("owner_signature", if (phase == "reserved") JSONObject.NULL else b64(proof.ownerSignature()))
        .put("requested_ms", if (phase == "reserved") JSONObject.NULL else proof.requestedMs.toString())
        .put("phone_signature", if (phase in setOf("reserved", "requested")) JSONObject.NULL else b64(checkNotNull(proof.phoneSignature())))
        .put("approved_ms", if (phase in setOf("reserved", "requested")) JSONObject.NULL else proof.approvedMs.toString())
        .put("installed_signature", if (phase == "active") b64(checkNotNull(proof.installedSignature())) else JSONObject.NULL)
        .put("installed_ms", if (phase == "active") proof.installedMs.toString() else JSONObject.NULL)
        .put("phase", phase).put("device_session_digest", b64(deviceSession)).put("physical_selection_digest", b64(physical))
        .put("owner_session_digest", b64(proof.statement.ownerSessionDigest)).put("compared_ms", f.now.toString())
        .put("permission_expires_ms", "100600").put("readers", JSONArray())
    fun selected() = Profile03CurrentReader.Selection(f.election, f.authority, f.currentSelection, f.installed,
        f.binding, f.ownerUser, f.ownerSession, 1, f.line.selected, f.line.cards(), checkNotNull(f.binding.installedSelectionV2()), deviceSession, physical)
    fun decode(json: JSONObject) = ConversationInterval03Permission.decode(Profile03Json.nested(Profile03Json.objectValue(
        JSONObject().put("interval_permission", json).toString().toByteArray()), "interval_permission"))
    override fun close() = f.close()
    companion object { fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes) }
}
