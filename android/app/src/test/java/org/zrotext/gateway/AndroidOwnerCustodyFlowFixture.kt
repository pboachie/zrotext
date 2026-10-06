// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.UUID
import org.json.JSONObject

/** Public synthetic codec framing; fake ports test publication gates, never cryptography. */
internal object AndroidOwnerCustodyFlowFixture {
    private val root = AndroidOwnerCustodyFixture
    val device: UUID = UUID.fromString("66666666-6666-4666-8666-666666666666")
    val line: UUID = UUID.fromString("77777777-7777-4777-8777-777777777777")
    val challenge: UUID = UUID.fromString("88888888-8888-4888-8888-888888888888")
    val pairedFingerprint = "ab".repeat(32)
    val nonce = ByteArray(32) { 5 }
    val approvalPoint = byteArrayOf(4) + ByteArray(64) { 9 }
    val approvalFingerprint = AndroidOwnerCustodyKit.hash(approvalPoint)
    val selection = AndroidOwnerCustodyFlowSelection(device, line, 1, "+12", pairedFingerprint, 0, "00".repeat(32))
    fun proposal(): ByteArray = ByteArrayOutputStream().apply {
        fun number(value: Long) = write(ByteBuffer.allocate(8).putLong(value).array())
        fun text(value: String) { val bytes = value.toByteArray(); write(ByteBuffer.allocate(2).putShort(bytes.size.toShort()).array()); write(bytes) }
        write("ZTSE/line/owner-key/register/v1\u0000".toByteArray())
        for (id in listOf(root.account, root.user, root.session, device, line)) write(root.uuid(id))
        number(1); write(root.uuid(challenge)); write(nonce); number(1000); number(61000)
        write(root.kit.pin); write(root.kit.identity.fingerprintBytes()); write(approvalPoint); write(approvalFingerprint)
        write(ByteArray(32) { 0xab.toByte() }); number(8); number(9); text("site-fixture"); text("instance-fixture"); text(root.origin)
    }.toByteArray()
    fun scope(): JSONObject {
        fun id(value: UUID) = value.toString().replace("-", "")
        return JSONObject().put("root_pin", AndroidOwnerCustodyKit.hex(root.kit.pin)).put("scope", JSONObject()
            .put("account", id(root.account)).put("user", id(root.user)).put("owner_session", id(root.session))
            .put("device", id(device)).put("line", id(line)).put("next_generation", 1)
            .put("challenge", id(challenge)).put("nonce", AndroidOwnerCustodyKit.hex(nonce))
            .put("issued_ms", 1000).put("expires_ms", 61000)
            .put("approval_fingerprint", AndroidOwnerCustodyKit.hex(approvalFingerprint)).put("paired_signing_fingerprint", pairedFingerprint)
            .put("connection_epoch", 8).put("deployment_epoch", 9).put("site_id", "site-fixture").put("instance_id", "instance-fixture").put("origin", root.origin))
    }
    fun expected() = AndroidOwnerCustodyFlowExpected.fromAuthenticatedComposition(scope().toString().toByteArray())
    fun pending(): JSONObject = JSONObject().put("v", 1).put("kind", 1).put("account_id", root.account.toString())
        .put("user_id", root.user.toString()).put("session_id", root.session.toString()).put("origin", root.origin)
        .put("root_fingerprint_hex", root.kit.identity.fingerprint)
        .put("proposal_sha256_hex", AndroidOwnerCustodyKit.hex(AndroidOwnerCustodyKit.hash(proposal())))
        .put("proposal_b64", java.util.Base64.getEncoder().encodeToString(proposal())).put("expected_context", scope())
        .put("server_now_ms", "2000").put("expires_ms", "61000")
}
