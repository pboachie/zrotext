// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class CaptureIntent03VectorTest {
    private fun vector() = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-capture-01.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private fun bytes(v: JSONObject, name: String) = Profile03ExecutionFixture.unhex(v.getString(name))
    private fun sha(b: ByteArray) = Profile03InboundFixture.sha(b)
    @Test fun independentlyFramedExtremaHaveRealOriginalProofsConsentAndTwoDistinctRole04Signatures() {
        val v = vector(); val pin = bytes(v, "root_pin"); val prior = bytes(v, "manifest02")
        val core = bytes(v, "core500"); val bundle = bytes(v, "bundle628")
        val original = Profile03OriginalBindingProof.verify(bytes(v, "registration_evidence"), bytes(v, "activation_evidence"),
            core, pin, bytes(v, "device_enrollment_point"), core.copyOfRange(256, 288), v.getString("origin"))
        assertEquals(3_000L, original.acceptedMs)
        assertTrue(ConversationContentCrypto.verifyRaw(bundle.copyOfRange(500, 564), original.devicePoint(),
            ReviewedIntent03.framed("ZTSE/line/payload-profile/device/v1", core)))
        assertTrue(ConversationContentCrypto.verifyRaw(bundle.copyOfRange(564, 628), bytes(v, "original_approval_point"),
            ReviewedIntent03.framed("ZTSE/line/payload-profile/owner/v1", core + sha(bundle.copyOfRange(500, 564)))))
        val checkpoint = Draft03ManifestAuthority.Accepted02Checkpoint(pin, core.copyOfRange(8, 24), bytes(v, "root_fingerprint"),
            1, 1, sha(prior.copyOfRange(0, prior.size - 64)), ByteArray(32), sha(prior), v.getLong("prior_accepted_ms"))
        val authority = Draft03ManifestAuthority.verifyFrom02(bytes(v, "manifest03"), prior, checkpoint, 11_220)
        for (name in listOf("minimum", "maximum")) {
            val c = v.getJSONObject(name); val interval = c.getJSONObject("interval")
            val s = ConversationInterval03.Statement.decode(bytes(interval, "statement"))
            val roles = authority.intervalKeys(s, bytes(v, "reader_point"), 11_220)
            assertFalse(roles.phonePoint().contentEquals(bytes(v, "device_enrollment_point")))
            assertFalse(roles.browserPoint().contentEquals(bytes(v, "original_approval_point")))
            assertTrue(ConversationContentCrypto.verifyRaw(bytes(interval, "owner_signature"), roles.browserPoint(),
                ConversationInterval03.requestTranscript(s)))
            assertTrue(ConversationContentCrypto.verifyRaw(bytes(interval, "phone_signature"), roles.phonePoint(),
                ConversationInterval03.approvalTranscript(s, bytes(interval, "owner_signature"))))
            assertTrue(ConversationContentCrypto.verifyRaw(bytes(interval, "installed_signature"), roles.phonePoint(),
                ConversationInterval03.installedTranscript(s, bytes(interval, "owner_signature"), bytes(interval, "phone_signature"))))
            val intent = CaptureIntent03.decode(bytes(c, "intent"))
            assertEquals(c.getInt("intent_bytes"), intent.bytes().size)
            assertEquals(UUID.fromString(c.getString("capture_id")), intent.identities.capture)
            assertEquals(1L, intent.times.selectionEpoch)
            assertArrayEquals(bytes(c, "intent_transcript"), intent.transcript())
            assertArrayEquals(bytes(c, "intent_sha256"), intent.sha256())
            intent.requireSignature(bytes(c, "intent_signature"), roles.phonePoint())
            assertFalse(ConversationContentCrypto.verifyRaw(bytes(c, "envelope_signature"), roles.phonePoint(), intent.transcript()))
            val expected = Draft03ManifestAuthority.InboundRequest(ReviewedIntent03.uuid(s.account),
                ReviewedIntent03.uuid(intent.identities.capture), ReviewedIntent03.uuid(s.device), ReviewedIntent03.uuid(s.line),
                bytes(c, "peer_hex"), s.phoneSignerKeyId, intent.recipients())
            val proof = intent.requireEnvelope(bytes(c, "envelope"), authority, expected, 11_220)
            assertArrayEquals(bytes(c, "unsigned_sha256"), proof.sha256())
            assertArrayEquals(sha(bytes(c, "envelope")), intent.commitments.envelope())
            assertArrayEquals(s.sha256(), intent.commitments.intervalStatement())
            assertArrayEquals(sha(bytes(interval, "owner_signature")), intent.commitments.ownerSignature())
            assertArrayEquals(sha(bytes(interval, "phone_signature")), intent.commitments.phoneSignature())
            assertArrayEquals(sha(bytes(interval, "installed_signature")), intent.commitments.installedSignature())
            assertArrayEquals(bytes(v, "physical_digest"), ConversationInterval03.originalPhysicalDigest(s.account, s.device,
                s.line, s.binding, s.electionCommitment, s.deviceSessionDigest, UUID.fromString(v.getString("old_binding_id")),
                bytes(v, "activation_evidence")))
        }
    }
}
