// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ConversationInterval03Test {
    private fun vector() = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-conversation-interval-01.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private fun bytes(json: JSONObject, field: String) = Profile03ExecutionFixture.unhex(json.getString(field))
    @Test fun independentVectorMatchesAllThreeExactDomainsWithDistinctActualRole04AndRole05() {
        val vector = vector()
        for (name in listOf("without_integrations", "with_integration")) {
            val v = vector.getJSONObject(name); val s = ConversationInterval03.Statement.decode(bytes(v, "statement"))
            assertArrayEquals(bytes(v, "statement_sha256"), s.sha256())
            assertArrayEquals(bytes(v, "request_transcript"), ConversationInterval03.requestTranscript(s))
            assertArrayEquals(bytes(v, "approval_transcript"), ConversationInterval03.approvalTranscript(s, bytes(v, "owner_signature")))
            assertArrayEquals(bytes(v, "installed_transcript"), ConversationInterval03.installedTranscript(s,
                bytes(v, "owner_signature"), bytes(v, "phone_signature")))
            assertTrue(ConversationContentCrypto.verifyRaw(bytes(v, "owner_signature"), bytes(vector, "browser_role5_point"), bytes(v, "request_transcript")))
            assertTrue(ConversationContentCrypto.verifyRaw(bytes(v, "phone_signature"), bytes(vector, "phone_role4_point"), bytes(v, "approval_transcript")))
            assertTrue(ConversationContentCrypto.verifyRaw(bytes(v, "installed_signature"), bytes(vector, "phone_role4_point"), bytes(v, "installed_transcript")))
            assertFalse(ConversationContentCrypto.verifyRaw(bytes(v, "phone_signature"), bytes(vector, "device_enrollment_point"), bytes(v, "approval_transcript")))
            assertFalse(ConversationContentCrypto.verifyRaw(bytes(v, "owner_signature"), bytes(vector, "original_approval_point"), bytes(v, "request_transcript")))
        }
    }
    @Test fun physicalCommitmentUsesOriginalBindingAndExactHighSActivationBytesWithoutCreatingPermission() {
        val v = vector(); val s = ConversationInterval03.Statement.decode(bytes(v.getJSONObject("without_integrations"), "statement"))
        val actual = ConversationInterval03.originalPhysicalDigest(s.account, s.device, s.line, s.binding,
            s.electionCommitment, s.deviceSessionDigest, UUID.fromString(v.getString("old_binding_id")), bytes(v, "activation_evidence"))
        assertArrayEquals(bytes(v, "physical_digest"), actual)
        assertArrayEquals(s.physicalSelectionDigest, actual)
        val changed = bytes(v, "activation_evidence").apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
        assertFalse(actual.contentEquals(ConversationInterval03.originalPhysicalDigest(s.account, s.device, s.line, s.binding,
            s.electionCommitment, s.deviceSessionDigest, UUID.fromString(v.getString("old_binding_id")), changed)))
    }
    @Test fun selectedContentRolesRemainIndependentFromEnrollmentAndOriginalSealedApproval(): Unit = ConversationInterval03TestFixture().use { v ->
        val s = v.statement(); val roles = v.f.authority.intervalKeys(s, Profile03ExecutionFixture.point(v.f.reader), v.f.now)
        assertArrayEquals(Profile03ExecutionFixture.point(v.f.eventSigning), roles.phonePoint())
        assertFalse(roles.phonePoint().contentEquals(Profile03ExecutionFixture.point(v.f.enrollment)))
        assertArrayEquals(Profile03ExecutionFixture.point(v.f.signer), roles.browserPoint())
        assertFalse(roles.browserPoint().contentEquals(Profile03ExecutionFixture.point(v.f.approval)))
        val wrongReader = Profile03ExecutionFixture.point(v.f.archive)
        assertThrows(Exception::class.java) { v.f.authority.intervalKeys(s, wrongReader, v.f.now) }
    }
    @Test fun closedStatementRejectsWidthHeaderZeroScopeNoncanonicalPeerDisclosureAndTrailingBytes(): Unit = ConversationInterval03TestFixture().use { v ->
        val original = v.statement().bytes()
        val variants = mutableListOf(original.copyOf(694), original + byteArrayOf(0))
        for (at in listOf(0, 4, 5, 6, 7, 632, 633, 658, 690)) variants.add(original.copyOf().apply { this[at] = (this[at].toInt() xor 1).toByte() })
        for (at in 8 until 152 step 16) variants.add(original.copyOf().apply { fill(0, at, at + 16) })
        for (at in 152 until 216 step 8) variants.add(original.copyOf().apply { ByteBuffer.wrap(this).putLong(at, 0) })
        for (at in 216 until 632 step 32) variants.add(original.copyOf().apply { fill(0, at, at + 32) })
        variants.add(original.copyOf().apply { ByteBuffer.wrap(this).putLong(192, 400_001) })
        variants.add(original.copyOf().apply { ByteBuffer.wrap(this).putLong(208, 86_500_001) })
        variants.forEach { assertTrue(runCatching { ConversationInterval03.Statement.decode(it) }.isFailure) }
        val owned = original.copyOf(); val parsed = ConversationInterval03.Statement.decode(owned); owned.fill(0); parsed.bytes().fill(0)
        assertArrayEquals(original, parsed.bytes())
    }
    @Test fun setupDeadlineDoesNotReplaceTheInstalledIntervalDeadlineAndBoundariesAreExclusive(): Unit = ConversationInterval03TestFixture().use { v ->
        val s = v.statement()
        s.requireSetupCurrent(s.setupExpiresMs - 1)
        assertThrows(Exception::class.java) { s.requireSetupCurrent(s.setupExpiresMs) }
        s.requireIntervalCurrent(s.setupExpiresMs)
        s.requireIntervalCurrent(s.intervalExpiresMs - 1)
        assertThrows(Exception::class.java) { s.requireIntervalCurrent(s.intervalExpiresMs) }
    }
    @Test fun signatureDomainsAndReceivedHighSOrZeroScalarsRefuseWithoutNormalization(): Unit = ConversationInterval03TestFixture().use { v ->
        val proof = v.proof(); val owner = proof.ownerSignature()
        assertFalse(ConversationContentCrypto.verifyRaw(owner, Profile03ExecutionFixture.point(v.f.signer),
            ConversationInterval03.approvalTranscript(proof.statement, owner)))
        assertThrows(Exception::class.java) { ConversationInterval03.approvalTranscript(proof.statement, ByteArray(64)) }
        val high = owner.copyOf().apply { fill(0xff.toByte(), 32, 64) }
        assertThrows(Exception::class.java) { ConversationInterval03.approvalTranscript(proof.statement, high) }
    }
}
