// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Real Room transitions, synthetic public proofs. This is not hosted owner/MFA acceptance. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SelectionRefresh03JournalTest {
    internal class Fixture : AutoCloseable {
        val f = Profile03ExecutionFixture().also { it.install() }
        val observation = checkNotNull(f.line.owner.capture()).observation().bytes()
        val session = Profile03SessionTime.Identity(f.session, "synthetic-site", "synthetic-instance")
            .deviceSessionDigest(Profile03ExecutionFixture.point(f.enrollment))
        val core = SelectionRefresh03.Core.decode(ByteBuffer.allocate(496)
            .put(byteArrayOf(90, 84, 83, 82, 1, 3, 3, 0)).put(f.account).put(f.device).put(f.lineId)
            .put(ReviewedIntent03.uuid(UUID(0, 77))).put(ReviewedIntent03.uuid(f.newBinding))
            .putLong(2).putLong(1).putLong(2).putLong(3).put(f.accepted.electionCommitment).put(f.accepted.electionBundleSha256)
            .put(Profile03ExecutionFixture.keyId(f.reader, false)).put(Profile03ExecutionFixture.keyId(f.enrollment, true))
            .put(Profile03ExecutionFixture.keyId(f.approval, true)).put(f.fingerprint).put(f.authority.digest)
            .put(session).put(ByteArray(32) { 8 }).put(Profile03ExecutionFixture.unhex(f.session.originHash))
            .put(ByteArray(32) { 9 }).putLong(f.now).putLong(f.now + 120_000).putLong(0).array())
        val device = Profile03ExecutionFixture.rawSign(f.enrollment, SelectionRefresh03.deviceTranscript(core, observation))
        val owner = Profile03ExecutionFixture.rawSign(f.approval, SelectionRefresh03.ownerTranscript(core, observation, device))
        val bundle = SelectionRefresh03.Bundle.verify(core.bytes() + observation + device + owner, core.bytes(), observation,
            Profile03ExecutionFixture.point(f.enrollment), Profile03ExecutionFixture.point(f.approval))
        val reserved = SelectionRefresh03Record(core.refresh.toString(), f.record.accountId, f.record.deviceId, f.record.lineId,
            f.record.newBindingId, 2, f.line.challengeId.toString(), 1, f.record.challengeId,
            checkNotNull(f.installed.acceptedEvidenceSha256), Profile03ExecutionFixture.hex(session), f.session.connectionEpoch,
            f.session.deploymentEpoch, f.session.originHash, f.line.selected, UUID(0, 78).toString(), f.now, f.now + 300_000,
            Profile03ElectionEncoding.encode(core.bytes()), Profile03ElectionEncoding.encode(observation))
        val signed = reserved.copy(state = "signed", deviceSignatureB64url = Profile03ElectionEncoding.encode(device))
        val accepted = signed.copy(state = "accepted", ownerSignatureB64url = Profile03ElectionEncoding.encode(owner),
            bundleSha256 = Profile03ExecutionFixture.hex(bundle.sha256()), acceptedMs = f.now + 1)
        val ackReserved = accepted.copy(state = "ack_reserved")
        val ackSigned = ackReserved.copy(state = "ack_signed", installedSignatureB64url = Profile03ElectionEncoding.encode(
            Profile03ExecutionFixture.rawSign(f.enrollment, SelectionRefresh03.installedTranscript(bundle, session))))
        val installed = ackSigned.copy(state = "installed", installedMs = f.now + 2)
        val dao get() = f.line.db.selectionRefreshes03()
        fun next(): SelectionRefresh03Record {
            val id = UUID(0, 79)
            val bytes = core.bytes().apply { ReviewedIntent03.uuid(id).copyInto(this, 56) }
            return reserved.copy(refreshId = id.toString(), coreB64url = Profile03ElectionEncoding.encode(bytes))
        }
        override fun close() = f.close()
    }
    @Test fun reservationBurnsChallengeAndEveryStageRequiresItsOriginalDurablePredecessor() = Fixture().use { v ->
        assertTrue(v.dao.reserve(v.reserved) {})
        assertFalse(v.dao.reserve(v.reserved) {})
        assertFalse(v.dao.advance(v.installed, "ack_signed") {})
        assertTrue(v.dao.advance(v.signed, "reserved") {})
        assertTrue(v.dao.advance(v.signed, "reserved") {})
        assertFalse(v.dao.advance(v.ackSigned, "ack_reserved") {})
        assertTrue(v.dao.advance(v.accepted, "signed") {})
        assertTrue(v.dao.advance(v.ackReserved, "accepted") {})
        assertTrue(v.dao.advance(v.ackSigned, "ack_reserved") {})
        assertTrue(v.dao.advance(v.installed, "ack_signed") {})
        assertTrue(v.dao.advance(v.installed, "ack_signed") {})
        assertFalse(v.dao.advance(v.installed.copy(installedMs = v.f.now + 3), "ack_signed") {})
        assertEquals(v.installed, v.dao.find(v.reserved.refreshId))
        assertEquals(v.f.installed, v.f.line.db.profile03Elections().find(v.f.record.challengeId))
        assertEquals(v.f.binding, v.f.line.db.attempts().currentLineBinding())
    }
    @Test fun retirementOfReleasedDeviceProofKeepsItsUnknownOutcomeFenceAndRejectsLateAcceptance() = Fixture().use { v ->
        assertTrue(v.dao.reserve(v.reserved) {})
        assertTrue(v.dao.advance(v.signed, "reserved") {})
        assertEquals(1, v.dao.retire(v.reserved.refreshId))
        assertEquals(v.signed.copy(state = "retired"), v.dao.find(v.reserved.refreshId))
        assertFalse(v.dao.reserve(v.next()) {})
        assertFalse(v.dao.advance(v.accepted, "signed") {})
        assertNull(v.dao.find(v.next().refreshId))
    }
    @Test fun unsignedAbandonmentDoesNotEraseHistoryAndCannotBeMistakenForAnInstalledRefresh() = Fixture().use { v ->
        assertTrue(v.dao.reserve(v.reserved) {})
        assertEquals(1, v.dao.retire(v.reserved.refreshId))
        assertTrue(v.dao.reserve(v.next()) {})
        assertEquals(v.reserved.copy(state = "retired"), v.dao.find(v.reserved.refreshId))
        assertFalse(v.dao.advance(v.signed, "reserved") {})
        assertNull(v.f.binding.installedSelectionV2()?.refresh03)
    }
    @Test fun guardWithdrawalAfterWriteRollsBackAndOriginalBindingCannotBeSubstituted() = Fixture().use { v ->
        var calls = 0
        assertThrows(IllegalStateException::class.java) {
            v.dao.reserve(v.reserved) { check(++calls <= 2) } // Pre/post original() invokes twice each.
        }
        assertNull(v.dao.find(v.reserved.refreshId))
        assertTrue(v.dao.reserve(v.reserved) {})
        calls = 0
        assertThrows(IllegalStateException::class.java) { v.dao.advance(v.signed, "reserved") { check(++calls <= 2) } }
        assertEquals(v.reserved, v.dao.find(v.reserved.refreshId))
        assertThrows(IllegalArgumentException::class.java) { v.dao.reserve(v.next().copy(bindingGeneration = 99)) {} }
        assertThrows(IllegalStateException::class.java) {
            v.dao.advance(v.signed.copy(electionIdentitySha256 = "a".repeat(64)), "reserved") {}
        }
    }
    @Test fun signaturesAndOriginalAcceptanceTimesCannotChangeAcrossLaterTransitions() = Fixture().use { v ->
        assertTrue(v.dao.reserve(v.reserved) {})
        assertTrue(v.dao.advance(v.signed, "reserved") {})
        val changed = Profile03ElectionEncoding.encode(ByteArray(64) { 3 })
        assertFalse(v.dao.advance(v.accepted.copy(deviceSignatureB64url = changed), "signed") {})
        assertTrue(v.dao.advance(v.accepted, "signed") {})
        assertFalse(v.dao.advance(v.ackReserved.copy(acceptedMs = v.f.now + 2), "accepted") {})
        assertFalse(v.dao.advance(v.ackReserved.copy(ownerSignatureB64url = changed), "accepted") {})
        assertEquals(v.accepted, v.dao.find(v.reserved.refreshId))
    }
    @Test fun unresolvedBoundOrUnboundRadioEffectsRefuseFreshObservationWithoutDeletingEitherHistory() {
        for (bound in listOf(false, true)) Fixture().use { v ->
            val attempt = SmsAttempt(UUID(0, 81).toString(), v.f.line.selected, 1, AttemptState.UNKNOWN, 1, 1,
                accountId = if (bound) v.f.record.accountId else null)
            v.f.line.db.attempts().insertAttempt(attempt)
            assertThrows(IllegalStateException::class.java) { v.dao.reserve(v.reserved) {} }
            assertEquals(attempt, v.f.line.db.attempts().getAttempt(attempt.attemptId))
            assertEquals(v.f.installed, v.f.line.db.profile03Elections().find(v.f.record.challengeId))
            assertNull(v.dao.find(v.reserved.refreshId))
        }
    }
    @Test fun storedReceiptCannotSubstituteAnotherSessionEpochOrGenuinelyWithdrawnIssuer() = Fixture().use { v ->
        assertTrue(v.dao.reserve(v.reserved) {})
        for ((next, expected) in listOf(v.signed to "reserved", v.accepted to "signed", v.ackReserved to "accepted",
            v.ackSigned to "ack_reserved", v.installed to "ack_signed")) assertTrue(v.dao.advance(next, expected) {})
        val lease = checkNotNull(v.f.line.owner.capture())
        val handle = InstalledSelectionRefresh03.issue(v.installed, v.bundle, lease) { true }
        val projection = mapOf<String, Any>("kind" to "owner_refresh03", "refresh_id" to v.installed.refreshId,
            "bundle" to Profile03ElectionEncoding.encode(v.bundle.bytes()), "accepted_ms" to v.installed.acceptedMs.toString(),
            "installed_ms" to v.installed.installedMs.toString())
        handle.requireProjection(projection, 3, v.session, v.f.line.db)
        assertThrows(IllegalStateException::class.java) { handle.requireContext(4, v.session, v.f.line.db) }
        assertThrows(IllegalStateException::class.java) { handle.requireContext(3, ByteArray(32) { 4 }, v.f.line.db) }
        assertThrows(IllegalArgumentException::class.java) { handle.requireProjection(projection + ("kind" to "original_v2"), 3, v.session, v.f.line.db) }
        v.f.line.callback()
        assertFalse(handle.isCurrent())
        assertThrows(IllegalStateException::class.java) { handle.requireProjection(projection, 3, v.session, v.f.line.db) }
        assertEquals(v.installed, v.dao.find(v.installed.refreshId)) // Persisted proof never restores withdrawn OS truth.
    }
}
