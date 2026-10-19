// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Genuine signed manifests. Enrollment authentication does not acquire an event-signing role. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03EnrollmentRoleSeparationTest {
    private fun old(f: Profile03ExecutionFixture) = Draft02ManifestAuthority.verify(f.pin, f.old,
        Draft02ManifestAuthority.Trust(f.account, f.fingerprint, 1,
            Draft02ManifestAuthority.Position.current(1, Profile03ExecutionFixture.unsigned(f.old))), f.now)

    @Test fun selectedPayloadReaderAndOutboundContextAcceptIndependentOrAbsentInboundEventSigner() {
        for (eventPresent in listOf(true, false)) Profile03ExecutionFixture(distinctEventSigner = true, includeEventSigner = eventPresent).use { f ->
            val readerId = Profile03ExecutionFixture.keyId(f.reader, false)
            val point = Profile03ExecutionFixture.point(f.reader)
            old(f).requireElectionReader(f.device, f.lineId, readerId, point, f.now)
            f.authority.requireSelectedReader(f.device, f.lineId, readerId, point, f.now, f.now + 100)
            val comparison = f.election.requireCurrent(f.authority, f.currentSelection, f.now)
            val request = f.intent.verifyReceipt(f.intentSignature, f.authority, comparison, f.admittedAt, f.now,
                3, Profile03ExecutionFixture.unhex(f.session.originHash), 1, 200_000)
            assertArrayEquals(Profile03ExecutionFixture.point(f.signer), f.authority.context(request, f.now).signerPoint)
        }
    }
    @Test fun readinessStillRefusesExpiredWrongDeviceWrongLineAndWrongHardwareReader() {
        Profile03ExecutionFixture(distinctEventSigner = true).use { f ->
            val readerId = Profile03ExecutionFixture.keyId(f.reader, false)
            val point = Profile03ExecutionFixture.point(f.reader)
            assertTrue(runCatching { f.authority.requireSelectedReader(Profile03ExecutionFixture.uuid(UUID(0, 99)), f.lineId, readerId, point, f.now, f.now + 100) }.isFailure)
            assertTrue(runCatching { f.authority.requireSelectedReader(f.device, Profile03ExecutionFixture.uuid(UUID(0, 99)), readerId, point, f.now, f.now + 100) }.isFailure)
            assertTrue(runCatching { f.authority.requireSelectedReader(f.device, f.lineId, readerId, Profile03ExecutionFixture.point(f.archive), f.now, f.now + 100) }.isFailure)
            assertTrue(runCatching { old(f).requireElectionReader(f.device, f.lineId, Profile03ExecutionFixture.keyId(f.archive, false), point, f.now) }.isFailure)
        }
        Profile03ExecutionFixture(selectedReaderUntilMs = 100_015, distinctEventSigner = true).use { f ->
            assertTrue(runCatching { f.authority.requireSelectedReader(f.device, f.lineId, Profile03ExecutionFixture.keyId(f.reader, false),
                Profile03ExecutionFixture.point(f.reader), f.now, f.now + 100) }.isFailure)
        }
    }
    @Test fun inboundMessageContextStillRequiresItsOwnExactRole04AndCannotUseTheEnrolledOrOutboundKey() {
        for (eventPresent in listOf(true, false)) Profile03ExecutionFixture(distinctEventSigner = true, includeEventSigner = eventPresent).use { f ->
            val authority = old(f)
            fun request(signer: ByteArray) = Draft02ManifestAuthority.Request(Draft02ManifestAuthority.Direction.INBOUND,
                f.account, ReviewedIntent03.uuid(f.message), f.device, f.lineId, f.peer, signer,
                listOf(Draft02ManifestAuthority.Reader(2, Profile03ExecutionFixture.keyId(f.archive, false))))
            if (eventPresent) assertArrayEquals(Profile03ExecutionFixture.point(f.eventSigning), authority.context(
                request(Profile03ExecutionFixture.keyId(f.eventSigning, true)), f.now).signerPoint)
            else assertTrue(runCatching { authority.context(request(Profile03ExecutionFixture.keyId(f.eventSigning, true)), f.now) }.isFailure)
            for (key in listOf(f.enrollment, f.signer, f.root)) assertTrue(runCatching {
                authority.context(request(Profile03ExecutionFixture.keyId(key, true)), f.now)
            }.isFailure)
        }
    }
}
