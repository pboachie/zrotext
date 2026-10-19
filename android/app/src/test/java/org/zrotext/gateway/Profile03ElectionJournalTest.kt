// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Room
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03ElectionJournalTest {
    @Test fun reservationBurnsChallengeAndNeverReconstructsInstalledPermission() = Profile03ExecutionFixture().use { f ->
        val dao = f.line.db.profile03Elections()
        assertTrue(dao.reserve(f.record) { assertEquals(f.binding, it) })
        assertFalse(dao.reserve(f.record) {})
        assertNull(dao.installed(f.record.accountId, f.record.lineId))
        assertEquals("reserved", dao.find(f.record.challengeId)?.state)
        assertFalse(dao.install(f.installed) {})
        assertEquals("Profile03ElectionRecord(redacted)", dao.find(f.record.challengeId).toString())
    }
    @Test fun originalProofAndAcceptanceCommitExactlyAndRetirementCannotRenewThem() = Profile03ExecutionFixture().use { f ->
        f.install()
        val dao = f.line.db.profile03Elections()
        assertEquals(f.installed, dao.installed(f.record.accountId, f.record.lineId))
        assertTrue(dao.install(f.installed) {})
        assertFalse(dao.install(f.installed.copy(acceptedEvidenceSha256 = "a".repeat(64))) {})
        assertFalse(dao.recordSigned(f.installed.copy(state = "signed", acceptedEvidenceSha256 = null)) {})
        assertEquals(1, dao.retire(f.record.challengeId))
        assertNull(dao.installed(f.record.accountId, f.record.lineId))
        assertFalse(dao.install(f.installed) {})
        assertFalse(dao.reserve(f.record) {})
        assertEquals("retired", dao.find(f.record.challengeId)?.state)
    }
    @Test fun postWriteAuthorityLossRollsBackReservationProofAndInstallation() = Profile03ExecutionFixture().use { f ->
        val dao = f.line.db.profile03Elections()
        var calls = 0
        assertThrows(IllegalStateException::class.java) { dao.reserve(f.record) { check(++calls == 1) } }
        assertNull(dao.find(f.record.challengeId))
        assertTrue(dao.reserve(f.record) {})
        val signed = f.installed.copy(state = "signed", acceptedEvidenceSha256 = null)
        calls = 0
        assertThrows(IllegalStateException::class.java) { dao.recordSigned(signed) { check(++calls == 1) } }
        assertEquals("reserved", dao.find(f.record.challengeId)?.state)
        assertTrue(dao.recordSigned(signed) {})
        calls = 0
        assertThrows(IllegalStateException::class.java) { dao.install(f.installed) { check(++calls == 1) } }
        assertEquals(signed, dao.find(f.record.challengeId))
    }
    @Test fun activeReservationPreventsParallelElectionAndMappingCannotChange() = Profile03ExecutionFixture().use { f ->
        val dao = f.line.db.profile03Elections()
        assertTrue(dao.reserve(f.record) {})
        // Another opening may not substitute a binding UUID or signatures for the burned challenge.
        assertFalse(dao.recordSigned(f.installed.copy(state = "signed", acceptedEvidenceSha256 = null,
            newBindingId = UUID(0, 99).toString())) {})
        val otherCore = Profile03ElectionEncoding.decode(f.record.coreB64url, 500)
        ReviewedIntent03.uuid(UUID(0, 20)).copyInto(otherCore, 56)
        val other = f.record.copy(challengeId = UUID(0, 20).toString(), newBindingId = UUID(0, 21).toString(),
            coreB64url = Profile03ElectionEncoding.encode(otherCore))
        assertFalse(dao.reserve(other) {})
        assertNull(dao.find(other.challengeId))
    }
    @Test fun decodedRowCannotOverrideTheExactReservedCore() = Profile03ExecutionFixture().use { f ->
        for (changed in listOf(f.record.copy(oldGeneration = 2), f.record.copy(newGeneration = 9),
            f.record.copy(rootFingerprint = "a".repeat(64)), f.record.copy(readerKeyId = "b".repeat(64)),
            f.record.copy(originHash = "c".repeat(64)), f.record.copy(challengeId = UUID(0, 99).toString()))) {
            assertThrows(IllegalArgumentException::class.java) { f.line.db.profile03Elections().reserve(changed) {} }
            assertNull(f.line.db.profile03Elections().find(changed.challengeId))
        }
    }
    @Test fun unresolvedEffectsAndPriorSealedPreparationsRefuseElectionWithoutDeletingHistory() = Profile03ExecutionFixture().use { f ->
        val dao = f.line.db.profile03Elections()
        f.line.db.attempts().reserveAlpha(f.attempt.toString(), f.message.toString(), f.line.selected, 1,
            UUID(0, 44).toString(), f.now, identity = testEvidenceIdentity)
        assertFalse(dao.reserve(f.record) {})
        assertEquals(AttemptState.RESERVED, f.line.db.attempts().getAttempt(f.attempt.toString())?.state)
        f.line.db.attempts().setState(f.attempt.toString(), AttemptState.DELIVERED, f.now)
        val old = SealedPreparationRecord(f.record.accountId, f.message.toString(), f.attempt.toString(), "a".repeat(64), "b".repeat(64))
        f.line.db.sealedPreparations().reserve(old) {}
        assertFalse(dao.reserve(f.record) {})
        assertEquals(old, f.line.db.sealedPreparations().find(old.accountId, old.messageId))
    }
    @Test fun electionReservationFencesOldPreparationAndLegacyRadioWritersUntilAbandoned() = Profile03ExecutionFixture().use { f ->
        val dao = f.line.db.profile03Elections()
        assertTrue(dao.reserve(f.record) {})
        val old = SealedPreparationRecord(f.record.accountId, f.message.toString(), f.attempt.toString(), "a".repeat(64), "b".repeat(64))
        assertThrows(IllegalStateException::class.java) { f.line.db.sealedPreparations().reserve(old) {} }
        assertThrows(IllegalStateException::class.java) {
            f.line.db.attempts().reserveAlpha(f.attempt.toString(), f.message.toString(), f.line.selected, 1,
                UUID(0, 44).toString(), f.now, identity = testEvidenceIdentity)
        }
        assertThrows(IllegalStateException::class.java) { f.line.db.attempts().reserve(UUID(0, 45).toString(), 7, 1, f.now) }
        assertNull(f.line.db.attempts().getAttempt(f.attempt.toString()))
        assertEquals(0, f.line.db.sealedPreparations().count())
        assertEquals(1, dao.retire(f.record.challengeId))
        // An abandoned unaccepted ceremony grants no03 permission and does not alter02 selection.
        f.line.db.sealedPreparations().reserve(old) {}
        assertEquals(old, f.line.db.sealedPreparations().find(old.accountId, old.messageId))
    }
    @Test fun unboundLegacyUnknownEffectCannotDisappearIntoAnotherAccountSelection() = Profile03ExecutionFixture().use { f ->
        val old = SmsAttempt(UUID(0, 46).toString(), f.line.selected, 1, AttemptState.UNKNOWN, 1, 1)
        f.line.db.attempts().insertAttempt(old)
        assertFalse(f.line.db.profile03Elections().reserve(f.record) {})
        assertEquals(old, f.line.db.attempts().getAttempt(old.attemptId))
        assertNull(f.line.db.profile03Elections().find(f.record.challengeId))
    }
    @Test fun retiredSignedProofStillFencesOldWritersAndNewCeremoniesWhileAcceptanceIsUnknown() = Profile03ExecutionFixture().use { f ->
        val dao = f.line.db.profile03Elections()
        assertTrue(dao.reserve(f.record) {})
        val signed = f.installed.copy(state = "signed", acceptedEvidenceSha256 = null)
        assertTrue(dao.recordSigned(signed) {})
        assertEquals(1, dao.retire(f.record.challengeId))
        assertEquals(signed.copy(state = "retired"), dao.find(f.record.challengeId))
        val old = SealedPreparationRecord(f.record.accountId, f.message.toString(), f.attempt.toString(), "a".repeat(64), "b".repeat(64))
        assertThrows(IllegalStateException::class.java) { f.line.db.sealedPreparations().reserve(old) {} }
        assertThrows(IllegalStateException::class.java) {
            f.line.db.attempts().reserveAlpha(f.attempt.toString(), f.message.toString(), f.line.selected, 1,
                UUID(0, 44).toString(), f.now, identity = testEvidenceIdentity)
        }
        assertThrows(IllegalStateException::class.java) { f.line.db.attempts().reserve(UUID(0, 45).toString(), 7, 1, f.now) }
        val core = Profile03ElectionEncoding.decode(f.record.coreB64url, 500)
        ReviewedIntent03.uuid(UUID(0, 47)).copyInto(core, 56)
        val next = f.record.copy(challengeId = UUID(0, 47).toString(), newBindingId = UUID(0, 48).toString(),
            coreB64url = Profile03ElectionEncoding.encode(core))
        assertFalse(dao.reserve(next) {})
        // The valid released signature may have been accepted remotely after local retirement.
        // A delayed reply cannot renew it locally, and its unknown outcome cannot restore02.
        assertFalse(dao.install(f.installed) {})
        assertNull(dao.find(next.challengeId))
        assertNull(dao.installed(f.record.accountId, f.record.lineId))
        assertEquals(signed.copy(state = "retired"), dao.find(f.record.challengeId))
        assertEquals(0, f.line.db.sealedPreparations().count())
        assertNull(f.line.db.attempts().getAttempt(f.attempt.toString()))
    }
    @Test fun upgradeFromFourteenPreservesExistingPairingLineAndUnknownAttempt() {
        val context = RuntimeEnvironment.getApplication()
        val name = "profile03-${UUID.randomUUID()}.db"
        val attempt = UUID(0, 31).toString()
        val line = LocalLineBinding(accountId = UUID(0, 1).toString(), deviceId = UUID(0, 2).toString(),
            lineId = UUID(0, 3).toString(), generation = 4, subscriptionId = 7, installedAtMs = 1, cardId = 20)
        try {
            Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build().let { db ->
                try {
                    assertTrue(db.attempts().installVerifiedLineBinding(line, listOf(ActiveSimCard(7, 20))))
                    db.attempts().insertAttempt(SmsAttempt(attempt, 7, 1, AttemptState.UNKNOWN, 1, 1))
                } finally { db.close() }
            }
            context.openOrCreateDatabase(name, Context.MODE_PRIVATE, null).use {
                it.execSQL("DROP TABLE profile03_elections")
                it.version = 14
            }
            Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
                .addMigrations(SmsJournalDatabase.MIGRATION_14_15).build().let { db ->
                    try {
                        assertEquals(15, db.openHelper.readableDatabase.version)
                        assertEquals(line, db.attempts().currentLineBinding())
                        assertEquals(AttemptState.UNKNOWN, db.attempts().getAttempt(attempt)?.state)
                        assertNull(db.profile03Elections().installed(line.accountId, line.lineId))
                    } finally { db.close() }
                }
        } finally { context.deleteDatabase(name) }
    }
}
