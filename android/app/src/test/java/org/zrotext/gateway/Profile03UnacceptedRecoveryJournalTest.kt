// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Context
import androidx.room.Room
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Profile03UnacceptedRecoveryJournalTest {
    @Test fun authenticatedCompleteClosureChainReservesFreshHigherGenerationWithoutErasingReleasedProof() = Profile03RecoveryFixture().use { r ->
        val signed = r.retainSignedFirst()
        assertTrue(r.reserve())
        assertEquals(signed, r.dao.find(r.first.challengeId))
        assertEquals(r.third, r.dao.find(r.third.challengeId))
        assertNull(r.dao.find(r.second.challengeId)) // Never received locally: no invented election row.
        for (row in r.closures) assertEquals(row, r.dao.closedUnaccepted(row.challengeId))
        assertNull(r.dao.signedOpening(r.first.accountId, r.first.lineId))
        val newest = r.signed(r.third)
        assertTrue(r.dao.recordSigned(newest) {})
        assertEquals(newest, r.dao.signedOpening(r.first.accountId, r.first.lineId))
        r.dao.requireClosureHistory(r.third, r.closures, r.now) {}
        assertNull(r.dao.installed(r.first.accountId, r.first.lineId))
        assertEquals(r.f.binding, r.f.line.db.attempts().currentLineBinding())
    }
    @Test fun retiredSignedAncestorCanRecoverOnlyWithExactDurableClosureAndStillCannotRestore02() = Profile03RecoveryFixture().use { r ->
        val retired = r.retainSignedFirst(retire = true)
        assertTrue(r.reserve())
        assertEquals(retired, r.dao.find(r.first.challengeId))
        val old = SealedPreparationRecord(r.first.accountId, r.f.message.toString(), r.f.attempt.toString(), "a".repeat(64), "b".repeat(64))
        assertThrows(IllegalStateException::class.java) { r.f.line.db.sealedPreparations().reserve(old) {} }
        assertThrows(IllegalStateException::class.java) { r.f.line.db.attempts().reserve(UUID(0, 90).toString(), 7, 1, r.now) }
        assertFalse(r.dao.reserve(r.second) {})
        assertFalse(r.dao.install(r.f.installed) {})
        assertNull(r.f.line.db.attempts().getAttempt(UUID(0, 90).toString()))
        assertEquals(0, r.f.line.db.sealedPreparations().count())
    }
    @Test fun expiryOrNotAcceptedAbsenceCannotResolveAnyRetainedSignedOpening() = Profile03RecoveryFixture().use { r ->
        val signed = r.retainSignedFirst()
        for (rows in listOf(emptyList(), listOf(r.closures.last()))) {
            assertThrows(IllegalStateException::class.java) { r.dao.reserveWithClosures(r.third, rows, r.now) {} }
            assertEquals(signed, r.dao.find(r.first.challengeId))
            assertNull(r.dao.find(r.third.challengeId))
            assertNull(r.dao.closedUnaccepted(r.first.challengeId))
        }
        assertFalse(r.dao.reserve(r.third) {})
    }
    @Test fun everyLocallyRetainedAncestorMustHaveExactCoreAndReservedBindingCovered() = Profile03RecoveryFixture().use { r ->
        r.retainSignedFirst()
        val original = r.closures.first()
        val changedCore = Profile03ElectionEncoding.decode(original.coreB64url, 500).also { it[352] = (it[352].toInt() xor 1).toByte() }
        for (bad in listOf(original.copy(newBindingId = UUID(0, 98).toString()),
            original.copy(coreB64url = Profile03ElectionEncoding.encode(changedCore)))) {
            assertThrows(IllegalStateException::class.java) { r.dao.reserveWithClosures(r.third, listOf(bad, r.closures.last()), r.now) {} }
            assertNull(r.dao.find(r.third.challengeId))
            assertNull(r.dao.closedUnaccepted(r.first.challengeId))
        }
    }
    @Test fun aLocallyAcceptedElectionContradictsOriginal02EvenAfterRetirement() = Profile03RecoveryFixture().use { r ->
        r.f.install()
        assertEquals(1, r.dao.retire(r.first.challengeId))
        assertThrows(IllegalStateException::class.java) { r.reserve() }
        assertEquals(r.f.installed.copy(state = "retired"), r.dao.find(r.first.challengeId))
        assertNull(r.dao.find(r.third.challengeId))
        assertNull(r.dao.closedUnaccepted(r.first.challengeId))
    }
    @Test fun unresolvedRadioEffectAndOldPreparationRemainIndependentRefusals() {
        Profile03RecoveryFixture().use { r ->
            r.retainSignedFirst()
            val unknown = SmsAttempt(UUID(0, 92).toString(), r.f.line.selected, 1, AttemptState.UNKNOWN, 1, 1)
            r.f.line.db.attempts().insertAttempt(unknown)
            assertThrows(IllegalStateException::class.java) { r.reserve() }
            assertEquals(unknown, r.f.line.db.attempts().getAttempt(unknown.attemptId))
            assertNull(r.dao.find(r.third.challengeId))
        }
        Profile03RecoveryFixture().use { r ->
            val old = SealedPreparationRecord(r.first.accountId, r.f.message.toString(), r.f.attempt.toString(), "a".repeat(64), "b".repeat(64))
            r.f.line.db.sealedPreparations().reserve(old) {}
            assertThrows(IllegalStateException::class.java) { r.reserve() }
            assertEquals(old, r.f.line.db.sealedPreparations().find(old.accountId, old.messageId))
            assertNull(r.dao.find(r.third.challengeId))
        }
    }
    @Test fun writerGuardWithdrawalRollsBackBothClosureChainAndFreshReservation() = Profile03RecoveryFixture().use { r ->
        val signed = r.retainSignedFirst()
        var guards = 0
        assertThrows(IllegalStateException::class.java) {
            r.dao.reserveWithClosures(r.third, r.closures, r.now) { check(++guards < 3) }
        }
        assertEquals(3, guards)
        assertEquals(signed, r.dao.find(r.first.challengeId))
        assertNull(r.dao.find(r.third.challengeId))
        for (row in r.closures) assertNull(r.dao.closedUnaccepted(row.challengeId))
    }
    @Test fun aLaterRecoveryRetainsEvenUnsignedAndPreviouslyUnseenServerAncestors() = Profile03RecoveryFixture().use { r ->
        // First two reservations were never seen locally; the complete authenticated chain
        // still becomes immutable history when the third opening is reserved.
        assertTrue(r.reserve())
        assertEquals(1, r.dao.retire(r.third.challengeId))
        val fourth = r.successor(24, 25, 6, 105_000, 106_000)
        val last = Profile03RecoveryFixture.close(r.third, fourth, 32)
        assertThrows(IllegalStateException::class.java) {
            r.dao.reserveWithClosures(fourth, listOf(r.closures.last(), last), 105_010) {}
        }
        assertNull(r.dao.find(fourth.challengeId))
        assertTrue(r.dao.reserveWithClosures(fourth, r.closures + last, 105_010) {})
        assertEquals(r.closures.first(), r.dao.closedUnaccepted(r.first.challengeId))
        assertEquals(last, r.dao.closedUnaccepted(r.third.challengeId))
        assertNull(r.dao.find(r.first.challengeId))
        assertNull(r.dao.find(r.second.challengeId))
    }
    @Test fun lateOriginalSignatureOrAcceptanceAndMissingResumeHistoryCannotRenewClosedRows() = Profile03RecoveryFixture().use { r ->
        // Original reservation never released a local proof; server expiry still closes it.
        assertTrue(r.dao.reserve(r.first) {})
        assertTrue(r.reserve())
        assertFalse(r.dao.recordSigned(r.signed(r.first)) {})
        assertFalse(r.dao.install(r.f.installed) {})
        val signed = r.signed(r.third)
        assertTrue(r.dao.recordSigned(signed) {})
        assertThrows(IllegalStateException::class.java) { r.dao.requireClosureHistory(r.third, emptyList(), r.now) {} }
        r.dao.requireClosureHistory(r.third, r.closures, r.now) {}
        assertEquals(signed, r.dao.find(r.third.challengeId))
        // Exact replay cannot mutate an immutable closure receipt, even through an unseen row.
        val replaced = r.closures.map { if (it.challengeId == r.second.challengeId) it.copy(openingId = UUID(0, 99).toString()) else it }
        assertThrows(IllegalStateException::class.java) { r.dao.requireClosureHistory(r.third, replaced, r.now) {} }
        assertEquals(r.closures.last(), r.dao.closedUnaccepted(r.second.challengeId))
    }
    @Test fun schemaSixteenUpgradeRetainsSignedProofAndUnknownRadio() {
        val context = RuntimeEnvironment.getApplication()
        val name = "unaccepted-${UUID.randomUUID()}.db"
        check(context.getDatabasePath(name).parentFile?.mkdirs() == true || context.getDatabasePath(name).parentFile?.isDirectory == true)
        Profile03RecoveryFixture().use { r ->
            val signed = r.signed(r.first)
            val unknown = SmsAttempt(UUID(0, 93).toString(), r.f.line.selected, 1, AttemptState.UNKNOWN, 1, 1)
            try {
                Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build().let { db ->
                    try {
                        assertTrue(db.profile03Elections().reserve(r.first) {})
                        assertTrue(db.profile03Elections().recordSigned(signed) {})
                        db.attempts().insertAttempt(unknown)
                    } finally { db.close() }
                }
                context.openOrCreateDatabase(name, Context.MODE_PRIVATE, null).use { old ->
                    old.execSQL("DROP TABLE selection_refresh03_closures")
                    old.execSQL("DROP TABLE profile03_unaccepted_closures")
                    old.version = 16
                }
                Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
                    .addMigrations(SmsJournalDatabase.MIGRATION_16_17, SmsJournalDatabase.MIGRATION_17_18, SmsJournalDatabase.MIGRATION_18_19, SmsJournalDatabase.MIGRATION_19_20, SmsJournalDatabase.MIGRATION_20_21, SmsJournalDatabase.MIGRATION_21_22, SmsJournalDatabase.MIGRATION_22_23).build().let { migrated ->
                        try {
                            assertEquals(23, migrated.openHelper.readableDatabase.version)
                            assertEquals(signed, migrated.profile03Elections().find(signed.challengeId))
                            assertEquals(unknown, migrated.attempts().getAttempt(unknown.attemptId))
                            assertNull(migrated.profile03Elections().closedUnaccepted(signed.challengeId))
                            assertNull(migrated.profile03Elections().installed(signed.accountId, signed.lineId))
                        } finally { migrated.close() }
                    }
            } finally { context.deleteDatabase(name) }
        }
    }
}
