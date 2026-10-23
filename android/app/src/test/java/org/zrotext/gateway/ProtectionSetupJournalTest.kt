// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Actual Room only. Candidate packets below are deliberately NOT authenticated server proofs;
 * no test invokes a key generator, signer, pin writer, socket or radio. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ProtectionSetupJournalTest {
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T =
        try { block(this) } finally { close() }
    private class Fixture : AutoCloseable {
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        val dao = db.protectionSetup()
        fun begin() = dao.reserveCommand(command()) {}
        fun opened(): ProtectionSetupCommand {
            val sent = dao.openingWillBeSubmitted(begin()) {}
            val packet = packet("synthetic-unverified-opening")
            return dao.retainOpeningCandidate(sent, id(9), packet.first, packet.second) {}
        }
        override fun close() = db.close()
    }

    @Test fun commandReservationDoesNotCreateKeysPinsCountersOrFirstEverAuthority() = Fixture().use { f ->
        val before = ProtectionSetupRecovery.state(f.dao.command(), f.dao.providers())
        assertEquals(ProtectionSetupRecovery.State.NO_LOCAL_COMMAND, before)
        f.begin()
        assertNull(f.db.captures03().protection())
        assertFalse(f.db.captures03().hasCapture03History())
        assertTrue(f.dao.providers().isEmpty())
        assertEquals(ProtectionSetupRecovery.State.RECONCILE_OPENING, ProtectionSetupRecovery.state(f.dao.command(), f.dao.providers()))
    }

    @Test fun exactOriginalCommandRetryRetainsSubmittedAndReceivedHistory() = Fixture().use { f ->
        val old = f.opened()
        assertEquals(old, f.dao.reserveCommand(command()) {})
        assertEquals(old, f.dao.openingWillBeSubmitted(old) {})
        assertEquals(old, f.dao.command())
    }

    @Test fun accountDeviceOriginKeySetupAndTimeCannotSelectAnotherInstallationCommand() = Fixture().use { f ->
        val original = f.begin()
        listOf(original.copy(commandId = id(12)), original.copy(accountId = id(13)),
            original.copy(deviceId = id(14)), original.copy(originSha256 = "c".repeat(64)),
            original.copy(enrolledSigningKeyId = "d".repeat(64)), original.copy(setupId = id(15)), original.copy(openingId = id(16)),
            original.copy(requestedMs = 1001)).forEach { changed ->
            assertThrows(IllegalStateException::class.java) { f.dao.reserveCommand(changed) {} }
            assertEquals(original, f.dao.command())
        }
    }

    @Test fun responseBeforeDurableSubmissionCannotAdvanceOpening() = Fixture().use { f ->
        val original = f.begin(); val p = packet("unverified")
        assertThrows(IllegalArgumentException::class.java) { f.dao.retainOpeningCandidate(original, id(9), p.first, p.second) {} }
        assertEquals(original, f.dao.command())
    }

    @Test fun lostOpeningReplyClassifiesReconciliationWithoutAllocatingOrCallingProvider() = Fixture().use { f ->
        val sent = f.dao.openingWillBeSubmitted(f.begin()) {}
        repeat(3) { assertEquals(sent, f.dao.openingWillBeSubmitted(sent) {}) }
        assertEquals(ProtectionSetupRecovery.State.RECONCILE_OPENING, ProtectionSetupRecovery.state(sent, f.dao.providers()))
        assertTrue(f.dao.providers().isEmpty())
    }

    @Test fun retainedOpeningCannotChangeAndRequiresIndependentVerificationOnRecovery() = Fixture().use { f ->
        val original = f.opened(); val different = packet("different")
        assertThrows(IllegalStateException::class.java) { f.dao.retainOpeningCandidate(original, id(9), different.first, different.second) {} }
        assertEquals(original, f.dao.command())
        assertEquals(ProtectionSetupRecovery.State.VERIFY_OPENING, ProtectionSetupRecovery.state(original, emptyList()))
    }

    @Test fun providerCannotBeReservedBeforeOpeningOrAheadOfPriorFamilies() = Fixture().use { f ->
        val local = f.begin()
        assertThrows(IllegalStateException::class.java) { f.dao.reserveProviderEntry(local, provider(0)) {} }
        val opened = f.opened()
        assertThrows(IllegalStateException::class.java) { f.dao.reserveProviderEntry(opened, provider(1)) {} }
        assertTrue(f.dao.providers().isEmpty())
    }

    @Test fun lostProviderResultIsPermanentUnknownAndExactRetryNeverReportsNewEntry() = Fixture().use { f ->
        val opened = f.opened(); val row = provider(0)
        assertTrue(f.dao.reserveProviderEntry(opened, row) {})
        repeat(3) { assertFalse(f.dao.reserveProviderEntry(opened, row) {}) }
        assertEquals(ProtectionSetupRecovery.State.RECONCILE_PROVIDER_RESULT, ProtectionSetupRecovery.state(opened, f.dao.providers()))
        assertThrows(IllegalStateException::class.java) { f.dao.reserveProviderEntry(opened, provider(1)) {} }
        assertThrows(IllegalStateException::class.java) { f.dao.reserveProviderEntry(opened, row.copy(operationId = id(99))) {} }
        assertEquals(listOf(row), f.dao.providers())
    }

    @Test fun sameBurnedOperationMayRetainRecoveredOriginalPublicEvidenceWithoutAnotherEntry() = Fixture().use { f ->
        val opened = f.opened(); val row = provider(0); val p = packet("public-result")
        assertTrue(f.dao.reserveProviderEntry(opened, row) {})
        val result = f.dao.retainProviderEvidence(row, p.first, p.second) {}
        assertEquals(result, f.dao.retainProviderEvidence(result, p.first, p.second) {})
        assertFalse(f.dao.reserveProviderEntry(opened, row) {})
        assertEquals(ProtectionSetupRecovery.State.CONTINUE_EXPLICIT_SETUP, ProtectionSetupRecovery.state(opened, f.dao.providers()))
    }

    @Test fun resultHashChangedEvidenceAndStaleCompareAndSetCannotRewriteOriginal() = Fixture().use { f ->
        val opened = f.opened(); val row = provider(0); val p = packet("original")
        f.dao.reserveProviderEntry(opened, row) {}
        assertThrows(IllegalArgumentException::class.java) { f.dao.retainProviderEvidence(row, p.first, "d".repeat(64)) {} }
        val original = f.dao.retainProviderEvidence(row, p.first, p.second) {}
        val changed = packet("changed")
        assertThrows(IllegalStateException::class.java) { f.dao.retainProviderEvidence(original, changed.first, changed.second) {} }
        assertThrows(IllegalStateException::class.java) { f.dao.retainProviderEvidence(row, p.first, p.second) {} }
        assertEquals(original, f.dao.provider(row.kind))
    }

    @Test fun everyProviderResultStillEndsAtAssociationRequiredAndNeverAtReady() = Fixture().use { f ->
        val opened = f.opened()
        ProtectionSetupProvider.KINDS.indices.forEach { index ->
            val row = provider(index); val p = packet("public-result-$index")
            assertTrue(f.dao.reserveProviderEntry(opened, row) {})
            f.dao.retainProviderEvidence(row, p.first, p.second) {}
        }
        assertEquals(ProtectionSetupRecovery.State.NEED_ASSOCIATION, ProtectionSetupRecovery.state(opened, f.dao.providers()))
        assertNull(f.db.captures03().protection())
        assertFalse(f.db.captures03().hasCapture03History())
    }

    @Test fun lifetimeWithdrawalDuringCommandWriterRollsBackTheWholeReservation() = Fixture().use { f ->
        val calls = AtomicInteger()
        assertThrows(IllegalStateException::class.java) { f.dao.reserveCommand(command()) { check(calls.incrementAndGet() < 2) } }
        assertNull(f.dao.command()); assertTrue(f.dao.providers().isEmpty())
    }

    @Test fun lifetimeWithdrawalDuringProviderResultRollsBackEvidenceButKeepsOriginalBurn() = Fixture().use { f ->
        val opened = f.opened(); val row = provider(0); val p = packet("public")
        f.dao.reserveProviderEntry(opened, row) {}
        val calls = AtomicInteger()
        assertThrows(IllegalStateException::class.java) { f.dao.retainProviderEvidence(row, p.first, p.second) { check(calls.incrementAndGet() < 2) } }
        assertEquals(row, f.dao.provider(row.kind))
        assertFalse(f.dao.reserveProviderEntry(opened, row) {})
    }

    @Test fun concurrentProviderReservationsProduceOnlyOneOriginalOperation() = Fixture().use { f ->
        val opened = f.opened(); val start = CountDownLatch(1); val done = CountDownLatch(2)
        val entered = AtomicInteger(); val conflicts = AtomicInteger()
        repeat(2) { index -> thread {
            try {
                check(start.await(5, TimeUnit.SECONDS))
                if (f.dao.reserveProviderEntry(opened, provider(0).copy(operationId = id(100 + index))) {}) entered.incrementAndGet()
            } catch (_: IllegalStateException) { conflicts.incrementAndGet() }
            finally { done.countDown() }
        } }
        start.countDown(); assertTrue(done.await(10, TimeUnit.SECONDS))
        assertEquals(1, entered.get()); assertEquals(1, conflicts.get())
        assertEquals(1, f.dao.providers().size)
    }

    @Test fun partialOrForeignHistoryCannotBeClassifiedAsFreshOrResumable() {
        assertThrows(IllegalStateException::class.java) { ProtectionSetupRecovery.state(null, listOf(provider(0))) }
        assertThrows(IllegalStateException::class.java) { ProtectionSetupRecovery.state(command(), listOf(provider(0))) }
        val opened = command().copy(openingSubmitted = true,
            openingCandidateB64url = packet("candidate").first, openingCandidateSha256 = packet("candidate").second)
        assertThrows(IllegalStateException::class.java) { ProtectionSetupRecovery.state(opened, listOf(provider(1))) }
        assertThrows(IllegalStateException::class.java) { ProtectionSetupRecovery.state(opened, listOf(provider(0).copy(commandId = id(89)))) }
    }

    @Test fun reopenedJournalRetainsUnknownAndDoesNotOfferANewProviderEntry() {
        val app = RuntimeEnvironment.getApplication()
        val name = "protection-setup-${UUID.randomUUID()}.db"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build()
        try {
            lateinit var original: ProtectionSetupCommand
            open().use { db ->
                val dao = db.protectionSetup(); val p = packet("candidate")
                val sent = dao.openingWillBeSubmitted(dao.reserveCommand(command()) {}) {}
                original = dao.retainOpeningCandidate(sent, id(9), p.first, p.second) {}
                assertTrue(dao.reserveProviderEntry(original, provider(0)) {})
            }
            open().use { db ->
                val dao = db.protectionSetup()
                assertEquals(original, dao.command())
                assertEquals(ProtectionSetupRecovery.State.RECONCILE_PROVIDER_RESULT, ProtectionSetupRecovery.state(dao.command(), dao.providers()))
                assertFalse(dao.reserveProviderEntry(original, provider(0)) {})
            }
        } finally { app.deleteDatabase(name) }
    }

    @Test fun additiveMigrationPreservesOldNegativeRoutesAndCreatesNoSetupOrigin() {
        val app = RuntimeEnvironment.getApplication()
        val name = "protection-migration-${UUID.randomUUID()}.db"
        app.deleteDatabase(name)
        try {
            Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build().use { db ->
                db.openHelper.writableDatabase.apply {
                    execSQL("INSERT INTO capture03_routes VALUES(?, 'blocked', NULL, NULL, 1000)", arrayOf("a".repeat(64)))
                    execSQL("INSERT INTO local_recipient_suppressions VALUES(?, 1000)", arrayOf("b".repeat(64)))
                    execSQL("DROP TABLE protection_setup_providers")
                    execSQL("DROP TABLE protection_setup_command")
                    execSQL("DROP TABLE room_master_table")
                    version = 19
                }
            }
            Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
                .addMigrations(SmsJournalDatabase.MIGRATION_19_20).build().use { db ->
                    assertEquals("blocked", db.captures03().route("a".repeat(64))!!.route)
                    assertTrue(db.attempts().isRecipientSuppressed("b".repeat(64)))
                    assertNull(db.protectionSetup().command())
                    assertTrue(db.protectionSetup().providers().isEmpty())
                    assertNull(db.captures03().protection())
                }
        } catch (failure: android.database.sqlite.SQLiteCantOpenDatabaseException) {
            val path = app.getDatabasePath(name).absolutePath
            throw AssertionError("Native database open failed: path=$path; pathLength=${path.length}; walLength=${path.length + 4}", failure)
        } finally { app.deleteDatabase(name) }
    }

    companion object {
        private fun id(value: Int) = UUID(0, value.toLong()).toString()
        private fun encode(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
        private fun packet(value: String): Pair<String, String> = value.toByteArray().let {
            encode(it) to Draft02OutboundPreparation.hex(MessageDigest.getInstance("SHA-256").digest(it))
        }
        private fun command() = ProtectionSetupCommand(setupId = id(4), openingId = id(9), commandId = id(1), accountId = id(2), deviceId = id(3),
            originSha256 = "a".repeat(64), enrolledSigningKeyId = "b".repeat(64), requestedMs = 1000)
        private fun provider(index: Int) = ProtectionSetupProvider(ProtectionSetupProvider.KINDS[index], id(1), id(20 + index), 1001L + index)
    }
}
