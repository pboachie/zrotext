// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.app.Activity
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
class Capture03IngressTest {
    @Test fun processWithdrawalHasNoResetAndDoesNotAliasAnotherLineOrAccount() {
        Capture03LegacyFence.requireLegacy(id(301), id(302), id(303))
        Capture03LegacyFence.withdraw(id(301), id(302), id(303))
        Capture03LegacyFence.withdraw(id(301), id(302), id(303))
        assertThrows(IllegalStateException::class.java) { Capture03LegacyFence.requireLegacy(id(301), id(302), id(303)) }
        Capture03LegacyFence.requireLegacy(id(301), id(302), id(304))
        Capture03LegacyFence.requireLegacy(id(305), id(302), id(303))
    }
    @Test fun genuineRetainedDeviceProofIsNegativeOnlyEvenWhenRetiredOrUnaccepted() {
        Profile03RetainedElectionTest.Fixture().use { v ->
            for (row in listOf(v.installed, v.installed.copy(state = "retired", acceptedEvidenceSha256 = null))) {
                val decision = Capture03Exclusion.decide(listOf(row), false, v.f.binding, v.f.line.selected,
                    v.store::inspect, { v.devicePoint })
                assertEquals("drop03", decision.route); assertNotNull(decision.provenance)
                assertTrue(decision.toString().contains("never-positive"))
            }
            assertEquals("installed", v.f.line.db.profile03Elections().find(v.installed.challengeId)!!.state)
            assertNull(v.f.line.db.captures03().counter(v.installed.accountId, v.installed.deviceId))
        }
    }
    @Test fun partialRootKeyScopeOrSignatureHistoryBlocksWithoutLegacyFallback() {
        Profile03RetainedElectionTest.Fixture().use { v ->
            fun decide(row: Profile03ElectionRecord = v.installed, sub: Int? = v.f.line.selected,
                compared: () -> Draft02TrustStore.Result = v.store::inspect, point: ByteArray = v.devicePoint) =
                Capture03Exclusion.decide(listOf(row), false, v.f.binding, sub, compared, { point })
            assertEquals("blocked", decide(compared = { Draft02TrustStore.Result(Draft02TrustStore.Status.KEY_LOST) }).route)
            assertEquals("blocked", decide(sub = null).route)
            assertEquals("blocked", decide(sub = v.f.line.selected + 1).route)
            assertEquals("blocked", decide(point = v.ownerPoint).route)
            val changed = Profile03ElectionEncoding.decode(checkNotNull(v.installed.deviceSignatureB64url), 64).apply { this[3] = (this[3].toInt() xor 1).toByte() }
            assertEquals("blocked", decide(row = v.installed.copy(deviceSignatureB64url = Profile03ElectionEncoding.encode(changed))).route)
            assertEquals("blocked", decide(row = v.installed.copy(state = "reserved", deviceSignatureB64url = null, acceptedEvidenceSha256 = null)).route)
            Profile03RetainedElectionTest.Fixture().use { other -> assertEquals("blocked", decide(compared = other.store::inspect).route) }
        }
    }
    @Test fun missingRawElectionWithRetainedProtectedModeNeverSelectsLegacy() {
        var providerReads = 0
        assertEquals("blocked", Capture03Exclusion.decide(emptyList(), true, null, null,
            { providerReads++; error("not needed") }, { providerReads++; error("not needed") }).route)
        assertEquals("legacy", Capture03Exclusion.decide(emptyList(), false, null, null,
            { providerReads++; error("not needed") }, { providerReads++; error("not needed") }).route)
        assertEquals(0, providerReads)
    }
    @Test fun unknownOldJournalReadBecomesPermanentBlockAndCannotBeUpgradedOnRetry() = database { db ->
        val token = h('a'); var reads = 0
        val first = Capture03Ingress.claim(db.captures03(), token, 1000,
            Capture03Exclusion.Candidate("legacy", null), {}, { reads++; error("unreadable old journal") })
        assertEquals("blocked", first.row.route); assertFalse(first.firstLegacy)
        val duplicate = Capture03Ingress.claim(db.captures03(), token, 2000,
            Capture03Exclusion.Candidate("legacy", null), {}, { reads++; false })
        assertEquals(first.row, duplicate.row); assertFalse(duplicate.firstLegacy); assertEquals(1, reads)
    }
    @Test fun legacyReservationIsCommittedBeforeProviderAndDuplicateCannotPromoteItsDroppedReceipt() = database { db ->
        val token = h('a')
        val first = Capture03Ingress.claim(db.captures03(), token, 1000, Capture03Exclusion.Candidate("legacy", null), {}, { false })
        assertTrue(first.firstLegacy); assertEquals(first.row, db.captures03().route(token))
        Capture03IngressGate.requireOutside() // The actual receiver invokes its provider here.
        val duplicate = Capture03Ingress.claim(db.captures03(), token, 2000, Capture03Exclusion.Candidate("legacy", null), {}, { false })
        assertFalse(duplicate.firstLegacy)
        assertEquals(1000L, duplicate.row.recordedMs)
    }
    @Test fun oldMetadataOrPossiblySignedReceiptAlwaysExcludesNewCaptureRoute() = database { db ->
        val decision = Capture03Ingress.claim(db.captures03(), h('a'), 1000,
            Capture03Exclusion.Candidate("drop03", h('b')), {}, { true })
        assertEquals("legacy", decision.row.route); assertFalse(decision.firstLegacy)
        assertNull(decision.row.captureId); assertNull(decision.row.provenanceSha256)
    }
    @Test fun actualLegacyReadDoesNotCreateAMissingDatabaseAndRetainsSignedTombstone() {
        val context = RuntimeEnvironment.getApplication()
        context.deleteDatabase(ConversationJournalStores.CAPTURE_FILE)
        try {
            assertFalse(Capture03IngressGate.reserve { Capture03Ingress.legacyReceipt(context, h('a')) })
            assertFalse(context.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            context.openOrCreateDatabase(ConversationJournalStores.CAPTURE_FILE, Context.MODE_PRIVATE, null).use { old ->
                old.execSQL("CREATE TABLE conversation_receipts(token TEXT PRIMARY KEY)")
                old.execSQL("CREATE TABLE conversation_wire_captures(token TEXT PRIMARY KEY, acknowledgedDigest TEXT)")
                old.execSQL("INSERT INTO conversation_wire_captures VALUES(?, ?)", arrayOf(h('a'), h('b')))
                old.version = 3
            }
            assertTrue(Capture03IngressGate.reserve { Capture03Ingress.legacyReceipt(context, h('a')) })
            assertFalse(Capture03IngressGate.reserve { Capture03Ingress.legacyReceipt(context, h('c')) })
        } finally { context.deleteDatabase(ConversationJournalStores.CAPTURE_FILE) }
    }
    @Test fun changedSelectionAfterProviderWaitRollsBackRouteBeforeAnyLegacyEffect() = database { db ->
        var calls = 0
        assertThrows(IllegalStateException::class.java) { Capture03Ingress.claim(db.captures03(), h('a'), 1000,
            Capture03Exclusion.Candidate("legacy", null), { check(++calls < 3) }, { false }) }
        assertNull(db.captures03().route(h('a')))
    }
    @Test fun allOptActionsRetainActualReportingAndStopBlocksBeforeFailedContentRoute() = database { db ->
        val dao = db.attempts(); val attempt = id(71); val message = id(72); val event = id(73); val sender = h('b')
        dao.reserveAlpha(attempt, message, 7, 1, event, 1000, sender)
        dao.acknowledgeAlphaIntent(event, true, 1001); dao.consumeRadioStart(attempt, message, 7, 1, 1002)
        dao.recordCallback(attempt, 0, false, Activity.RESULT_OK, null, 1003)
        var contentCalls = 0; var reports = 0; var withdrawals = 0
        for ((index, action) in listOf(OptOutParser.OPT_OUT, OptOutParser.OPT_OUT_REVIEW, OptOutParser.OPT_IN).withIndex()) {
            val token = listOf(h('c'), h('d'), h('e'))[index]
            Capture03Ingress.deliver(action, withdraw = {
                withdrawals++
                dao.recordLocalWithdrawal(token, sender, action, 7, null, 2000)
            }, reserve = {
                if (action != OptOutParser.OPT_IN) assertTrue(dao.isRecipientSuppressed(sender))
                error("stopped/missing content route")
            }, legacyContent = { contentCalls++ }, metadata = { first ->
                assertFalse(first); reports++
                val row = dao.recordInbound(dao.activeInboundWindows(sender, 2000).single(), token, 7, 1, 2000,
                    null, null, action)!!
                assertEquals(action, row.classification); assertNull(row.encryptedBody)
                assertNotNull(dao.inboundUpload(row.eventId))
            })
        }
        assertEquals(0, contentCalls); assertEquals(3, reports); assertEquals(2, withdrawals)
        assertTrue(dao.isRecipientSuppressed(sender)) // OPT_IN never silently unsuppresses.
        assertEquals(2, listOf(h('c'), h('d'), h('e')).count { dao.localWithdrawal(it) != null })
    }
    @Test fun ordinaryBodyWithNoCurrentAuthorityDoesNotEnterEitherContentWriter() {
        var content = 0; var metadata = 0
        Capture03Ingress.deliver(null, { error("not a withdrawal") }, { false }, { content++ }, { metadata++ })
        assertEquals(0, content); assertEquals(0, metadata)
    }
    @Test fun migrationAndColdReopenKeepRouteWithoutCreatingCounterOrReconstructingTicket() {
        val context = RuntimeEnvironment.getApplication(); val name = "capture03-upgrade-test.db"
        context.deleteDatabase(name)
        fun open() = Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
            .addMigrations(SmsJournalDatabase.MIGRATION_18_19).build()
        try {
            open().use { db ->
                db.attempts().insertAttempt(SmsAttempt(id(91), 3, 1, AttemptState.UNKNOWN, 1000, 1000))
                // Exact parent18 tables are unchanged. Remove ONLY new19 tables to construct
                // the immediate predecessor, then require Room's independent schema check.
                for (table in listOf("capture03_routes", "capture03_records", "capture03_counters", "capture03_modes"))
                    db.openHelper.writableDatabase.execSQL("DROP TABLE $table")
                db.openHelper.writableDatabase.execSQL("DROP TABLE room_master_table")
                db.openHelper.writableDatabase.version = 18
            }
            open().use { db ->
                assertEquals(19, db.openHelper.readableDatabase.version); assertNotNull(db.attempts().getAttempt(id(91)))
                assertNull(db.captures03().counter(id(1), id(2)))
                Capture03Ingress.claim(db.captures03(), h('a'), 2000, Capture03Exclusion.Candidate("drop03", h('b')), {}, { false })
            }
            open().use { db ->
                val duplicate = Capture03Ingress.claim(db.captures03(), h('a'), 3000, Capture03Exclusion.Candidate("legacy", null), {}, { false })
                assertEquals("drop03", duplicate.row.route); assertFalse(duplicate.firstLegacy)
                assertNull(db.captures03().counter(id(1), id(2)))
            }
        } finally { context.deleteDatabase(name) }
    }
    private fun database(action: (SmsJournalDatabase) -> Unit) {
        Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build().use(action)
    }
    companion object {
        private fun id(n: Long) = UUID(0, n).toString()
        private fun h(c: Char) = c.toString().repeat(64)
    }
}
