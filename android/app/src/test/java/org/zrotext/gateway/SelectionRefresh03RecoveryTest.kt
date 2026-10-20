// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.nio.ByteBuffer
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SelectionRefresh03RecoveryTest {
    @Test fun sharedStructuralVectorPassesTheShippingClosedDecoderWithoutAnyInventedObservation() {
        val vector = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-refresh-closures-01.json")!!.use {
            org.json.JSONObject(it.bufferedReader().readText())
        }
        val rows = SelectionRefresh03Closure.decode(Profile03Json.objectValue(
            ("{\"closed_unaccepted\":" + vector.getJSONArray("closed_unaccepted") + "}").toByteArray()))
        val target = SelectionRefresh03.Core.decode(Profile03ElectionEncoding.decode(vector.getString("target_core"), 496))
        SelectionRefresh03Closure.requireChain(target, rows, vector.getString("authenticated_now_ms").toLong())
        assertEquals(2, rows.size)
        assertEquals("SelectionRefresh03ClosureRecord(server-history-only)", rows.first().toString())
    }
    private class Fixture : AutoCloseable {
        val v = SelectionRefresh03JournalTest.Fixture()
        val first = v.reserved
        val second = successor(82, v.core.expiresMs + 1_000)
        val targetCore = successor(83, v.core.expiresMs + 3_000)
        val now = targetCore.issuedMs + 10
        val closures = listOf(close(v.core, second, 90), close(second, targetCore, 91))
        init { v.f.line.callback() }
        val observation = checkNotNull(v.f.line.owner.capture()).observation().bytes()
        val target = first.copy(refreshId = targetCore.refresh.toString(), consentId = UUID(0, 92).toString(),
            consentConfirmedMs = targetCore.issuedMs, consentExpiresMs = targetCore.issuedMs + 300_000,
            coreB64url = b64(targetCore.bytes()), observationB64url = b64(observation))
        val dao get() = v.dao
        fun successor(id: Long, issued: Long): SelectionRefresh03.Core {
            val bytes = v.core.bytes()
            ReviewedIntent03.uuid(UUID(0, id)).copyInto(bytes, 56)
            bytes.fill(id.toByte(), 376, 408) // A genuinely fresh owner session is allowed.
            bytes.fill(id.toByte(), 440, 472)
            ByteBuffer.wrap(bytes, 472, 8).putLong(issued)
            ByteBuffer.wrap(bytes, 480, 8).putLong(issued + 1_000)
            return SelectionRefresh03.Core.decode(bytes)
        }
        fun retainSigned(retire: Boolean = false): SelectionRefresh03Record {
            check(dao.reserve(v.reserved) {})
            check(dao.advance(v.signed, "reserved") {})
            if (retire) check(dao.retire(v.signed.refreshId) == 1)
            return checkNotNull(dao.find(first.refreshId))
        }
        fun reserve() = dao.reserveWithClosures(target, closures, now) { check(it == v.f.binding) }
        override fun close() = v.close()
    }
    @Test fun immutableCompleteChainCommitsWithFreshObservationWithoutInventingIntermediateProofs(): Unit = Fixture().use { r ->
        val signed = r.retainSigned()
        assertFalse(r.observation.contentEquals(Profile03ElectionEncoding.decode(signed.observationB64url, 121)))
        assertTrue(r.reserve())
        assertEquals(signed, r.dao.find(r.first.refreshId))
        assertEquals(r.target, r.dao.find(r.target.refreshId))
        assertNull(r.dao.find(r.second.refresh.toString()))
        for (row in r.closures) assertEquals(row, r.dao.closure(row.refreshId))
        assertTrue(r.dao.everSigned(r.first.bindingId, r.first.deviceSessionSha256))
        assertFalse(r.dao.everSigned(r.first.bindingId, "f".repeat(64)))
        assertNull(r.v.f.binding.installedSelectionV2()) // No original physical fallback.
        assertEquals(r.v.f.installed, r.v.f.line.db.profile03Elections().find(r.v.f.installed.challengeId))
    }
    @Test fun retiredSignedHistoryRequiresExplicitClosureAndForeverFencesOriginalConnectionFallback(): Unit = Fixture().use { r ->
        val retired = r.retainSigned(true)
        assertFalse(r.dao.reserve(r.target) {})
        assertThrows(IllegalStateException::class.java) { r.dao.reserveWithClosures(r.target, emptyList(), r.now) {} }
        assertTrue(r.reserve())
        assertEquals(retired, r.dao.find(r.first.refreshId))
        assertTrue(r.dao.everSigned(r.first.bindingId, r.first.deviceSessionSha256))
        assertFalse(r.dao.advance(r.v.accepted, "signed") {})
        assertFalse(r.dao.advance(r.v.installed, "ack_signed") {})
    }
    @Test fun changedLocalCoreMissingAncestorOrAnyAcceptedReceiptRefusesWithoutHistoryMutation() {
        Fixture().use { r ->
            r.retainSigned()
            val a = r.closures.first()
            val bytes = Profile03ElectionEncoding.decode(a.coreB64url, 496).also { it[440] = (it[440].toInt() xor 1).toByte() }
            for (rows in listOf(r.closures.drop(1), listOf(a.copy(coreB64url = b64(bytes)), r.closures.last()))) {
                assertThrows(IllegalStateException::class.java) { r.dao.reserveWithClosures(r.target, rows, r.now) {} }
                assertNull(r.dao.find(r.target.refreshId))
                assertNull(r.dao.closure(r.first.refreshId))
            }
        }
        Fixture().use { r ->
            r.retainSigned()
            assertTrue(r.dao.advance(r.v.accepted, "signed") {})
            assertEquals(1, r.dao.retire(r.first.refreshId))
            assertThrows(IllegalStateException::class.java) { r.reserve() }
            assertNull(r.dao.closure(r.first.refreshId))
        }
    }
    @Test fun closedUnsignedPredecessorCannotReleaseALateSignatureAndFreshReviewCannotReuseOldConsent(): Unit = Fixture().use { r ->
        assertTrue(r.dao.reserve(r.first) {})
        assertThrows(IllegalStateException::class.java) {
            r.dao.reserveWithClosures(r.target.copy(consentId = r.first.consentId), r.closures, r.now) {}
        }
        assertThrows(IllegalArgumentException::class.java) {
            r.dao.reserveWithClosures(r.target.copy(consentConfirmedMs = r.v.core.expiresMs - 1), r.closures, r.now) {}
        }
        assertTrue(r.reserve())
        assertFalse(r.dao.advance(r.v.signed, "reserved") {})
        assertFalse(r.dao.everSigned(r.first.bindingId, r.first.deviceSessionSha256))
        assertEquals(r.first, r.dao.find(r.first.refreshId))
    }
    @Test fun guardWithdrawalRollsBackWholeChainAndTargetBeforeAnyNewProof(): Unit = Fixture().use { r ->
        val signed = r.retainSigned()
        var calls = 0
        assertThrows(IllegalStateException::class.java) {
            r.dao.reserveWithClosures(r.target, r.closures, r.now) { check(++calls <= 2) }
        }
        assertEquals(signed, r.dao.find(r.first.refreshId))
        assertNull(r.dao.find(r.target.refreshId))
        for (row in r.closures) assertNull(r.dao.closure(row.refreshId))
    }
    @Test fun strictChainRejectsWrongCurrentScopeTimeLinkOrderAndDuplicateHistory(): Unit = Fixture().use { r ->
        SelectionRefresh03Closure.requireChain(r.targetCore, r.closures, r.now)
        for (offset in listOf(8, 24, 40, 72, 88, 96, 104, 112, 120, 152, 184, 216, 248, 280, 312, 344, 408)) {
            val changed = r.v.core.bytes().also { it[offset] = (it[offset].toInt() xor 1).toByte() }
            val old = r.closures.first().copy(coreB64url = b64(changed))
            assertThrows(IllegalArgumentException::class.java) { SelectionRefresh03Closure.requireChain(r.targetCore, listOf(old, r.closures.last()), r.now) }
        }
        val a = r.closures.first(); val b = r.closures.last()
        for (rows in listOf(listOf(b, a), listOf(a, a), List(17) { a },
            listOf(a.copy(closedUnacceptedMs = a.closedUnacceptedMs + 1), b),
            listOf(a.copy(supersededByRefreshId = r.target.refreshId), b), listOf(a, b.copy(openingId = a.openingId))))
            assertThrows(IllegalArgumentException::class.java) { SelectionRefresh03Closure.requireChain(r.targetCore, rows, r.now) }
        assertThrows(IllegalArgumentException::class.java) { SelectionRefresh03Closure.requireChain(r.targetCore, r.closures, r.targetCore.expiresMs) }
    }
    @Test fun closureWireIsClosedCanonicalAndCannotUseElectionReceipts(): Unit = Fixture().use { r ->
        val row = r.closures.first()
        val fields = mapOf("opening_id" to row.openingId, "refresh_id" to row.refreshId, "core" to row.coreB64url,
            "closed_unaccepted_ms" to row.closedUnacceptedMs.toString(), "superseded_by_refresh_id" to row.supersededByRefreshId)
        val frame = mapOf("closed_unaccepted" to listOf(fields))
        assertEquals(listOf(row), SelectionRefresh03Closure.decode(Profile03Json.objectValue(Profile03Json.render(frame))))
        for (bad in listOf(fields - "opening_id", fields + ("new_binding_id" to r.first.bindingId),
            fields + ("closed_unaccepted_ms" to "01"), fields + ("refresh_id" to UUID(0, 0).toString())))
            assertThrows(Exception::class.java) { SelectionRefresh03Closure.decode(mapOf("closed_unaccepted" to listOf(bad))) }
    }
    @Test fun genuinelyNewForegroundDecisionAfterExpiryIsRequiredAndCancellationStillWithdrawsIt(): Unit = Fixture().use { r ->
        var instant = r.now
        val inputs = object : SamePhoneSelectionReview.Inputs {
            override fun withdrawInstalled() = r.v.f.line.owner.retireInstalled()
            override fun requireSession() = Unit
            override fun nowMs() = instant
            override fun captureFresh() = r.v.f.line.owner.capture()
            override fun retained() = SamePhoneSelectionReview.Retained(r.v.f.binding,
                checkNotNull(r.v.f.line.db.lineActivationsV2().find("sealed", r.v.f.line.challengeId.toString())),
                r.v.f.installed, r.v.f.line.point)
        }
        SamePhoneSelectionReview(inputs).use { controller ->
            val review = checkNotNull(controller.prepare())
            assertTrue(controller.confirm(review))
            val pending = checkNotNull(controller.takePending())
            SelectionRefresh03Closure.requireFreshDecision(r.v.signed, pending, r.now)
            assertThrows(IllegalStateException::class.java) { SelectionRefresh03Closure.requireFreshDecision(
                r.v.signed.copy(consentId = pending.consentId.toString()), pending, r.now) }
            assertThrows(IllegalArgumentException::class.java) { SelectionRefresh03Closure.requireFreshDecision(r.v.accepted, pending, r.now) }
            controller.cancel()
            assertThrows(IllegalStateException::class.java) { SelectionRefresh03Closure.requireFreshDecision(r.v.signed, pending, r.now) }
        }
        instant = r.v.core.expiresMs - 1
        SamePhoneSelectionReview(inputs).use { controller ->
            assertTrue(controller.confirm(checkNotNull(controller.prepare())))
            val early = checkNotNull(controller.takePending())
            assertThrows(IllegalStateException::class.java) { SelectionRefresh03Closure.requireFreshDecision(r.v.signed, early, r.now) }
        }
    }
    @Test fun sixteenRetainedReservationsBoundOneConnectionEvenWhenUnsignedOnesWereRetired(): Unit = Fixture().use { r ->
        for (index in 0 until SelectionRefresh03Dao.CONNECTION_CAPACITY) {
            val id = UUID(0, 200L + index)
            val core = r.v.core.bytes().also { ReviewedIntent03.uuid(id).copyInto(it, 56) }
            val row = r.first.copy(refreshId = id.toString(), coreB64url = b64(core))
            assertTrue(r.dao.reserve(row) {})
            assertEquals(1, r.dao.retire(row.refreshId))
            assertEquals(row.copy(state = "retired"), r.dao.find(row.refreshId))
        }
        assertFalse(r.dao.reserve(r.target) {})
        assertFalse(r.dao.everSigned(r.first.bindingId, r.first.deviceSessionSha256))
        assertNull(r.dao.find(r.target.refreshId))
    }
    @Test fun unseenServerReservationsCountTowardTheSameSixteenBoundWithoutFakeLocalRows(): Unit = Fixture().use { r ->
        val cores = (0..16).map { r.successor(300L + it, 400_000L + it * 2_000L) }
        val rows = cores.dropLast(1).mapIndexed { i, old -> close(old, cores[i + 1], 400L + i) }
        val last = cores.last()
        val target = r.target.copy(refreshId = last.refresh.toString(), coreB64url = b64(last.bytes()),
            consentConfirmedMs = last.issuedMs, consentExpiresMs = last.issuedMs + 300_000)
        SelectionRefresh03Closure.requireChain(last, rows, last.issuedMs + 1)
        assertFalse(r.dao.reserveWithClosures(target, rows, last.issuedMs + 1) {})
        assertNull(r.dao.find(target.refreshId))
        for (row in rows) { assertNull(r.dao.find(row.refreshId)); assertNull(r.dao.closure(row.refreshId)) }
    }
    @Test fun schemaSeventeenUpgradeRetainsSignedAndUnknownHistory(): Unit = Fixture().use { r ->
        r.retainSigned()
        val context = org.robolectric.RuntimeEnvironment.getApplication()
        val name = "refresh-closure-${UUID.randomUUID()}.db"
        check(context.getDatabasePath(name).parentFile?.mkdirs() == true || context.getDatabasePath(name).parentFile?.isDirectory == true)
        val unknown = SmsAttempt(UUID(0, 94).toString(), r.v.f.line.selected, 1, AttemptState.UNKNOWN, 1, 1)
        try {
            androidx.room.Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build().let { saved ->
                try {
                    val actual = r.v.f.line.db.openHelper.readableDatabase
                    for (table in listOf("local_line_binding", "line_activation_v2", "profile03_elections", "selection_refresh03")) {
                        actual.query("SELECT * FROM $table").use { rows ->
                            while (rows.moveToNext()) {
                                val values = android.content.ContentValues()
                                for (index in 0 until rows.columnCount) {
                                    val column = rows.getColumnName(index)
                                    when (rows.getType(index)) {
                                        android.database.Cursor.FIELD_TYPE_NULL -> values.putNull(column)
                                        android.database.Cursor.FIELD_TYPE_INTEGER -> values.put(column, rows.getLong(index))
                                        android.database.Cursor.FIELD_TYPE_STRING -> values.put(column, rows.getString(index))
                                        else -> error("Unexpected journal fixture type")
                                    }
                                }
                                saved.openHelper.writableDatabase.insert(table, android.database.sqlite.SQLiteDatabase.CONFLICT_ABORT, values)
                            }
                        }
                    }
                    saved.attempts().insertAttempt(unknown)
                } finally { saved.close() }
            }
            context.openOrCreateDatabase(name, android.content.Context.MODE_PRIVATE, null).use {
                it.execSQL("DROP TABLE selection_refresh03_closures")
                it.version = 17
            }
            androidx.room.Room.databaseBuilder(context, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
                .addMigrations(SmsJournalDatabase.MIGRATION_17_18, SmsJournalDatabase.MIGRATION_18_19).build().let { migrated ->
                    try {
                        assertEquals(19, migrated.openHelper.readableDatabase.version)
                        assertEquals(r.v.signed, migrated.selectionRefreshes03().find(r.first.refreshId))
                        assertEquals(r.v.f.installed, migrated.profile03Elections().find(r.v.f.installed.challengeId))
                        assertEquals(r.v.f.binding, migrated.attempts().currentLineBinding())
                        assertEquals(unknown, migrated.attempts().getAttempt(unknown.attemptId))
                        assertTrue(migrated.selectionRefreshes03().everSigned(r.first.bindingId, r.first.deviceSessionSha256))
                        assertNull(migrated.selectionRefreshes03().closure(r.first.refreshId))
                        assertNull(checkNotNull(migrated.attempts().currentLineBinding()).installedSelectionV2())
                    } finally { migrated.close() }
                }
        } finally { context.deleteDatabase(name) }
    }
    companion object {
        private fun b64(bytes: ByteArray) = Profile03ElectionEncoding.encode(bytes)
        private fun close(old: SelectionRefresh03.Core, next: SelectionRefresh03.Core, opening: Long) =
            SelectionRefresh03ClosureRecord(UUID(0, opening).toString(), old.refresh.toString(), b64(old.bytes()), next.issuedMs, next.refresh.toString())
    }
}
