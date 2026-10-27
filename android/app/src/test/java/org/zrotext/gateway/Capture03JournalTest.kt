// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Real Room transactions. Counter seeding is TEST-ONLY SQL, not a usable bootstrap factory,
 * key/canary/current permission or an assertion that a hardware signature took place. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Capture03JournalTest {
    private class Fixture : AutoCloseable {
        val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        val dao = db.captures03()
        val row = record(11)
        fun claim(row: Capture03Record = this.row) = Capture03IngressGate.reserve {
            dao.claim(Capture03Route(row.routeToken, "capture03", h('a'), row.captureId, 10_000), row, false) {}
        }
        fun seed(at: Long = 0): Capture03Counter {
            db.openHelper.writableDatabase.execSQL("INSERT INTO capture03_counters VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                arrayOf(id(1), id(2), id(21), id(22), h('a'), h('b'), h('c'), h('d'), at, ByteArray(20) { 2 }, ByteArray(12) { 3 }))
            return checkNotNull(dao.counter(id(1), id(2)))
        }
        fun sequence(row: Capture03Record = this.row, expected: Capture03Counter = checkNotNull(dao.counter(id(1), id(2)))): Capture03Record {
            val next = row.copy(phase = "sealing", sequence = expected.lastSequence + 1, permissionExpiresMs = 20_000)
            Capture03IngressGate.reserve { dao.reserveSequence(row, next, expected) {} }; return next
        }
        fun packet(): Capture03Record {
            claim(); seed(); var row = sequence()
            for (phase in listOf("envelope_reserved", "envelope_signed", "intent_reserved", "packet")) {
                val next = next(row, phase); dao.advance(row, next) {}; row = next
            }
            return row
        }
        override fun close() = db.close()
    }
    @Test fun emptyTableDoesNotInitializeZeroOrUseAnIdentityAsAllocator(): Unit = Fixture().use { f ->
        f.claim()
        assertNull(f.dao.counter(id(1), id(2)))
        val fake = Capture03Counter(id(1), id(2), id(21), id(22), h('a'), h('b'), h('c'), h('d'), 0, ByteArray(20), ByteArray(12))
        assertThrows(IllegalStateException::class.java) { f.sequence(expected = fake) }
        assertNull(f.dao.counter(id(1), id(2))); assertTrue(f.dao.record(f.row.captureId)!!.same(f.row))
    }
    @Test fun routeClaimRequiresProcessOrderingAndPostWriterWithdrawalRollsBackEverything(): Unit = Fixture().use { f ->
        val route = Capture03Route(f.row.routeToken, "capture03", h('a'), f.row.captureId, 10_000)
        assertThrows(IllegalStateException::class.java) { f.dao.claim(route, f.row, false) {} }
        var calls = 0
        assertThrows(IllegalStateException::class.java) { Capture03IngressGate.reserve {
            f.dao.claim(route, f.row, false) { check(++calls == 1) }
        } }
        assertNull(f.dao.route(f.row.routeToken)); assertNull(f.dao.record(f.row.captureId))
    }
    @Test fun preexistingLegacyReceiptOverridesNewCaptureWithoutSequenceOrBody(): Unit = Fixture().use { f ->
        val route = Capture03IngressGate.reserve { f.dao.claim(
            Capture03Route(f.row.routeToken, "capture03", h('a'), f.row.captureId, 10_000), f.row, true) {} }
        assertEquals("legacy", route.route); assertNull(route.captureId)
        assertNull(f.dao.record(f.row.captureId)); assertNull(f.dao.counter(id(1), id(2)))
    }
    @Test fun dropAndBlockedRoutesCanNeverBePromotedOnDuplicateOrFreshPermission(): Unit = Fixture().use { f ->
        for ((token, kind) in listOf(h('a') to "drop03", h('b') to "blocked")) {
            val row = f.row.copy(routeToken = token, captureId = if (kind == "drop03") id(31) else id(32))
            val initial = Capture03Route(token, kind, if (kind == "drop03") h('c') else null, null, 10_000)
            Capture03IngressGate.reserve { f.dao.claim(initial, null, false) {} }
            assertEquals(initial, f.claim(row)); assertNull(f.dao.record(row.captureId))
        }
    }
    @Test fun positiveSequenceIsGlobalAcrossLineIntervalStopAndRedaction(): Unit = Fixture().use { f ->
        f.claim(); f.seed(); val first = f.sequence()
        f.dao.redact(first, 21_000)
        val second = record(12).copy(lineId = id(41), intervalId = id(42), routeToken = h('b'))
        f.claim(second); val next = f.sequence(second)
        assertEquals(2L, next.sequence); assertEquals(2L, f.dao.counter(id(1), id(2))!!.lastSequence)
        assertEquals(1L, f.dao.record(first.captureId)!!.sequence)
        assertEquals("capture03", f.dao.route(first.routeToken)!!.route)
        assertThrows(IllegalStateException::class.java) { f.sequence() }
    }
    @Test fun exactCounterComparesOwnedArrayContentsAndRefusesChangedBootstrap(): Unit = Fixture().use { f ->
        f.claim(); val initial = f.seed()
        assertTrue(initial.same(initial.copy(protectedOrigin = initial.protectedOrigin.copyOf(), nonce = initial.nonce.copyOf())))
        assertThrows(IllegalStateException::class.java) { f.sequence(expected = initial.copy(receiptSha256 = h('f'))) }
        assertThrows(IllegalStateException::class.java) { f.sequence(expected = initial.copy(protectedOrigin = ByteArray(20) { 9 })) }
        assertEquals(1L, f.sequence(expected = initial).sequence)
    }
    @Test fun sequenceOverflowRefusesWithoutWrappingOrChangingOriginalIdentity(): Unit = Fixture().use { f ->
        f.claim(); val counter = f.seed(Long.MAX_VALUE)
        val next = f.row.copy(phase = "sealing", sequence = 1, permissionExpiresMs = 20_000)
        assertThrows(IllegalArgumentException::class.java) { Capture03IngressGate.reserve { f.dao.reserveSequence(f.row, next, counter) {} } }
        assertEquals(Long.MAX_VALUE, f.dao.counter(id(1), id(2))!!.lastSequence)
        assertTrue(f.dao.record(f.row.captureId)!!.same(f.row))
    }
    @Test fun sequencePostWaitGuardFailureRollsBackBothCounterAndPhase(): Unit = Fixture().use { f ->
        f.claim(); val counter = f.seed(); var calls = 0
        val next = f.row.copy(phase = "sealing", sequence = 1, permissionExpiresMs = 20_000)
        assertThrows(IllegalStateException::class.java) { Capture03IngressGate.reserve {
            f.dao.reserveSequence(f.row, next, counter) { check(++calls == 1) }
        } }
        assertEquals(0L, f.dao.counter(id(1), id(2))!!.lastSequence)
        assertTrue(f.dao.record(f.row.captureId)!!.same(f.row))
    }
    @Test fun everyIrreversibleSignaturePhaseNeedsItsExactCommittedPredecessor(): Unit = Fixture().use { f ->
        f.claim(); f.seed(); val sealing = f.sequence(); val reserved = next(sealing, "envelope_reserved")
        f.dao.advance(sealing, reserved) {}
        assertThrows(IllegalStateException::class.java) { f.dao.advance(sealing, reserved) {} }
        val signed = next(reserved, "envelope_signed")
        f.dao.advance(reserved, signed) {}
        val intent = next(signed, "intent_reserved"); f.dao.advance(signed, intent) {}
        assertThrows(IllegalArgumentException::class.java) { f.dao.advance(intent,
            next(intent, "packet").copy(envelopeSha256 = h('f'))) {} }
        val unknown = f.dao.markUnknown(intent)
        assertThrows(IllegalStateException::class.java) { f.dao.advance(intent, next(intent, "packet")) {} }
        assertThrows(IllegalArgumentException::class.java) { f.dao.advance(unknown, next(unknown, "packet").copy(unknown = false)) {} }
        assertTrue(f.dao.record(intent.captureId)!!.unknown)
    }
    @Test fun providerCompletionAfterWithdrawalCannotCommitItsSignature(): Unit = Fixture().use { f ->
        f.claim(); f.seed(); val sealing = f.sequence(); val reserved = next(sealing, "envelope_reserved")
        f.dao.advance(sealing, reserved) {}; var calls = 0
        assertThrows(IllegalStateException::class.java) { f.dao.advance(reserved, next(reserved, "envelope_signed")) { check(++calls == 1) } }
        assertTrue(f.dao.record(reserved.captureId)!!.same(reserved))
        f.dao.markUnknown(reserved)
        assertThrows(IllegalStateException::class.java) { f.dao.advance(reserved, next(reserved, "envelope_signed")) {} }
    }
    @Test fun unknownPacketCanReceiveHistoricalAckAfterRedactionWithoutRestoringContent(): Unit = Fixture().use { f ->
        val packet = f.packet(); val unknown = f.dao.markUnknown(packet); val redacted = f.dao.redact(unknown, 21_000)
        val ack = redacted.copy(phase = "acknowledged", receiptSha256 = h('f'))
        f.dao.acknowledge(redacted, ack) {}
        assertNull(f.dao.record(packet.captureId)!!.protectedPayload)
        assertTrue(f.dao.record(packet.captureId)!!.unknown)
        assertEquals(1L, f.dao.counter(id(1), id(2))!!.lastSequence)
        assertThrows(IllegalStateException::class.java) { f.dao.acknowledge(redacted, ack) {} }
    }
    @Test fun ordinaryPhaseAdvanceCannotReplaceHistoricalAckValidation(): Unit = Fixture().use { f ->
        val packet = f.packet(); val submitted = next(packet, "submitted"); f.dao.advance(packet, submitted) {}
        assertThrows(IllegalArgumentException::class.java) { f.dao.advance(submitted,
            submitted.copy(phase = "acknowledged", receiptSha256 = h('f'))) {} }
        f.dao.acknowledge(submitted, submitted.copy(phase = "acknowledged", receiptSha256 = h('f'))) {}
    }
    @Test fun modeRetainsFirstProtectedOriginalAndRejectsIdentityReplacement(): Unit = Fixture().use { f ->
        val row = Capture03Mode(id(51), id(1), id(2), id(3), id(4), h('a'), h('b'), ByteArray(25) { 3 }, ByteArray(12) { 4 })
        f.dao.retainOriginal(row) {}
        f.dao.retainOriginal(row.copy(protectedEvidence = ByteArray(25) { 8 }, nonce = ByteArray(12) { 9 })) {}
        assertArrayEquals(row.protectedEvidence, f.dao.mode(row.electionId)!!.protectedEvidence)
        assertThrows(IllegalArgumentException::class.java) { f.dao.retainOriginal(row.copy(originalIdentity = h('f'))) {} }
        var calls = 0
        assertThrows(IllegalStateException::class.java) { f.dao.retainOriginal(row.copy(electionId = id(52))) { check(++calls == 1) } }
        assertNull(f.dao.mode(id(52)))
    }
    @Test fun concurrentLegacyAndCaptureReservationHasOnePermanentWinner(): Unit = Fixture().use { f ->
        val start = CountDownLatch(1); val pool = Executors.newFixedThreadPool(2)
        try {
            val jobs = (0..1).map { index -> pool.submit<Capture03Route> {
                check(start.await(5, TimeUnit.SECONDS)); Capture03IngressGate.reserve {
                    val candidate = if (index == 0) Capture03Route(f.row.routeToken, "legacy", null, null, 10_000)
                        else Capture03Route(f.row.routeToken, "capture03", h('a'), f.row.captureId, 10_000)
                    f.dao.claim(candidate, if (index == 1) f.row else null, false) {}
                }
            } }; start.countDown(); val rows = jobs.map { it.get(10, TimeUnit.SECONDS) }
            assertEquals(rows[0], rows[1]); assertEquals(rows[0], f.dao.route(f.row.routeToken))
            assertEquals(rows[0].route == "capture03", f.dao.record(f.row.captureId) != null)
        } finally { pool.shutdownNow() }
    }
    @Test fun providerWaitOutsideReservationDoesNotBlockAnotherIngress(): Unit = Fixture().use { f ->
        val waiting = CountDownLatch(1); val release = CountDownLatch(1); val pool = Executors.newFixedThreadPool(2)
        try {
            val provider = pool.submit { Capture03Ingress.claim(f.dao, h('a'), 10_000,
                Capture03Exclusion.Candidate("legacy", null), {}, { false })
                Capture03IngressGate.requireOutside(); waiting.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
            check(waiting.await(5, TimeUnit.SECONDS))
            assertEquals("blocked", pool.submit<Capture03Ingress.Decision> { Capture03Ingress.claim(f.dao, h('b'), 10_000,
                Capture03Exclusion.Candidate("blocked", null), {}, { false }) }.get(3, TimeUnit.SECONDS).row.route)
            release.countDown(); provider.get(5, TimeUnit.SECONDS)
        } finally { release.countDown(); pool.shutdownNow() }
    }
    companion object {
        internal fun id(n: Long) = UUID(0, n).toString()
        internal fun h(c: Char) = c.toString().repeat(64)
        private fun record(n: Long) = Capture03Record(id(n), h('a'), id(1), id(2), id(3), id(4), id(n + 100), h('b'),
            10_000, 10_002, 20, "identity", protectedPayload = ByteArray(20), nonce = ByteArray(12))
        private fun next(row: Capture03Record, phase: String) = when (phase) {
            "envelope_reserved" -> row.copy(phase = phase, unsignedEnvelopeSha256 = h('c'))
            "envelope_signed" -> row.copy(phase = phase, envelopeSha256 = h('d'), envelopeSignatureSha256 = h('e'))
            "intent_reserved" -> row.copy(phase = phase, intentSha256 = h('a'))
            "packet" -> row.copy(phase = phase, intentSignatureSha256 = h('b'), packetSha256 = h('c'))
            "submitted" -> row.copy(phase = phase)
            else -> error("test transition")
        }
    }
}
