// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID

/**
 * Roadmap #628 lane: the grant-driven caller fetches only the grant-bound
 * envelope, refuses without vouched trusted time, and submits only behind the
 * pre-submit fences, closing the prepared text on every path. The JVM has no
 * Android Keystore, so executor-path tests observe the journal (reserved then
 * aborted at the custody fence) and the post-decrypt stage is driven directly
 * over the primitive seams, exactly like [SealedDispatchExecutor.settle].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SealedDispatchLaneTest {
    private val f = PreparationFixture()
    private val vectors = JSONObject(
        checkNotNull(javaClass.classLoader?.getResourceAsStream("sealed-execution-grant-01.json"))
            .use { it.readBytes() }.toString(Charsets.UTF_8)
    )
    private val fields = SealedExecutionGrantFrame.parse(frame())
    private val session = SealedDispatchExecutor.Session(
        UUID.fromString(PreparationFixture.uuid(f.account)), UUID.fromString(PreparationFixture.uuid(f.device)),
        1L, 1L, UUID.fromString("61616161-6161-4161-8161-616161616161"), "ab".repeat(32),
    )

    private fun frame(patch: Map<String, Any> = emptyMap()) =
        JSONObject(vectors.getJSONObject("frame").toString()).also { copy -> patch.forEach { (k, v) -> copy.put(k, v) } }

    private fun local(binding: LocalLineBinding = f.binding()) = SealedDispatchExecutor.Local(
        binding, PreparationFixture.hex(f.json.getString("deviceKeyId")), 1L, 1L,
        Draft02OutboundPreparation.hex(f.authority().digest),
        Draft02OutboundPreparation.hash("+12".toByteArray()),
    )

    private fun db() = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
        .allowMainThreadQueries().build().also {
            assertTrue(it.attempts().installVerifiedLineBinding(f.binding(), listOf(ActiveSimCard(3, 7))))
        }

    private fun key() = DevicePayloadKeyStore("zrotext.test.unavailable.${UUID.randomUUID()}")

    /** The trusted anchor: hub sample f.now at elapsed 500_000; the grant expires at f.now + 15_000. */
    private fun clock(epoch: Long = 1L, hubMs: Long = f.now) =
        checkNotNull(SealedSessionClock.establish(epoch, hubMs, 500_000L))

    private fun lane(
        db: SmsJournalDatabase,
        clock: SealedSessionClock = clock(),
        elapsed: () -> Long = { 500_010L },
        fetch: (ByteArray) -> ByteArray? = { f.envelope() },
        localTruth: () -> SealedDispatchExecutor.Local? = { local() },
        current: (Draft02OutboundPreparation.Grant) -> Draft02OutboundPreparation.Current? = { f.current(it) },
        suppressed: (ByteArray) -> Boolean = { false },
        cards: () -> List<ActiveSimCard>? = { listOf(ActiveSimCard(3, 7)) },
        sessionCurrent: () -> Boolean = { true },
        submit: (SealedExecutionGrantValidator.Fields, Int, ((CharArray) -> Unit) -> Unit) -> SealedDispatchLane.Submission =
            { _, _, _ -> SealedDispatchLane.Submission.SUBMITTED },
    ) = SealedDispatchLane(
        session, clock, fetch, localTruth, db, key(), elapsed, current,
        suppressed, cards, sessionCurrent, submit,
    )

    /** What preparation left behind for the submit stage: a finished `prepared` row. */
    private fun preparedRow(db: SmsJournalDatabase, segments: Int = 1) {
        val dao = db.sealedPreparations()
        val record = SealedPreparationRecord(
            fields.accountId.toString(), fields.messageId.toString(), fields.attemptId.toString(),
            Draft02OutboundPreparation.hex(fields.unsignedDigest), Draft02OutboundPreparation.hex(ByteArray(32) { 1 }),
        )
        dao.reserve(record) { }
        dao.finish(record, segments) { }
    }

    /** The one-use zeroizing holder stand-in: closed exactly like the Keystore-gated real one. */
    private class HeldText(val text: String = "synthetic sealed body") {
        var closed = false
            private set
        var consumed = false
            private set
        fun consumeText(consumer: (CharArray) -> Unit) {
            check(!closed && !consumed) { "Holder closed or consumed" }
            consumed = true
            consumer(text.toCharArray())
        }
        fun closeText() { closed = true }
    }

    private fun rowState(db: SmsJournalDatabase): String? =
        db.sealedPreparations().find(fields.accountId.toString(), fields.messageId.toString())?.state

    @Test
    fun fetchIsBoundToTheGrantsEnvelopeDigestAndAMismatchedFetchIsRefused() {
        val db = db()
        try {
            val fetched = ArrayList<ByteArray>()
            val outcome = lane(db, fetch = { digest -> fetched.add(digest.copyOf()); f.envelope() })
                .onGrant(frame())
            assertEquals(1, fetched.size)
            assertTrue(fetched.single().contentEquals(fields.envelopeDigest))
            // The executor entered the journal (then aborted at the JVM custody fence).
            assertTrue(outcome is SealedDispatchLane.Outcome.Rejected || outcome is SealedDispatchLane.Outcome.Unsupported)
            assertEquals("aborted", rowState(db))
            // Bytes other than the digest-bound envelope never consume the grant.
            assertEquals(
                SealedDispatchLane.Outcome.Refused(SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_DIGEST_MISMATCH),
                lane(db, fetch = { f.envelope("wrongNonce") }).onGrant(frame()),
            )
            assertEquals(1, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test
    fun anUnavailableFetchOrUnvouchedTimeLeavesNoJournalRow() {
        val db = db()
        try {
            assertEquals(SealedDispatchLane.Outcome.Unavailable, lane(db, fetch = { null }).onGrant(frame()))
            // Reboot: monotonic reading at the anchor.
            assertEquals(SealedDispatchLane.Outcome.Unavailable, lane(db, elapsed = { 500_000L }).onGrant(frame()))
            // Stale anchor: past the one-minute bound.
            assertEquals(
                SealedDispatchLane.Outcome.Unavailable,
                lane(db, elapsed = { 500_000L + SealedSessionClock.MAX_ANCHOR_AGE_MS + 1 }).onGrant(frame()),
            )
            assertEquals(0, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test
    fun aGrantFromAnotherConnectionEpochIsRefusedBeforeAnyFetch() {
        val db = db()
        try {
            var fetched = 0
            assertEquals(
                SealedDispatchLane.Outcome.Unavailable,
                lane(db, clock = clock(epoch = 2L), fetch = { fetched++; f.envelope() }).onGrant(frame()),
            )
            assertEquals(0, fetched)
            assertEquals(0, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test
    fun everyPreSubmitFenceClosesTheTextAbortsTheRowAndNeverSubmits() {
        val token = { peer: ByteArray ->
            PreparationFixture.sha(peer).joinToString("") { "%02x".format(it.toInt() and 255) }
        }
        val cases = listOf<Pair<SealedDispatchLane.Fence, (HeldText, SmsJournalDatabase) -> SealedDispatchLane.Outcome>>(
            SealedDispatchLane.Fence.SESSION_TIME to { held, db ->
                lane(db, elapsed = { 500_000L + SealedSessionClock.MAX_ANCHOR_AGE_MS + 1 })
                    .submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            },
            SealedDispatchLane.Fence.EXPIRY to { held, db ->
                lane(db, elapsed = { 500_000L + 15_001L })
                    .submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            },
            SealedDispatchLane.Fence.SESSION_CANCELLED to { held, db ->
                lane(db, sessionCurrent = { false })
                    .submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            },
            SealedDispatchLane.Fence.SIM_CARD_CONTINUITY to { held, db ->
                lane(db, cards = { listOf(ActiveSimCard(3, 9)) })
                    .submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            },
            SealedDispatchLane.Fence.SIM_CARD_CONTINUITY to { held, db ->
                lane(db, cards = { null })
                    .submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            },
            SealedDispatchLane.Fence.LOCAL_SUPPRESSION to { held, db ->
                // A recorded STOP withdrawal keeps blocking the sealed submission.
                db.attempts().recordLocalWithdrawal(
                    "ab".repeat(32), token("+12".toByteArray()), InboundClassification.OPT_OUT,
                    3, listOf(ActiveSimCard(3, 7)), f.now,
                )
                lane(db, suppressed = { peer -> db.attempts().isRecipientSuppressed(token(peer)) })
                    .submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            },
            SealedDispatchLane.Fence.LOCAL_SUPPRESSION to { held, db ->
                // A peer that cannot be established under current authority fails closed.
                lane(db, current = { null })
                    .submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            },
            SealedDispatchLane.Fence.SEGMENT_CAP to { held, db ->
                lane(db).submitUnderFences(fields, local(), 2, { c -> held.consumeText(c) }, { held.closeText() })
            },
        )
        for ((expected, attempt) in cases) {
            val held = HeldText()
            val db = db()
            try {
                preparedRow(db)
                assertEquals(expected.name, SealedDispatchLane.Outcome.FenceRefused(expected), attempt(held, db))
                assertTrue("$expected closed the holder", held.closed)
                assertFalse("$expected never submitted", held.consumed)
                assertEquals("$expected aborted the journal row", "aborted", rowState(db))
            } finally { db.close() }
        }
    }

    @Test
    fun theSubmitSeamRunsBehindTheFencesAndConsumesTheTextOnce() {
        val db = db()
        try {
            preparedRow(db)
            val held = HeldText()
            val seen = ArrayList<String>()
            val outcome = lane(db, submit = { _, segments, consumeText ->
                assertEquals(1, segments)
                consumeText { chars -> seen.add(String(chars)) }
                SealedDispatchLane.Submission.SUBMITTED
            }).submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            assertEquals(SealedDispatchLane.Outcome.Submitted(SealedDispatchLane.Submission.SUBMITTED), outcome)
            assertEquals(listOf("synthetic sealed body"), seen)
            assertTrue(held.consumed)
            assertTrue(held.closed) // The lane closes after the seam; zeroizing is idempotent.
            // A submitted attempt keeps its journal row as the permanent replay fence.
            assertEquals("prepared", rowState(db))
        } finally { db.close() }
    }

    @Test
    fun aThrowingSubmitSeamStaysUnknownClosesTheTextAndKeepsTheReplayFence() {
        val db = db()
        try {
            preparedRow(db)
            val held = HeldText()
            val outcome = lane(db, submit = { _, _, _ -> error("radio boundary crashed") })
                .submitUnderFences(fields, local(), 1, { c -> held.consumeText(c) }, { held.closeText() })
            assertEquals(SealedDispatchLane.Outcome.Submitted(SealedDispatchLane.Submission.UNKNOWN), outcome)
            assertTrue(held.closed)
            // A throw may follow a partial radio action: the row is never aborted to a re-entrant state.
            assertEquals("prepared", rowState(db))
            // Crash-after-intent: the retained row refuses the same grant on reconnect.
            assertTrue(lane(db).onGrant(frame()) is SealedDispatchLane.Outcome.Rejected)
            assertEquals(1, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test
    fun aDuplicateGrantNeverReEntersPreparationAfterAnyPriorOutcome() {
        val db = db()
        try {
            val first = lane(db).onGrant(frame())
            // JVM custody fence: entered the journal, aborted, never decrypted.
            assertTrue(first is SealedDispatchLane.Outcome.Rejected || first is SealedDispatchLane.Outcome.Unsupported)
            assertEquals("aborted", rowState(db))
            // The retained row is a permanent replay fence, in either terminal state.
            assertEquals(SealedDispatchLane.Outcome.Rejected, lane(db).onGrant(frame()))
            assertEquals(1, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test
    fun teardownRefusesFurtherGrantsWithoutAnyFetch() {
        val db = db()
        try {
            var fetched = 0
            val lane = lane(db, fetch = { fetched++; f.envelope() })
            lane.teardown()
            assertEquals(SealedDispatchLane.Outcome.Unavailable, lane.onGrant(frame()))
            assertEquals(0, fetched)
            assertEquals(0, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test
    fun theLiveStreamStillNeverConstructsTheLaneOrOffersTheNegotiation() {
        // Dormancy guard: the lane exists only for the post-negotiation contract.
        val source = java.io.File("src/main/java/org/zrotext/gateway/AuthenticatedGatewayService.kt").readText()
        assertFalse(source.contains("SealedDispatchLane"))
        assertFalse(DeviceStatusPublisher.OFFER.contains("sealed-dispatch"))
    }
}
