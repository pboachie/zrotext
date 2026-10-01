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
import java.util.Base64
import java.util.UUID

/**
 * Roadmap #539 executor: every grant refusal happens before the journal and the
 * Keystore, and only a fully bound grant reaches the existing journal-before-decrypt
 * preparation. The JVM has no Android Keystore, so a bound grant stops at the key
 * custody fence after its journal reservation; that reservation (then aborted) is
 * the observable difference between "refused before anything" and "entered".
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class SealedDispatchExecutorTest {
    private val f = PreparationFixture()
    private val vectors = JSONObject(
        checkNotNull(javaClass.classLoader?.getResourceAsStream("sealed-execution-grant-01.json"))
            .use { it.readBytes() }.toString(Charsets.UTF_8)
    )
    private val readerKey = PreparationFixture.hex(f.json.getString("deviceKeyId"))
    private val session = SealedDispatchExecutor.Session(
        UUID.fromString(PreparationFixture.uuid(f.account)), UUID.fromString(PreparationFixture.uuid(f.device)),
        1L, 1L, UUID.fromString("61616161-6161-4161-8161-616161616161"), "ab".repeat(32),
    )
    private fun local(binding: LocalLineBinding = f.binding(), reader: ByteArray = readerKey) =
        SealedDispatchExecutor.Local(
            binding, reader, 1L, 1L, Draft02OutboundPreparation.hex(f.authority().digest),
            Draft02OutboundPreparation.hash("+12".toByteArray()),
        )

    private fun db() = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
        .allowMainThreadQueries().build().also {
            assertTrue(it.attempts().installVerifiedLineBinding(f.binding(), listOf(ActiveSimCard(3, 7))))
        }

    private fun key() = DevicePayloadKeyStore(RuntimeEnvironment.getApplication(), "zrotext.test.unavailable.${UUID.randomUUID()}")

    private fun frame(patch: Map<String, Any> = emptyMap()) =
        JSONObject(vectors.getJSONObject("frame").toString()).also { copy -> patch.forEach { (k, v) -> copy.put(k, v) } }

    private fun run(
        frame: JSONObject = frame(),
        envelope: ByteArray = f.envelope(),
        session: SealedDispatchExecutor.Session = this.session,
        local: SealedDispatchExecutor.Local = local(),
        db: SmsJournalDatabase,
        now: () -> Long? = { f.now },
    ) = SealedDispatchExecutor.execute(
        SealedExecutionGrantFrame.parse(frame), envelope, session, local, db, key(), now,
    ) { grant -> f.current(grant) }

    private val other = "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e"

    @Test fun boundGrantEntersTheJournalBeforeKeyUseAndAbortsWhenCustodyIsUnavailable() {
        val db = db()
        try {
            val outcome = run(db = db)
            assertFalse(outcome is SealedDispatchExecutor.Refused)
            assertFalse(outcome is SealedDispatchExecutor.Ready)
            assertEquals(1, db.sealedPreparations().count())
            val row = db.sealedPreparations().find(PreparationFixture.uuid(f.account), PreparationFixture.uuid(f.message))
            assertEquals("aborted", row?.state)
            // The journal holds identities and digests only, never envelope bytes or text.
            assertEquals("SealedPreparationRecord(redacted)", row.toString())
            // Journal-before-send is a permanent replay fence: the same grant cannot re-enter.
            assertEquals(SealedDispatchExecutor.Rejected, run(db = db))
            assertEquals(1, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test fun everyBindingRefusalWritesNoJournalRowAndNeverReachesTheKeystore() {
        val wrongSession = { account: UUID?, device: UUID?, epoch: Long, deployment: Long ->
            SealedDispatchExecutor.Session(account ?: session.accountId, device ?: session.deviceId,
                epoch, deployment, session.sessionId, session.originHash)
        }
        val archive = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(PreparationFixture.hex(f.json.getString("archiveKeyId")))
        val cases = listOf<Pair<SealedExecutionGrantValidator.Verdict.Refused, (SmsJournalDatabase) -> SealedDispatchExecutor.Outcome>>(
            SealedExecutionGrantValidator.Verdict.Refused.ACCOUNT_MISMATCH to
                { db -> run(frame(mapOf("account_id" to other)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.ACCOUNT_MISMATCH to
                { db -> run(session = wrongSession(UUID.fromString(other), null, 1, 1), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.DEVICE_MISMATCH to
                { db -> run(frame(mapOf("device_id" to other)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.DEVICE_MISMATCH to
                { db -> run(session = wrongSession(null, UUID.fromString(other), 1, 1), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.LINE_MISMATCH to
                { db -> run(frame(mapOf("line_id" to other)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.LINE_MISMATCH to
                { db -> run(local = local(f.binding().copy(lineId = other)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.BINDING_GENERATION_MISMATCH to
                { db -> run(local = local(f.binding().copy(generation = 2)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.MESSAGE_MISMATCH to
                { db -> run(frame(mapOf("message_id" to other)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.READER_ROLE_MISMATCH to
                { db -> run(frame(mapOf("reader_role" to 2)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.READER_KEY_MISMATCH to
                { db -> run(frame(mapOf("reader_key_id" to archive)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.READER_KEY_MISMATCH to
                { db -> run(local = local(reader = ByteArray(32) { 9 }), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.SESSION_MISMATCH to
                { db -> run(session = wrongSession(null, null, 2, 1), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.DEPLOYMENT_MISMATCH to
                { db -> run(session = wrongSession(null, null, 1, 2), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_DIGEST_MISMATCH to
                { db -> run(envelope = f.envelope("wrongNonce"), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.EXPIRED to
                { db -> run(now = { f.now + 15_000 }, db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.IMPLAUSIBLE_EXPIRY to
                { db -> run(frame(mapOf("expires_at_ms" to f.now + 35_001)), db = db) },
            SealedExecutionGrantValidator.Verdict.Refused.SEGMENT_COUNT_OUT_OF_RANGE to
                { db -> run(frame(mapOf("segment_count" to 7)), db = db) },
        )
        for ((expected, attempt) in cases) {
            val db = db()
            try {
                assertEquals(expected.name, SealedDispatchExecutor.Refused(expected), attempt(db))
                assertEquals(expected.name, 0, db.sealedPreparations().count())
            } finally { db.close() }
        }
    }

    @Test fun malformedEnvelopeIsRefusedBeforeTheGrantOrTrustedTimeIsConsulted() {
        val db = db()
        try {
            var clockReads = 0
            val normal = f.envelope()
            for (bytes in listOf(normal.copyOf(normal.size - 1), ByteArray(0), normal + 0)) {
                assertEquals(
                    SealedDispatchExecutor.Refused(SealedExecutionGrantValidator.Verdict.Refused.ENVELOPE_MALFORMED),
                    run(envelope = bytes, now = { clockReads++; f.now }, db = db),
                )
            }
            assertEquals(0, clockReads)
            assertEquals(0, db.sealedPreparations().count())
            // Without trusted time the grant cannot be judged at all.
            assertEquals(SealedDispatchExecutor.Unavailable, run(now = { null }, db = db))
            assertEquals(0, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test fun preV11LineBindingWithoutCardContinuityCannotEnterPreparation() {
        val db = db()
        try {
            assertEquals(SealedDispatchExecutor.Rejected, run(local = local(f.binding().copy(cardId = null)), db = db))
            assertEquals(0, db.sealedPreparations().count())
        } finally { db.close() }
    }

    @Test fun moreSegmentsThanGrantedDiscardsThePreparedTextBeforeAnySubmit() {
        var discarded = 0
        val ready = SealedDispatchExecutor.Unavailable
        assertEquals(
            SealedDispatchExecutor.Refused(SealedExecutionGrantValidator.Verdict.Refused.SEGMENT_COUNT_EXCEEDS_GRANT),
            SealedDispatchExecutor.settle(3, 2, { discarded++ }) { ready },
        )
        assertEquals(1, discarded)
        assertEquals(ready, SealedDispatchExecutor.settle(2, 2, { discarded++ }) { ready })
        assertEquals(ready, SealedDispatchExecutor.settle(1, 6, { discarded++ }) { ready })
        assertEquals(1, discarded)
    }

    @Test fun candidateContractCarriesTheWireBindingsAndLocalTruthOnly() {
        val fields = SealedExecutionGrantFrame.parse(frame())
        val candidate = SealedDispatchExecutor.candidate(fields, session, local())
        // Identical to the fixture's independently written candidate grant.
        assertEquals(f.grant().identity(), candidate.identity())
        assertEquals("CandidateGrant(redacted)", candidate.toString())
    }

    @Test fun thisClientIgnoresTheUnnegotiatedFrameAndNeverOffersTheNegotiation() {
        // The live handler's only branch for the frame: no parse, no journal, no Keystore, no teardown.
        assertEquals(
            SealedExecutionGrantFrame.Disposition.IGNORED_NOT_NEGOTIATED,
            SealedExecutionGrantFrame.dispositionWithoutNegotiation(),
        )
        assertFalse(DeviceStatusPublisher.OFFER.contains("sealed-dispatch"))
        assertFalse(DeviceStatusPublisher.OFFER.split(",").map { it.trim() }
            .contains(SealedExecutionGrantFrame.NEGOTIATION_PROTOCOL))
        val source = java.io.File("src/main/java/org/zrotext/gateway/AuthenticatedGatewayService.kt").readText()
        val arm = source.substringAfter("SealedExecutionGrantFrame.TYPE ->").substringBefore("else ->")
        assertTrue(arm.contains("dispositionWithoutNegotiation()"))
        for (forbidden in listOf("SealedDispatchExecutor", "prepare(", "parse(", "sealedPreparations", "keyStore", "fail(")) {
            assertFalse(forbidden, arm.contains(forbidden))
        }
    }
}
