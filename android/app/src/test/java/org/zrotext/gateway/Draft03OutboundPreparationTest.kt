// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID

/** JVM has no enrolled Android Keystore recipient. A valid case must reserve and then abort;
 * these controls prove ordering and replay, not native HPKE/plaintext/radio acceptance.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class Draft03OutboundPreparationTest {
    private fun run(f: Profile03ExecutionFixture, grant: SealedDispatch03Frames.Grant = f.grant,
        envelope: ByteArray = f.envelope, now: () -> Long? = { f.now },
        current: () -> Draft03OutboundPreparation.Current? = { f.current() }) =
        Draft03OutboundPreparation.prepare(envelope, grant, f.session, f.line.db,
            DevicePayloadKeyStore(RuntimeEnvironment.getApplication(), "zrotext.synthetic.missing.${UUID.randomUUID()}"), now, current)

    @Test fun authenticGrantEntersTheDurableJournalBeforeMissingCustodyAndNeverReenters() = Profile03ExecutionFixture().use { f ->
        f.install()
        assertEquals(Draft03OutboundPreparation.Rejected, run(f))
        val saved = f.line.db.sealedPreparations().find(f.line.account.toString(), f.message.toString())
        assertEquals("aborted", saved?.state)
        assertEquals(1, f.line.db.sealedPreparations().count())
        assertEquals(Draft03OutboundPreparation.Rejected, run(f))
        assertEquals(saved, f.line.db.sealedPreparations().find(f.line.account.toString(), f.message.toString()))
        assertNull(f.line.db.attempts().getAttempt(f.attempt.toString()))
    }
    @Test fun v2UpdateNeverRearmsOriginalPreparingPreparedOrAbortedMessageHistory() {
        for (state in listOf("preparing", "prepared", "aborted")) Profile03ExecutionFixture().use { f ->
            f.install()
            val old = SealedPreparationRecord(f.line.account.toString(), f.message.toString(), f.attempt.toString(),
                Profile03ExecutionFixture.hex(Profile03ExecutionFixture.unsigned(f.envelope)), "ab".repeat(32))
            val dao = f.line.db.sealedPreparations()
            dao.reserve03(old, f.installed) { check(it == f.binding) }
            if (state == "prepared") dao.finish(old, 1) { check(it == f.binding) }
            if (state == "aborted") dao.abort(old.accountId, old.messageId, old.attemptId)
            val retained = dao.find(old.accountId, old.messageId)
            assertEquals(state, retained?.state)
            assertEquals(Draft03OutboundPreparation.Rejected, run(f))
            assertEquals(retained, dao.find(old.accountId, old.messageId))
            assertEquals(1, dao.count())
            assertNull(f.line.db.attempts().getAttempt(f.attempt.toString()))
        }
    }
    @Test fun aComparedHistoricalElectionCannotReplaceTheSameRoomInstallation() = Profile03ExecutionFixture().use { f ->
        assertEquals(Draft03OutboundPreparation.Rejected, run(f))
        assertEquals(0, f.line.db.sealedPreparations().count())
        f.install(); f.line.db.profile03Elections().retire(f.record.challengeId)
        assertEquals(Draft03OutboundPreparation.Rejected, run(f))
        assertEquals(0, f.line.db.sealedPreparations().count())
    }
    @Test fun changedAccountSessionBindingReaderManifestElectionCeilingOrCiphertextRefusesBeforeJournal() = Profile03ExecutionFixture().use { f ->
        f.install()
        val otherId = UUID(0, 99).toString()
        val otherDigest = Profile03ExecutionFixture.b64(ByteArray(32) { 42 })
        val changes = listOf("account_id" to otherId, "device_id" to otherId, "line_id" to otherId,
            "message_id" to otherId, "connection_epoch" to 8, "deployment_epoch" to 2,
            "binding_generation" to 3, "reader_key_id" to otherDigest, "root_fingerprint" to otherDigest,
            "manifest_digest" to otherDigest, "election_digest" to otherDigest, "manifest_version" to 3,
            "trust_generation" to 2, "segment_count" to 2, "unsigned_sha256" to otherDigest, "envelope_sha256" to otherDigest)
        for ((key, value) in changes) {
            val grant = SealedDispatch03Frames.grant(JSONObject(f.grant.json()).put(key, value).toString())
            assertEquals(key, Draft03OutboundPreparation.Rejected, run(f, grant))
            assertEquals(key, 0, f.line.db.sealedPreparations().count())
        }
        assertEquals(Draft03OutboundPreparation.Rejected, run(f, envelope = f.envelope.copyOf().apply { this[200] = 0 }))
        assertEquals(0, f.line.db.sealedPreparations().count())
    }
    @Test fun missingClockExpiryRegressionAndMissingCurrentPermissionNeverReserve() = Profile03ExecutionFixture().use { f ->
        f.install()
        assertEquals(Draft03OutboundPreparation.Unavailable, run(f, now = { null }))
        assertEquals(Draft03OutboundPreparation.Unavailable, run(f, current = { null }))
        assertEquals(Draft03OutboundPreparation.Rejected, run(f, now = { f.grant.expiresAtMs }))
        var calls = 0
        assertEquals(Draft03OutboundPreparation.Rejected, run(f, now = { if (calls++ < 2) f.now else f.now - 1 }))
        assertEquals(0, f.line.db.sealedPreparations().count())
    }
    @Test fun callbackRetiresTheRealSelectedV2LeaseBeforeAnyPreparation() = Profile03ExecutionFixture().use { f ->
        f.install()
        assertTrue(f.binding.liveContinuity())
        f.line.callback()
        assertFalse(f.binding.liveContinuity())
        assertEquals(Draft03OutboundPreparation.Rejected, run(f))
        assertEquals(0, f.line.db.sealedPreparations().count())
    }
    @Test fun stoppedConversationRamLeaseRefusesBeforeJournalAndRemainsAnIndependentGuard() = Profile03ExecutionFixture().use { f ->
        f.install(); val c = f.current(); c.intervalRamCurrent()
        f.intervalCurrent = false
        assertThrows(Exception::class.java) { c.intervalRamCurrent() }
        assertEquals(Draft03OutboundPreparation.Rejected, run(f))
        assertEquals(0, f.line.db.sealedPreparations().count())
        assertTrue(f.binding.liveContinuity()) // Physical reader availability does not replace content consent.
    }
    @Test fun verifiedReaderDeadlineIsIndependentOfALongerAdapterPermissionLease() {
        Profile03ExecutionFixture(selectedReaderUntilMs = 100_600).use { f ->
            val c = f.current()
            val checked = c.authority.context(c.intent.request(), f.now, c.intent.expiresMs)
            assertEquals(100_600L, checked.authorityExpiresAtMs)
            assertEquals(100_500L, checked.notAfterMs)
            assertTrue(checked.authorityExpiresAtMs < c.selection.permissionExpiresAtMs)
        }
        Profile03ExecutionFixture(selectedReaderUntilMs = 100_499).use { f ->
            f.install()
            assertEquals(Draft03OutboundPreparation.Rejected, run(f))
            assertEquals(0, f.line.db.sealedPreparations().count())
        }
    }
    @Test @Config(sdk = [30]) fun unsupportedApiNeverConsultsAuthorityOrKeysOrJournal() {
        val frame = javaClass.classLoader!!.getResourceAsStream("sealed-profile03-contract-01.json")!!.use {
            JSONObject(it.bufferedReader().readText()).getJSONObject("grant").getJSONObject("frame").toString()
        }
        // The contract fixture is not authority. Only the runtime floor is exercised here.
        val grant = SealedDispatch03Frames.grant(frame)
        val db = androidx.room.Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
            .allowMainThreadQueries().build()
        try {
            val session = SealedDispatchExecutor.Session(grant.accountId, grant.deviceId, grant.connectionEpoch,
                grant.deploymentEpoch, UUID(0, 1), "a".repeat(64))
            assertEquals(Draft03OutboundPreparation.Unsupported, Draft03OutboundPreparation.prepare(ByteArray(557), grant,
                session, db, DevicePayloadKeyStore(RuntimeEnvironment.getApplication(), "zrotext.synthetic.api.floor"),
                { error("No clock call") }, { error("No authority call") }))
            assertEquals(0, db.sealedPreparations().count())
        } finally { db.close() }
    }
}
