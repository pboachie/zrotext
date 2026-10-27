// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Actual Room, original shared signatures and synthetic control candidates only. Nothing
 * here establishes a real pairing, authenticated service, Android key/provider or ready pin. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class ProtectionOriginJournalTest {
    private fun <T> SmsJournalDatabase.use(block: (SmsJournalDatabase) -> T): T = try { block(this) } finally { close() }
    private val vector = javaClass.classLoader!!.getResourceAsStream("device-protection-origin-v1.json")!!.use {
        JSONObject(it.bufferedReader().readText())
    }
    private val p get() = vector.getJSONObject("parameters")
    private fun parameter(name: String) = decode(p.getString(name))
    private fun value(name: String) = decode(vector.getString(name))
    private val app get() = RuntimeEnvironment.getApplication()
    private fun memory() = Room.inMemoryDatabaseBuilder(app, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
    private fun original() = ProtectionSetupCommand(setupId = p.getString("setup_id"), openingId = p.getString("opening_id"),
        commandId = p.getString("command_id"), accountId = p.getString("account_id"), deviceId = p.getString("device_id"),
        originSha256 = hex(parameter("origin_digest")), enrolledSigningKeyId = hex(parameter("enrolled_key_id")), requestedMs = 2_990_000)
    private fun opened(db: SmsJournalDatabase): ProtectionOriginPrepared {
        val dao = db.protectionSetup()
        val original = dao.reserveCommand(original()) {}
        val sent = dao.openingWillBeSubmitted(original) {}
        val raw = ProtectionOriginJson.render(header("protection_origin_opened").apply { put("opening", opening()) })
        val opening = (ProtectionOriginWire.decode(raw, original, 7, parameter("enrolled_point")) as ProtectionOriginWire.Opened).opening
        val bytes = opening.bytes()
        val command = dao.retainOpeningCandidate(sent, original.openingId, encode(bytes), hash(bytes)) {}
        val public = listOf(parameter("canary_point"), parameter("hmac_probe"), parameter("journal_aes_probe"), parameter("withdrawal_aes_probe"))
        for ((i, kind) in ProtectionSetupProvider.KINDS.withIndex()) {
            val row = ProtectionSetupProvider(kind, command.commandId, id(20 + i.toLong()), 2_996_000L + i)
            assertTrue(dao.reserveProviderEntry(command, row) {})
            dao.retainProviderEvidence(row, encode(public[i]), hash(public[i])) {}
        }
        return ProtectionOriginPrepared.fromRetained(command, dao.providers(), opening)
    }
    private fun candidate(prepared: ProtectionOriginPrepared) = ProtectionOriginAttempt(id(8), prepared.command.commandId,
        encode(prepared.association.bytes()), encode(prepared.aesProbe()), 2_997_000)
    private fun challenged(db: SmsJournalDatabase, prepared: ProtectionOriginPrepared): ProtectionOriginAttempt {
        val dao = db.protectionOrigins()
        val row = dao.reserve(prepared, candidate(prepared)) {}
        assertTrue(dao.enterRequest(row, 7, originalRequest()) {})
        return dao.retainChallenge(checkNotNull(dao.attempt(row.proofRequestId)), challenge()) {}
    }
    private fun originalRequest() = ProtectionOriginWire.proofOpen(original(), 7, UUID.fromString(id(8)),
        ProtectionOriginProof.Association.decode(value("association")), parameter("journal_aes_probe") + parameter("withdrawal_aes_probe"), null)
    private fun challenge(): ProtectionOriginWire.Challenge {
        val raw = ProtectionOriginJson.render(header("protection_origin_proof_challenge").apply {
            put("proof_request_id", id(8)); put("attempt_id", p.getString("attempt_id")); put("core", vector.getString("core"))
            put("nonce", p.getString("attempt_nonce")); put("closed_predecessor", ProtectionOriginJson.Null)
        })
        return (ProtectionOriginWire.decode(raw, original(), 7, parameter("enrolled_point"),
            ProtectionOriginProof.Association.decode(value("association"))) as ProtectionOriginWire.ProofChallenge).challenge
    }

    @Test fun durableRequestEntryIsOnceOnlyAndStoresNoClockOrReadyProtection(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins()
        val row = dao.reserve(prepared, candidate(prepared)) {}
        assertTrue(dao.enterRequest(row, 7, originalRequest()) {})
        val sent = dao.attempt(row.proofRequestId)!!
        assertFalse(dao.enterRequest(sent, 9, originalRequest()) {})
        assertEquals(7L, dao.attempt(row.proofRequestId)!!.requestEpoch)
        assertNull(dao.installed()); assertNull(dao.protection()); assertNull(db.captures03().counter(original().accountId, original().deviceId))
    }

    @Test fun deviceSignatureUnknownCannotBeInvokedAgainOrSkippedForCanary(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins(); val row = challenged(db, prepared)
        assertThrows(IllegalArgumentException::class.java) { dao.enterSignature(row, true, 3_000_001) {} }
        assertTrue(dao.enterSignature(row, false, 3_000_001) {})
        val burned = dao.attempt(row.proofRequestId)!!
        assertFalse(dao.enterSignature(burned, false, 3_000_002) {})
        assertThrows(IllegalArgumentException::class.java) { dao.enterSignature(burned, true, 3_000_002) {} }
        assertNotNull(dao.attempt(row.proofRequestId)!!.deviceEnteredMs)
        assertNull(dao.attempt(row.proofRequestId)!!.deviceSignatureB64url)
        assertNull(dao.installed())
    }

    @Test fun withdrawalAfterActualReturnRetainsCandidateButPreventsNextSignature(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins(); val row = challenged(db, prepared)
        var foreground = true
        fun current() { check(foreground) }
        assertTrue(dao.enterSignature(row, false, 3_000_001, ::current))
        val burned = dao.attempt(row.proofRequestId)!!
        foreground = false // The old already-authorized operation returned during withdrawal.
        val recorded = dao.retainSignature(burned, false, value("device_signature")) {}
        assertEquals(encode(value("device_signature")), recorded.deviceSignatureB64url)
        assertThrows(IllegalStateException::class.java) { dao.enterSignature(recorded, true, 3_000_002, ::current) }
        assertNull(dao.attempt(row.proofRequestId)!!.canaryEnteredMs); assertNull(dao.installed()); assertNull(dao.protection())
    }

    @Test fun actualDualProofAndAcceptedReceiptStillCannotInstallFromJournalAlone(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins(); var row = challenged(db, prepared)
        assertTrue(dao.enterSignature(row, false, 3_000_001) {})
        row = dao.retainSignature(dao.attempt(row.proofRequestId)!!, false, value("device_signature")) {}
        assertTrue(dao.enterSignature(row, true, 3_000_002) {})
        row = dao.retainSignature(dao.attempt(row.proofRequestId)!!, true, value("canary_signature")) {}
        val verified = ProtectionOriginProof.Bundle.verify(value("bundle"), prepared.association, parameter("enrolled_point"))
        row = dao.retainBundle(row, verified) {}
        assertTrue(dao.enterProofSubmission(row) {})
        row = dao.attempt(row.proofRequestId)!!
        val accepted = ProtectionOriginJson.render(header("protection_origin_accepted").apply {
            put("proof_request_id", id(8)); put("attempt_id", p.getString("attempt_id")); put("receipt", linkedMapOf<String, Any>(
                "association_sha256" to vector.getJSONObject("sha256").getString("association"),
                "core_sha256" to vector.getJSONObject("sha256").getString("core"), "bundle_sha256" to vector.getJSONObject("sha256").getString("bundle"),
                "accepted_ms" to "3000003"))
        })
        val receipt = (ProtectionOriginWire.decode(accepted, original(), 7, parameter("enrolled_point")) as ProtectionOriginWire.Accepted).receipt
        row = dao.retainAccepted(row, receipt, verified) {}
        assertEquals(3_000_003L, row.acceptedMs); assertNull(dao.installed()); assertNull(dao.protection())
        assertFalse(dao.enterProofSubmission(row) {})
        assertThrows(IllegalStateException::class.java) { dao.reserve(prepared, candidate(prepared).copy(proofRequestId = id(90))) {} }
    }

    @Test fun staleWriterAndRamWithdrawalRollBackWithoutErasingOriginalProviderBurns(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins(); var checks = 0
        assertThrows(IllegalStateException::class.java) { dao.reserve(prepared, candidate(prepared)) { check(++checks < 2) } }
        assertTrue(dao.attempts().isEmpty()); assertEquals(4, db.protectionSetup().providers().size)
        val row = dao.reserve(prepared, candidate(prepared)) {}
        assertTrue(dao.enterRequest(row, 7, originalRequest()) {})
        assertThrows(IllegalStateException::class.java) { dao.retainChallenge(row, challenge()) {} }
        assertNull(dao.attempt(row.proofRequestId)!!.coreB64url)
    }

    @Test fun coldSubmittedCommandRetainsItsOriginalEpochAndCannotMintASecondTransportEntry() {
        val name = "po-${UUID.randomUUID().toString().take(8)}.db"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries().build()
        try {
            open().use { db -> val prepared = opened(db); val row = db.protectionOrigins().reserve(prepared, candidate(prepared)) {}
                assertTrue(db.protectionOrigins().enterRequest(row, 7, originalRequest()) {}) }
            open().use { db -> val dao = db.protectionOrigins(); val row = dao.attempt(id(8))!!
                assertEquals(7L, row.requestEpoch); assertFalse(dao.enterRequest(row, 9, originalRequest()) {})
                assertNull(row.coreB64url); assertNull(row.deviceEnteredMs); assertNull(dao.installed()) }
        } finally { app.deleteDatabase(name) }
    }

    @Test fun additiveMigrationRetainsUnknownProviderAndCreatesNoProofOrReadyPin() {
        val name = "pom-${UUID.randomUUID().toString().take(8)}.db"
        fun open() = Room.databaseBuilder(app, SmsJournalDatabase::class.java, name).allowMainThreadQueries()
            .addMigrations(SmsJournalDatabase.MIGRATION_20_21, SmsJournalDatabase.MIGRATION_21_22, SmsJournalDatabase.MIGRATION_22_23, SmsJournalDatabase.MIGRATION_23_24, SmsJournalDatabase.MIGRATION_24_25, SmsJournalDatabase.MIGRATION_25_26).build()
        try {
            open().use { db ->
                val dao = db.protectionSetup(); val sent = dao.openingWillBeSubmitted(dao.reserveCommand(original()) {}) {}
                val raw = "synthetic-candidate".toByteArray()
                val command = dao.retainOpeningCandidate(sent, sent.openingId, encode(raw), hash(raw)) {}
                assertTrue(dao.reserveProviderEntry(command, ProtectionSetupProvider("canary", command.commandId, id(20), 2_996_000)) {})
                db.openHelper.writableDatabase.apply {
                    execSQL("DROP TABLE protection_origin_attempts"); execSQL("DROP TABLE protection_origin_installed")
                    LegacyTypedJournalFixture.removeEmptyFutureTables(this)
                    execSQL("DROP TABLE room_master_table"); version = 20
                }
            }
            open().use { db ->
                assertEquals(26, db.openHelper.readableDatabase.version)
                assertEquals(1, db.protectionSetup().providers().size); assertNull(db.protectionSetup().providers().single().evidenceB64url)
                assertEquals(ProtectionSetupRecovery.State.RECONCILE_PROVIDER_RESULT,
                    ProtectionSetupRecovery.state(db.protectionSetup().command(), db.protectionSetup().providers()))
                assertTrue(db.protectionOrigins().attempts().isEmpty()); assertNull(db.protectionOrigins().installed()); assertNull(db.captures03().protection())
            }
        } finally { app.deleteDatabase(name) }
    }

    @Test fun laterActualClaimAbsenceRetainsOldRequestWithoutInventingServerClosure(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins()
        val first = dao.reserve(prepared, candidate(prepared)) {}
        assertTrue(dao.enterRequest(first, 7, originalRequest()) {})
        val old = dao.attempt(first.proofRequestId)!!
        ProtectionOriginSocketFixture(EvidenceIdentity(original().accountId, original().deviceId, original().originSha256),
            parameter("enrolled_point"), 9).use { socket ->
            val nonce = UUID.randomUUID(); val proofId = UUID.fromString(old.proofRequestId)
            val received = socket.host.request(prepared.command, ProtectionOriginWire.status(prepared.command, 9, nonce, proofId),
                prepared.association, beforeSend = {}) { it is ProtectionOriginWire.Status && it.requestId == nonce && it.proofRequestId == proofId }
            val next = candidate(prepared).copy(proofRequestId = id(90), absentPreviousProofRequestId = old.proofRequestId)
            val witness = received.laterMissing(old)
            assertEquals(next, dao.reserveAfterLaterMissing(prepared, old, next, witness) {})
            val retained = dao.attempt(old.proofRequestId)!!
            assertEquals(old.requestB64url, retained.requestB64url); assertEquals(7L, retained.requestEpoch)
            assertEquals(9L, retained.absentEpoch); assertNotNull(retained.absentStatusB64url)
            assertNull(retained.closedMs); assertEquals(next.proofRequestId, retained.supersededByProofRequestId)
            assertEquals(listOf(next), dao.unresolved()); assertNull(dao.installed()); assertNull(dao.protection())
            assertThrows(IllegalStateException::class.java) { dao.enterRequest(retained, 9, originalRequest()) {} }
        }
    }

    @Test fun atomicPinRefusesQuarantineAndRollsBackBothHalvesOnForegroundWithdrawal(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins(); var row = challenged(db, prepared)
        assertTrue(dao.enterSignature(row, false, 3_000_001) {})
        row = dao.retainSignature(dao.attempt(row.proofRequestId)!!, false, value("device_signature")) {}
        assertTrue(dao.enterSignature(row, true, 3_000_002) {})
        row = dao.retainSignature(dao.attempt(row.proofRequestId)!!, true, value("canary_signature")) {}
        val bundle = ProtectionOriginProof.Bundle.verify(value("bundle"), prepared.association, parameter("enrolled_point"))
        row = dao.retainBundle(row, bundle) {}; assertTrue(dao.enterProofSubmission(row) {}); row = dao.attempt(row.proofRequestId)!!
        val fields = linkedMapOf<String, Any>("association_sha256" to encode(prepared.association.sha256()),
            "core_sha256" to encode(bundle.core.sha256()), "bundle_sha256" to encode(bundle.sha256()), "accepted_ms" to "3000003")
        val receipt = ProtectionOriginWire.retainedReceipt(ProtectionOriginJson.render(fields))
        row = dao.retainAccepted(row, receipt, bundle) {}
        val installed = ProtectionOriginInstallation(commandId = row.commandId, proofRequestId = row.proofRequestId,
            associationB64url = row.associationB64url, aesProbeB64url = row.aesProbeB64url, bundleB64url = encode(bundle.bytes()),
            receiptB64url = encode(ProtectionOriginJson.render(fields)), enrolledPointB64url = encode(parameter("enrolled_point")),
            expectedTag = "a1".repeat(32), installedMs = 3_000_004)
        var calls = 0
        assertThrows(IllegalStateException::class.java) { dao.install(prepared, row, installed) { check(++calls < 2) } }
        assertNull(dao.installed()); assertNull(dao.protection())
        db.captures03().quarantineProtection("continuity_missing", 1, 3_000_005)
        assertThrows(IllegalStateException::class.java) { dao.install(prepared, row, installed) {} }
        assertNull(dao.installed()); assertTrue(dao.protection()!!.blocked); assertEquals(1, dao.protection()!!.debtMask)
    }

    @Test fun delayedSignatureResultSurvivesAuthenticatedClosureWithoutReopeningOldAttempt(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins(); val first = challenged(db, prepared)
        assertTrue(dao.enterSignature(first, false, 3_000_001) {})
        val burned = dao.attempt(first.proofRequestId)!!
        val next = candidate(prepared).copy(proofRequestId = id(90), previousProofRequestId = first.proofRequestId,
            previousAttemptId = first.attemptId, previousCoreSha256 = hash(value("core")))
        val reserved = dao.reserve(prepared, next) {}
        val previous = ProtectionOriginWire.PreviousRequest(UUID.fromString(first.attemptId), ProtectionOriginProof.sha(value("core")), null)
        val request = ProtectionOriginWire.proofOpen(prepared.command, 7, UUID.fromString(next.proofRequestId),
            prepared.association, prepared.aesProbe(), previous)
        assertTrue(dao.enterRequest(reserved, 7, request) {})
        val raw = value("core")
        java.nio.ByteBuffer.wrap(raw, 329, 32).putLong(0).putLong(91).putLong(3_000_010).putLong(3_030_010)
        val core = ProtectionOriginProof.Core.decode(raw)
        val closure = ProtectionOriginWire.Predecessor(UUID.fromString(first.proofRequestId), UUID.fromString(first.attemptId),
            ProtectionOriginProof.sha(value("core")), null, core.issuedMs)
        dao.retainChallenge(dao.attempt(next.proofRequestId)!!,
            ProtectionOriginWire.Challenge(UUID.fromString(next.proofRequestId), core, parameter("attempt_nonce"), closure)) {}
        val retained = dao.retainSignature(burned, false, value("device_signature")) {}
        assertEquals(encode(value("device_signature")), retained.deviceSignatureB64url)
        assertEquals(3_000_010L, retained.closedMs); assertEquals(next.proofRequestId, retained.supersededByProofRequestId)
        assertThrows(IllegalArgumentException::class.java) { dao.enterSignature(retained, true, 3_000_011) {} }
        assertEquals(listOf(next.proofRequestId), dao.unresolved().map { it.proofRequestId })
        assertNull(dao.installed()); assertNull(dao.protection())
    }

    @Test fun withdrawalAfterProofBurnDuringTransportEntrySendsNothingAndPreservesOriginalRequest(): Unit = memory().use { db ->
        val prepared = opened(db); val dao = db.protectionOrigins()
        val row = dao.reserve(prepared, candidate(prepared)) {}
        val frame = originalRequest(); var foreground = true
        assertTrue(dao.enterRequest(row, 7, frame) { check(foreground) })
        ProtectionOriginSocketFixture(EvidenceIdentity(original().accountId, original().deviceId, original().originSha256),
            parameter("enrolled_point"), 7).use { socket ->
            // The original Room commit completed while foreground. Withdrawal happens
            // during subsequent entry work, before the real socket.send boundary.
            socket.actorCheck = { foreground = false }
            assertThrows(IllegalStateException::class.java) {
                socket.host.request(prepared.command, frame, prepared.association, beforeSend = { check(foreground) }) { true }
            }
            assertEquals(0, socket.sentCount)
            val retained = dao.attempt(row.proofRequestId)!!
            assertEquals(7L, retained.requestEpoch); assertEquals(encode(frame), retained.requestB64url)
            assertNull(retained.coreB64url); assertNull(retained.deviceEnteredMs)
            assertEquals(4, db.protectionSetup().providers().size); assertNull(dao.installed())
        }
    }

    @Test fun withdrawalAfterOpeningBurnDuringTransportEntrySendsNothingAndCreatesNoProvider(): Unit = memory().use { db ->
        val setup = db.protectionSetup(); var foreground = true
        val command = setup.openingWillBeSubmitted(setup.reserveCommand(original()) { check(foreground) }) { check(foreground) }
        ProtectionOriginSocketFixture(EvidenceIdentity(original().accountId, original().deviceId, original().originSha256),
            parameter("enrolled_point"), 7).use { socket ->
            socket.actorCheck = { foreground = false }
            assertThrows(IllegalStateException::class.java) {
                socket.host.request(command, ProtectionOriginWire.open(command, 7), beforeSend = { check(foreground) }) { true }
            }
            assertEquals(0, socket.sentCount); assertTrue(setup.command()!!.openingSubmitted)
            assertNull(setup.command()!!.openingCandidateB64url); assertTrue(setup.providers().isEmpty())
            assertNull(db.protectionOrigins().installed()); assertNull(db.protectionOrigins().protection())
        }
    }

    private fun header(type: String) = linkedMapOf<String, Any>("v" to ProtectionOriginJson.Integer(1), "type" to type,
        "connection_epoch" to ProtectionOriginJson.Integer(7), "setup_id" to original().setupId,
        "opening_id" to original().openingId, "command_id" to original().commandId)
    private fun opening() = linkedMapOf<String, Any>("account_id" to original().accountId, "device_id" to original().deviceId,
        "source_pairing_id" to p.getString("source_pairing_id"), "origin_digest" to p.getString("origin_digest"),
        "enrolled_point" to p.getString("enrolled_point"), "enrolled_key_id" to p.getString("enrolled_key_id"),
        "opening_nonce" to p.getString("opening_nonce"), "created_ms" to "2995000", "pairing_created_ms" to "2980000",
        "pairing_claimed_ms" to "2981000", "pairing_approved_ms" to "2982000", "pairing_expires_ms" to "2983000")
    private fun id(n: Long) = UUID(0, n).toString()
    private fun decode(value: String) = java.util.Base64.getUrlDecoder().decode(value)
    private fun encode(value: ByteArray) = Profile03ElectionEncoding.encode(value)
    private fun hex(value: ByteArray) = Draft02OutboundPreparation.hex(value)
    private fun hash(value: ByteArray) = hex(ProtectionOriginProof.sha(value))
}
