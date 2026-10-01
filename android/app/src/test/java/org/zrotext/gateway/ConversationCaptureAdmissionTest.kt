// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ConversationCaptureAdmissionTest {
    private lateinit var db: ConversationCaptureDatabase
    private lateinit var journal: ConversationCaptureDao
    private lateinit var gate: ConversationCaptureAdmission
    private val authority = FixtureAuthority()
    private val protection = FixtureProtection()
    @Volatile private var now = 100L
    @Volatile private var allowed = true
    private var sealHook: (() -> Unit)? = null
    private val scope = ConversationCaptureScope(
        uuid(), uuid(), uuid(), 3, "+12025550199", uuid(), uuid(), uuid(),
        "11".repeat(32), "22".repeat(32), 2, 8, "33".repeat(32), "44".repeat(32))
    private var currentReader = scope.readerKeyId
    private var currentRoot = scope.trustGeneration
    private var currentLineGeneration = scope.bindingGeneration
    private var originatingSessionLive = true

    @Before fun setup() {
        db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), ConversationCaptureDatabase::class.java)
            .allowMainThreadQueries().build()
        journal = db.journal()
        gate = newGate()
    }
    @After fun cleanup() { db.close() }

    private fun newGate() = ConversationCaptureAdmission(journal, authority, object : ConversationJournalProtection {
        override fun seal(value: String, aad: String): InboundVault.Sealed {
            sealHook?.invoke()
            return protection.seal(value, aad)
        }
        override fun open(value: InboundVault.Sealed, aad: String) = protection.open(value, aad)
    }, { now }, { expected ->
        check(allowed && originatingSessionLive && currentReader == expected.readerKeyId &&
            currentRoot == expected.trustGeneration && currentLineGeneration == expected.bindingGeneration) {
            "Current authority was withdrawn"
        }
    })

    private fun prepare(value: ConversationCaptureScope = scope) = gate.prepare(authority.preparation(value), true)
    private fun activate(duration: Long = 1000): Pair<ConversationRecoveryRequest, ByteArray> {
        val request = gate.beginRecovery()
        val proof = authority.active(scope, request.challenge, duration)
        gate.completeRecovery(request.challenge, proof)
        return request to proof
    }
    private fun observe(token: Int = 1, peer: String = scope.peer, line: String = scope.lineId,
                        generation: Long = scope.bindingGeneration) =
        gate.observe(token(token), 1234, peer, line, generation, "fixture conversation text")

    @Test fun phoneDenialDoesNotPrepareOrChangePairing() {
        assertThrows(IllegalArgumentException::class.java) { gate.prepare(authority.preparation(scope), false) }
        assertNull(journal.installation())
        assertTrue(allowed)
        assertFalse(gate.captureEligible())
    }

    @Test fun preparationIsIdempotentAndCannotCapture() {
        prepare()
        val first = journal.installation()!!
        prepare()
        assertArrayEquals(first.protectedScope, journal.installation()!!.protectedScope)
        assertEquals("prepared", journal.installation()!!.state)
        assertFalse(gate.captureEligible())
        assertEquals(ConversationObservation.DISCARDED, observe())
        assertNull(journal.receipt(token(1))!!.protectedCapture)
    }

    @Test fun firstReceiptBeforeActivationCanNeverBeCapturedByReplay() {
        prepare()
        observe()
        activate()
        assertEquals(ConversationObservation.DUPLICATE, observe())
        assertNull(gate.retry(token(1)))
        assertEquals(0, journal.contentCount())
    }

    @Test fun sealedPacketAndCounterCommitBeforeUploadAndExactRetryNeverEncryptsAgain() {
        prepare(); activate(); observe()
        var seals=0
        val first=gate.sealedCapture(token(1)){content,sequence ->
            assertEquals(1L,sequence); assertEquals("fixture conversation text",content.body)
            seals++; "synthetic sealed packet".toByteArray()
        }!!
        val retry=gate.sealedCapture(token(1)){_,_->error("Retry must not reseal")}!!
        assertArrayEquals(first.second,retry.second); assertEquals(1,seals)
        assertNotNull(journal.wireCapture(token(1))!!.protectedEnvelope)
        observe(2)
        gate.sealedCapture(token(2)){_,sequence->assertEquals(2L,sequence);byteArrayOf(1)}
        gate.close(scope.intervalId)
        assertNull(gate.sealedCapture(token(1)){_,_->error("Closed")})
        assertEquals(1L,journal.wireCapture(token(1))!!.sequence)
        assertNull(journal.wireCapture(token(1))!!.protectedEnvelope)
    }

    @Test fun wireEncryptionAuthorityLossLeavesOnlyCounterFenceAndCannotUpload() {
        prepare(); activate(); observe()
        assertThrows(IllegalStateException::class.java) {
            gate.sealedCapture(token(1)){_,_->allowed=false;byteArrayOf(1)}
        }
        assertFalse(gate.captureEligible())
        assertEquals(1L,journal.wireCapture(token(1))!!.sequence)
        assertNull(journal.wireCapture(token(1))!!.protectedEnvelope)
    }

    @Test fun retentionPurgesWireAndBodyButKeepsSequenceAndReceiptIdentity() {
        prepare(); activate(); observe()
        gate.sealedCapture(token(1)){_,_->byteArrayOf(1)}
        assertEquals(1,journal.purgeContentBefore(1235))
        assertNull(journal.receipt(token(1))!!.protectedCapture)
        assertNull(journal.wireCapture(token(1))!!.protectedEnvelope)
        assertEquals(1L,journal.wireCapture(token(1))!!.sequence)
        assertNull(gate.retry(token(1)))
    }

    @Test fun explicitVersionOneMigrationPreservesReceiptAndClosedIntervalFences() {
        val context=RuntimeEnvironment.getApplication()
        val name="conversation-migration-test.db"
        context.deleteDatabase(name)
        val file=context.getDatabasePath(name); file.parentFile!!.mkdirs()
        context.openOrCreateDatabase(name,android.content.Context.MODE_PRIVATE,null).use { legacy ->
            legacy.execSQL("CREATE TABLE conversation_closed_intervals (intervalId TEXT NOT NULL PRIMARY KEY)")
            legacy.execSQL("CREATE TABLE conversation_installation (slot INTEGER NOT NULL PRIMARY KEY, intervalId TEXT NOT NULL, receiptId TEXT NOT NULL, transcriptDigest TEXT NOT NULL, protectedScope BLOB NOT NULL, nonce BLOB NOT NULL, state TEXT NOT NULL)")
            legacy.execSQL("CREATE TABLE conversation_receipts (token TEXT NOT NULL PRIMARY KEY, firstObservedAtMs INTEGER NOT NULL, captureId TEXT, intervalId TEXT, protectedCapture BLOB, nonce BLOB)")
            legacy.execSQL("INSERT INTO conversation_closed_intervals VALUES (?)",arrayOf(scope.intervalId))
            legacy.execSQL("INSERT INTO conversation_receipts(token,firstObservedAtMs) VALUES (?,?)",arrayOf<Any>(token(1),1234))
            legacy.version=1
        }
        val migrated=Room.databaseBuilder(context,ConversationCaptureDatabase::class.java,name)
            .addMigrations(ConversationCaptureDatabase.MIGRATION_1_2).allowMainThreadQueries().build()
        try {
            assertEquals(1,migrated.journal().isClosed(scope.intervalId))
            assertEquals(1234L,migrated.journal().receipt(token(1))!!.firstObservedAtMs)
            assertNull(migrated.journal().wireCapture(token(1)))
        } finally { migrated.close(); context.deleteDatabase(name) }
    }

    @Test fun receiptDuringActivationMonitorWaitCannotInheritPromotedLease() {
        prepare()
        val finished=java.util.concurrent.CountDownLatch(1)
        val boundary=java.util.concurrent.atomic.AtomicReference<ConversationCaptureAdmission.ReceiptBoundary>()
        val failure=java.util.concurrent.atomic.AtomicReference<Throwable>()
        val receiver=Thread { try { boundary.set(gate.firstReceiptBoundary { 1234L }) }
            catch(error:Throwable){failure.set(error)} finally {finished.countDown()} }
        try {
            synchronized(gate) {
                receiver.start()
                assertTrue("Receipt must snapshot before waiting for activation's monitor",
                    finished.await(2,java.util.concurrent.TimeUnit.SECONDS))
                activate()
            }
            failure.get()?.let { throw AssertionError(it) }
            assertEquals(ConversationObservation.DISCARDED,gate.observeAtBoundary(checkNotNull(boundary.get()),
                token(1),scope.peer,scope.lineId,scope.bindingGeneration,"synthetic"))
            assertNull(journal.receipt(token(1))!!.protectedCapture)
            assertEquals(ConversationObservation.CAPTURED,observe(2))
        } finally {receiver.join(3000)}
    }

    @Test fun forgedServerResponseCannotInstallOrOpenCapture() {
        prepare()
        val request = gate.beginRecovery()
        val forged = authority.active(scope, request.challenge, 1000)
        forged[forged.lastIndex] = (forged.last().toInt() xor 1).toByte()
        assertThrows(RuntimeException::class.java) { gate.completeRecovery(request.challenge, forged) }
        assertFalse(gate.captureEligible())
        assertEquals("prepared", journal.installation()!!.state)
    }

    @Test fun activeProofBindsExactScopeAndRecoveryChallenge() {
        prepare()
        val first = gate.beginRecovery()
        val next = gate.beginRecovery()
        assertThrows(IllegalStateException::class.java) {
            gate.completeRecovery(next.challenge, authority.active(scope, first.challenge, 1000))
        }
        val third = gate.beginRecovery()
        assertThrows(IllegalStateException::class.java) {
            gate.completeRecovery(third.challenge, authority.active(scope.copy(peer = "+12025550198"), third.challenge, 1000))
        }
        assertFalse(gate.captureEligible())
    }

    @Test fun responseLifetimeStartsAtRequestAndSlowResponsesCannotActivate() {
        prepare()
        val request = gate.beginRecovery()
        now += 1000
        assertThrows(IllegalStateException::class.java) {
            gate.completeRecovery(request.challenge, authority.active(scope, request.challenge, 1000))
        }
        assertEquals("prepared", journal.installation()!!.state)
        assertFalse(gate.captureEligible())
    }

    @Test fun overlongLeaseCannotActivate() {
        prepare()
        val request = gate.beginRecovery()
        assertThrows(IllegalArgumentException::class.java) {
            gate.completeRecovery(request.challenge, authority.active(scope, request.challenge, 60_001))
        }
        assertFalse(gate.captureEligible())
    }

    @Test fun duplicateActiveResponseIsIdempotentWithoutExtendingLease() {
        prepare()
        val (request, proof) = activate()
        now += 500
        gate.completeRecovery(request.challenge, proof)
        assertTrue(gate.captureEligible())
        now += 500
        assertFalse(gate.captureEligible())
        assertThrows(IllegalStateException::class.java) { gate.completeRecovery(request.challenge, proof) }
        assertFalse(gate.captureEligible())
    }

    @Test fun capturePersistsEncryptedBodyWithOriginalIntervalAndReceiptTime() {
        prepare()
        activate()
        assertEquals(ConversationObservation.CAPTURED, observe())
        val row = journal.receipt(token(1))!!
        assertFalse(row.protectedCapture!!.toString(Charsets.UTF_8).contains("fixture conversation text"))
        val captured = gate.retry(token(1))!!
        assertEquals(scope, captured.scope)
        assertEquals("fixture conversation text", captured.body)
        assertEquals(1234, captured.firstObservedAtMs)
        assertEquals(100, captured.firstObservedElapsedMs)
        assertEquals(row.captureId, captured.captureId)
        assertFalse(captured.toString().contains(scope.peer))
        assertFalse(journal.installation().toString().contains(scope.peer))
        assertFalse(scope.toString().contains(scope.peer))
    }

    @Test fun anotherPeerLineOrGenerationCannotCapture() {
        prepare()
        activate()
        assertEquals(ConversationObservation.DISCARDED, observe(1, peer = "+12025550198"))
        assertEquals(ConversationObservation.DISCARDED, observe(2, line = uuid()))
        assertEquals(ConversationObservation.DISCARDED, observe(3, generation = 4))
        assertEquals(0, journal.contentCount())
    }

    @Test fun benignRecoveryPreservesOriginalCaptureAndCiphertext() {
        prepare()
        activate()
        observe()
        val before = journal.receipt(token(1))!!
        now += 200
        activate()
        assertArrayEquals(before.protectedCapture, journal.receipt(token(1))!!.protectedCapture)
        assertEquals(100, gate.retry(token(1))!!.firstObservedElapsedMs)
        assertEquals(scope.activationVersion, gate.retry(token(1))!!.scope.activationVersion)
    }

    @Test fun restartCannotCaptureOrRetryUntilFreshAuthenticatedRecovery() {
        prepare()
        activate()
        observe()
        gate = newGate()
        assertFalse(gate.captureEligible())
        assertNull(gate.retry(token(1)))
        assertEquals(ConversationObservation.DISCARDED, observe(2))
        activate()
        assertNotNull(gate.retry(token(1)))
        assertEquals(ConversationObservation.DUPLICATE, observe(2))
    }

    @Test fun permissionSessionRootOrReaderRevocationClosesAdmissionAndRetry() {
        prepare()
        activate()
        observe()
        allowed = false
        assertFalse(gate.captureEligible())
        assertNull(gate.retry(token(1)))
        assertEquals(ConversationObservation.DISCARDED, observe(2))
        allowed = true
        assertFalse(gate.captureEligible()) // Restoring a capability requires another verified response.
    }

    @Test fun monotonicClockRegressionClosesAdmission() {
        prepare()
        activate()
        now--
        assertFalse(gate.captureEligible())
        assertEquals(ConversationObservation.DISCARDED, observe())
        now = 101
        assertFalse(gate.captureEligible())
    }

    @Test fun expiryWhileEncryptingRollsBackBodyAndPersistsDiscardFence() {
        prepare()
        activate()
        sealHook = { now += 1000 }
        assertEquals(ConversationObservation.DISCARDED, observe())
        assertEquals(0, journal.contentCount())
        assertNull(journal.receipt(token(1))!!.protectedCapture)
        sealHook = null
        activate()
        assertEquals(ConversationObservation.DUPLICATE, observe())
    }

    @Test fun currentFenceFailureWhileEncryptingRollsBackBody() {
        prepare()
        activate()
        sealHook = { allowed = false }
        assertEquals(ConversationObservation.DISCARDED, observe())
        assertEquals(0, journal.contentCount())
        assertFalse(gate.captureEligible())
    }

    @Test fun closeWaitsForAtomicCaptureThenAcknowledgesClosedAdmission() {
        prepare()
        activate()
        val encrypting = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val closing = java.util.concurrent.CountDownLatch(1)
        val pool = java.util.concurrent.Executors.newFixedThreadPool(2)
        sealHook = { encrypting.countDown(); check(release.await(5, java.util.concurrent.TimeUnit.SECONDS)) }
        try {
            val capture = pool.submit<ConversationObservation> { observe() }
            assertTrue(encrypting.await(5, java.util.concurrent.TimeUnit.SECONDS))
            val close = pool.submit { closing.countDown(); gate.close(scope.intervalId) }
            assertTrue(closing.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertFalse(close.isDone)
            release.countDown()
            assertEquals(ConversationObservation.CAPTURED, capture.get(5, java.util.concurrent.TimeUnit.SECONDS))
            close.get(5, java.util.concurrent.TimeUnit.SECONDS)
            assertFalse(gate.captureEligible())
            assertNull(gate.retry(token(1)))
            assertEquals(ConversationObservation.DISCARDED, observe(2))
        } finally { release.countDown(); pool.shutdownNow() }
    }

    @Test fun processDeathDuringEncryptionLeavesCommittedReceiptFence() {
        prepare()
        activate()
        sealHook = { throw AssertionError("simulated process death") }
        assertThrows(AssertionError::class.java) { observe() }
        assertNull(journal.receipt(token(1))!!.protectedCapture)
        sealHook = null
        gate = newGate()
        activate()
        assertEquals(ConversationObservation.DUPLICATE, observe())
        assertEquals(0, journal.contentCount())
    }

    @Test fun oversizedFirstReceiptIsFencedBeforeAnyPossibleRedelivery() {
        prepare()
        activate()
        assertEquals(ConversationObservation.DISCARDED,
            gate.observe(token(1), 1234, scope.peer, scope.lineId, 3, "x".repeat(8193)))
        assertEquals(ConversationObservation.DUPLICATE, observe())
        assertNull(gate.retry(token(1)))
    }

    @Test fun readerRootLineRotationAndOriginatingSessionExpiryRejectOldLease() {
        prepare()
        activate()
        currentReader = "66".repeat(32)
        assertFalse(gate.captureEligible())
        assertThrows(IllegalStateException::class.java) { activate() }
        currentReader = scope.readerKeyId
        activate()
        currentRoot++
        assertFalse(gate.captureEligible())
        currentRoot = scope.trustGeneration
        activate()
        currentLineGeneration++
        assertFalse(gate.captureEligible())
        currentLineGeneration = scope.bindingGeneration
        activate()
        originatingSessionLive = false
        assertFalse(gate.captureEligible())
        assertThrows(IllegalStateException::class.java) { activate() }
    }

    @Test fun lastClosureSlotCanCloseButCannotAdmitAnotherInterval() {
        val sql = db.openHelper.writableDatabase
        repeat(ConversationCaptureDao.RECEIPT_CAPACITY - 1) {
            sql.execSQL("INSERT INTO conversation_closed_intervals(intervalId) VALUES (?)", arrayOf(uuid()))
        }
        prepare()
        activate()
        gate.close(scope.intervalId)
        assertEquals("closed", journal.installation()!!.state)
        gate = newGate()
        assertThrows(IllegalStateException::class.java) { gate.beginRecovery() }
        assertThrows(IllegalStateException::class.java) {
            prepare(scope.copy(intervalId = uuid(), receiptId = uuid()))
        }
        assertFalse(gate.captureEligible())
    }

    @Test fun durableDatabaseReopenRequiresRecoveryAndRetainsReceiptFences() {
        val context = RuntimeEnvironment.getApplication()
        val name = "conversation-reopen-test.db"
        context.deleteDatabase(name)
        db.close()
        fun reopen() {
            db = Room.databaseBuilder(context, ConversationCaptureDatabase::class.java, name)
                .allowMainThreadQueries().build()
            journal = db.journal()
            gate = newGate()
        }
        try {
            reopen()
            prepare()
            activate()
            observe()
            db.close()
            reopen()
            assertEquals("installed", journal.installation()!!.state)
            assertFalse(gate.captureEligible())
            assertEquals(ConversationObservation.DUPLICATE, observe())
            activate()
            assertNotNull(gate.retry(token(1)))
        } finally { db.close(); context.deleteDatabase(name) }
    }

    @Test fun closeAcknowledgementFencesAdmissionAndCannotReviveSameInterval() {
        prepare()
        activate()
        observe()
        gate.close(scope.intervalId)
        assertFalse(gate.captureEligible())
        assertNull(gate.retry(token(1)))
        assertEquals("closed", journal.installation()!!.state)
        assertThrows(IllegalStateException::class.java) { prepare() }
        gate.close(scope.intervalId) // Idempotent local withdrawal.
        assertEquals(ConversationObservation.DISCARDED, observe(2))
    }

    @Test fun cancellationDuringPendingRecoveryCannotInstall() {
        prepare()
        val request = gate.beginRecovery()
        gate.close(scope.intervalId)
        assertThrows(IllegalStateException::class.java) {
            gate.completeRecovery(request.challenge, authority.active(scope, request.challenge, 1000))
        }
        assertEquals("closed", journal.installation()!!.state)
    }

    @Test fun freshIntervalCannotRelabelOldQueuedBody() {
        prepare()
        activate()
        observe()
        gate.close(scope.intervalId)
        val replacement = scope.copy(intervalId = uuid(), receiptId = uuid(), transcriptDigest = "55".repeat(32))
        prepare(replacement)
        val request = gate.beginRecovery()
        gate.completeRecovery(request.challenge, authority.active(replacement, request.challenge, 1000))
        assertNull(gate.retry(token(1)))
        assertEquals(scope.intervalId, journal.receipt(token(1))!!.intervalId)
        assertEquals(ConversationObservation.DUPLICATE, observe())
    }

    @Test fun purgeDeletesCiphertextAndRetainsPermanentReplayFence() {
        prepare()
        activate()
        observe()
        assertEquals(1, journal.purgeContentBefore(1235))
        assertNull(journal.receipt(token(1))!!.protectedCapture)
        assertNull(gate.retry(token(1)))
        assertEquals(ConversationObservation.DUPLICATE, observe())
        assertEquals(1, journal.receiptCount())
    }

    @Test fun queueCapacityDiscardsNewBodyWithoutEvictingOrReplayingLater() {
        prepare()
        activate()
        repeat(ConversationCaptureDao.CONTENT_CAPACITY) { assertEquals(ConversationObservation.CAPTURED, observe(it + 1)) }
        assertEquals(ConversationObservation.DISCARDED, observe(129))
        journal.purgeContentBefore(1235)
        assertEquals(ConversationObservation.DUPLICATE, observe(129))
        assertEquals(ConversationObservation.CAPTURED, observe(130))
    }

    @Test fun receiptCapacityFailsClosedWithoutEvictingReplayIdentity() {
        repeat(ConversationCaptureDao.RECEIPT_CAPACITY) { observe(it + 1) }
        prepare()
        activate()
        assertThrows(IllegalStateException::class.java) { observe(1025) }
        assertFalse(gate.captureEligible())
        assertEquals(ConversationCaptureDao.RECEIPT_CAPACITY, journal.receiptCount())
        assertEquals(ConversationObservation.DUPLICATE, observe(1))
    }

    @Test fun scopeProtectionBindsReceiptAndIntervalAndRejectsTampering() {
        prepare()
        db.openHelper.writableDatabase.execSQL("UPDATE conversation_installation SET receiptId = ?", arrayOf(uuid()))
        assertThrows(javax.crypto.AEADBadTagException::class.java) { gate.beginRecovery() }
        assertFalse(gate.captureEligible())
    }

    @Test fun failedProtectedPreparationClosesExistingActiveAdmission() {
        prepare()
        activate()
        db.openHelper.writableDatabase.execSQL("UPDATE conversation_installation SET protectedScope = ?",
            arrayOf(byteArrayOf(1)))
        assertThrows(java.security.GeneralSecurityException::class.java) { prepare() }
        assertFalse(gate.captureEligible())
        assertEquals(ConversationObservation.DISCARDED, observe())
    }

    @Test fun captureProtectionRejectsCiphertextMovedBetweenReceipts() {
        prepare()
        activate()
        observe(1)
        observe(2)
        val first = journal.receipt(token(1))!!
        db.openHelper.writableDatabase.execSQL(
            "UPDATE conversation_receipts SET protectedCapture = ?, nonce = ? WHERE token = ?",
            arrayOf(first.protectedCapture, first.nonce, token(2)))
        assertThrows(javax.crypto.AEADBadTagException::class.java) { gate.retry(token(2)) }
        assertFalse(gate.captureEligible())
    }

    @Test fun protectedScopeCodecRejectsTrailingOrInvalidFields() {
        assertEquals(scope, ConversationCaptureScope.decode(scope.encode()))
        val bytes = java.util.Base64.getDecoder().decode(scope.encode()) + byteArrayOf(0)
        assertThrows(IllegalArgumentException::class.java) {
            ConversationCaptureScope.decode(java.util.Base64.getEncoder().encodeToString(bytes))
        }
        assertThrows(IllegalArgumentException::class.java) { scope.copy(bindingGeneration = 0) }
        assertThrows(IllegalArgumentException::class.java) { scope.copy(readerKeyId = "bad") }
    }

    /** Signed simulator adapter only. This local test format is deliberately not a network ACK. */
    private class FixtureAuthority : ConversationActivationVerifier {
        private val key = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        fun preparation(scope: ConversationCaptureScope) = sign("fixture-prepare|${scope.encode()}")
        fun active(scope: ConversationCaptureScope, challenge: String, duration: Long) =
            sign("fixture-active|${scope.encode()}|$challenge|$duration")
        override fun verifiedPreparation(evidence: ByteArray): ConversationCaptureScope {
            val payload = verify(evidence).split('|')
            check(payload.size == 2 && payload[0] == "fixture-prepare")
            return ConversationCaptureScope.decode(payload[1])
        }
        override fun verifiedActiveLease(scope: ConversationCaptureScope, challenge: String, evidence: ByteArray): Long {
            val payload = verify(evidence).split('|')
            check(payload.size == 4 && payload[0] == "fixture-active" && payload[1] == scope.encode() && payload[2] == challenge)
            return payload[3].toLong()
        }
        private fun sign(payload: String): ByteArray {
            val content = payload.toByteArray(Charsets.UTF_8)
            val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(key.private); update(content) }.sign()
            return ByteBuffer.allocate(4 + sig.size + content.size).putInt(sig.size).put(sig).put(content).array()
        }
        private fun verify(evidence: ByteArray): String {
            val bytes = ByteBuffer.wrap(evidence)
            val sig = ByteArray(bytes.int).also(bytes::get)
            val content = ByteArray(bytes.remaining()).also(bytes::get)
            check(Signature.getInstance("SHA256withECDSA").apply { initVerify(key.public); update(content) }.verify(sig))
            return content.toString(Charsets.UTF_8)
        }
    }

    private class FixtureProtection : ConversationJournalProtection {
        private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        override fun seal(value: String, aad: String): InboundVault.Sealed {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(aad.toByteArray(Charsets.US_ASCII))
            return InboundVault.Sealed(cipher.doFinal(value.toByteArray(Charsets.UTF_8)), cipher.iv)
        }
        override fun open(value: InboundVault.Sealed, aad: String): String {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, value.nonce))
            cipher.updateAAD(aad.toByteArray(Charsets.US_ASCII))
            return cipher.doFinal(value.ciphertext).toString(Charsets.UTF_8)
        }
    }

    companion object {
        private fun uuid() = UUID.randomUUID().toString()
        private fun token(value: Int) = value.toString(16).padStart(64, '0')
    }
}
