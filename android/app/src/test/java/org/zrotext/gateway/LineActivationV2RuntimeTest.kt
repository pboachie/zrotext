// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.Executor
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/** Proper synthetic P-256 keys and source callbacks; no Android key creation or carrier claim. */
internal class LineActivationV2RuntimeFixture(selectedEmbedded: Boolean = false) : AutoCloseable {
    val account = UUID.fromString(testEvidenceIdentity.accountId)
    val device = UUID.fromString(testEvidenceIdentity.deviceId)
    val line = UUID.fromString("33333333-3333-4333-8333-333333333333")
    val challengeId = UUID.fromString("44444444-4444-4444-8444-444444444444")
    val epoch = 7L
    var now = 100_000L
    var active = true
    var selected = if (selectedEmbedded) 8 else 7
    var permission = true
    var rows = listOf(ProfileSubscriptionObservation(7, 20, false, 0, 0),
        ProfileSubscriptionObservation(8, 30, true, 0, 1))
    private var changed: () -> Unit = {}
    var closeHook: () -> Unit = {}
    val owner = LineActivationV2SelectedLineOwner({ 34 }, { selected }, object : ProfileObservationSource {
        override fun permissionGranted() = permission
        override fun readComplete() = rows
        override fun register(callback: () -> Unit): AutoCloseable {
            changed = callback; callback(); return AutoCloseable { closeHook() }
        }
    }, { action -> action(); true }, Executor { it.run() })
    val db = Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), SmsJournalDatabase::class.java)
        .allowMainThreadQueries().build()
    private val pair = KeyPairGenerator.getInstance("EC").run { initialize(ECGenParameterSpec("secp256r1")); generateKeyPair() }
    val point = DevicePayloadKeyStore.encodePoint(pair.public as ECPublicKey)
    var signCalls = 0
    var signHook: () -> Unit = {}
    var pointHook: () -> Unit = {}
    private val signer = object : LineActivationV2RuntimeSigner {
        override fun point(purpose: LineActivationV2Purpose): ByteArray { pointHook(); return point.copyOf() }
        override fun sign(purpose: LineActivationV2Purpose, fields: LineActivationV2StatementFields,
            lease: SelectedLineLeaseV2, fingerprint: ByteArray, expiresAtMs: Long, now: () -> Long,
            current: () -> Boolean): SignedLineActivationV2 {
            signCalls++; signHook()
            check(current())
            val bytes = LineActivationV2Statements.device(purpose, fields, lease.observation())
            val signature = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(bytes); sign() }
            return SignedLineActivationV2(bytes, signature, point)
        }
    }
    val runtime = LineActivationV2Runtime(account, device, epoch, testEvidenceIdentity.originHash, owner, signer, db, { active }, { now })
    fun newRuntime(connectionEpoch: Long) = LineActivationV2Runtime(account, device, connectionEpoch,
        testEvidenceIdentity.originHash, owner, signer, db, { active }, { now })
    private var acceptance: AutoCloseable? = null
    init { owner.selectCurrent(); LineActivationV2SelectedLineMount.attach(owner) }
    fun callback() = changed()
    fun cards() = rows.map { ActiveSimCard(it.subscriptionId, it.cardId, it.embedded, it.portIndex, it.logicalSlotIndex) }
    fun challenge(purpose: LineActivationV2Purpose = LineActivationV2Purpose.SMS,
        id: UUID = challengeId, generation: Long = 1): LineActivationV2IncomingFrames.Challenge {
        val frame = JSONObject().put("v", 2).put("type", if (purpose == LineActivationV2Purpose.SMS) "sms_line_challenge_v2" else "sealed_line_challenge_v2")
            .put("challenge_id", id.toString()).put("account_id", account.toString()).put("device_id", device.toString())
            .put("line_id", line.toString()).put("generation", generation.toString()).put("expires_at_ms", 200_000L)
            .put("nonce", LineActivationV2JournalEncoding.encode(ByteArray(32) { 9 }))
        if (purpose == LineActivationV2Purpose.SEALED) frame.put("connection_epoch", epoch.toString())
        return LineActivationV2IncomingFrames.parse(frame.toString().toByteArray(), purpose) as LineActivationV2IncomingFrames.Challenge
    }
    fun acceptSealed() {
        val lease = checkNotNull(owner.capture())
        acceptance = checkNotNull(SealedLineActivationMount.enableV2Owned(SealedLineAcceptance(account, device, line,
            1, selected, SealedLineActivationTranscript.digest(point)), lease) { active })
    }
    fun proof(purpose: LineActivationV2Purpose = LineActivationV2Purpose.SMS): LineActivationV2Record {
        val output = checkNotNull(runtime.accept(challenge(purpose)))
        val declaration = LineActivationV2Frames.parseProof(JSONObject(output), purpose)
        assertEquals(epoch, declaration.connectionEpoch)
        return checkNotNull(db.lineActivationsV2().find(purpose.journalName(), challengeId.toString()))
    }
    fun receipt(record: LineActivationV2Record): LineActivationV2IncomingFrames.Receipt {
        fun bytes(text: String?) = checkNotNull(text).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return if (record.purpose == "sms") LineActivationV2IncomingFrames.SmsActivated(challengeId, account, line, device,
            record.generation, bytes(record.statementSha256), bytes(record.signatureSha256))
        else LineActivationV2IncomingFrames.SealedActivated(epoch, challengeId, account, line, device,
            record.generation, bytes(record.statementSha256), bytes(record.signatureSha256))
    }
    fun installSealed(): LocalLineBinding {
        acceptSealed()
        val proof = proof(LineActivationV2Purpose.SEALED)
        assertNotNull(runtime.accept(receipt(proof)))
        runtime.accept(LineActivationV2IncomingFrames.SealedInstallAck(epoch, challengeId, true))
        return checkNotNull(db.attempts().currentLineBinding()).also { assertTrue(it.liveContinuity()) }
    }
    fun radioContext(binding: LocalLineBinding): JournaledRadioContext {
        val liveSession = SealedDispatchExecutor.Session(account, device, epoch, 1, UUID(0, 9), testEvidenceIdentity.originHash)
        val lineLocal = SealedDispatchExecutor.Local(binding, ByteArray(32) { 3 }, 1, 1, "a".repeat(64), "b".repeat(64))
        val fields = SealedExecutionGrantValidator.Fields(account, device, line, UUID(0, 5), UUID(0, 6),
            epoch, ByteArray(32) { 4 }, now + 10_000, 1, 1, ByteArray(32) { 3 }, 1, binding.generation, 1, ByteArray(32) { 5 })
        return object : JournaledRadioContext {
            override val message = fields.messageId.toString()
            override val attempt = fields.attemptId.toString()
            override val accountId = account.toString()
            override val deviceId = device.toString()
            override val peer = "+12025550123"
            override val originalDeadlineMs = now + 20_000
            override val deadlineMs = fields.expiresAtMs
            override val grant = fields
            override val session = liveSession
            override val local = lineLocal
        }
    }
    override fun close() {
        active = false; runtime.close(); acceptance?.close(); SealedLineActivationMount.disable()
        LineActivationV2SelectedLineMount.detach(owner); owner.close(); db.close()
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class LineActivationV2RuntimeTest {
    @Test fun smsProofAndProofAckCannotInstallBeforeExactFinalReceipt() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        f.runtime.accept(LineActivationV2IncomingFrames.SmsProofAck(f.challengeId, true))
        assertNull(f.db.attempts().currentLineBinding())
        assertEquals("proof_recorded", f.db.lineActivationsV2().find("sms", f.challengeId.toString())?.state)
        val correct = f.receipt(proof) as LineActivationV2IncomingFrames.SmsActivated
        f.runtime.accept(LineActivationV2IncomingFrames.SmsActivated(f.challengeId, f.account, f.line, f.device, 1,
            ByteArray(32), correct.deviceSignatureSha256()))
        assertNull(f.db.attempts().currentLineBinding())
        f.runtime.accept(correct)
        val binding = checkNotNull(f.db.attempts().currentLineBinding())
        assertEquals(2, binding.protocolVersion); assertNull(binding.cardId)
        assertTrue(binding.liveContinuity()); assertTrue(SimCardContinuity.matches(binding.activatedSim(), f.cards()))
    }
    @Test fun callbackDuringKeyOperationLeavesOnlyReservationAndCannotReproveWithNewLease() = LineActivationV2RuntimeFixture().use { f ->
        f.signHook = { f.callback() }
        assertNull(f.runtime.accept(f.challenge()))
        assertEquals(1, f.signCalls)
        val record = checkNotNull(f.db.lineActivationsV2().find("sms", f.challengeId.toString()))
        assertEquals("reserved", record.state); assertNull(record.signatureDerB64url)
        f.signHook = {}
        assertNull(f.runtime.accept(f.challenge()))
        assertEquals(1, f.signCalls); assertNull(f.db.attempts().currentLineBinding())
    }
    @Test fun sameCountPeerReplacementRetiresProofAndInstalledPhysicalAuthority() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        f.runtime.accept(f.receipt(proof))
        val binding = checkNotNull(f.db.attempts().currentLineBinding())
        val capability = checkNotNull(binding.installedSelectionV2())
        f.rows = listOf(f.rows.first(), ProfileSubscriptionObservation(9, 40, true, 1, 1)); f.callback()
        assertFalse(capability.isCurrent()); assertFalse(binding.liveContinuity())
        assertFalse(SimCardContinuity.matches(binding.activatedSim(), f.cards()))
        f.runtime.accept(f.receipt(proof))
        assertFalse(binding.liveContinuity()); assertEquals(1, f.signCalls)
    }
    @Test fun sealedRequiresExplicitAcceptanceAndActualInstallAck() = LineActivationV2RuntimeFixture(true).use { f ->
        assertNull(f.runtime.accept(f.challenge(LineActivationV2Purpose.SEALED)))
        assertEquals(0, f.signCalls)
        f.acceptSealed()
        val proof = f.proof(LineActivationV2Purpose.SEALED)
        val output = checkNotNull(f.runtime.accept(f.receipt(proof)))
        assertTrue(LineActivationV2IncomingFrames.parse(output.toByteArray(), LineActivationV2Purpose.SEALED) is LineActivationV2IncomingFrames.SealedInstalled)
        val binding = checkNotNull(f.db.attempts().currentLineBinding())
        assertFalse(binding.liveContinuity())
        f.runtime.accept(LineActivationV2IncomingFrames.SealedInstallAck(f.epoch + 1, f.challengeId, true))
        assertFalse(binding.liveContinuity())
        f.runtime.accept(LineActivationV2IncomingFrames.SealedInstallAck(f.epoch, f.challengeId, true))
        assertTrue(binding.liveContinuity()); assertTrue(binding.activatedSim()?.completeSelection?.selected?.kind == ObservedSubscriptionKind.EMBEDDED)
    }
    @Test fun postProviderExpiryCannotPublishFinalReceipt() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        f.pointHook = { f.now = proof.expiresAtMs + 900_000L }
        f.runtime.accept(f.receipt(proof))
        assertNull(f.db.attempts().currentLineBinding())
    }
    @Test fun closeOrPermissionWithdrawalCannotRecoverAuthorityFromInstalledJournal() = LineActivationV2RuntimeFixture(true).use { f ->
        val binding = f.installSealed()
        val proof = checkNotNull(f.db.lineActivationsV2().find("sealed", f.challengeId.toString()))
        assertTrue(proof.isInstalled())
        f.owner.permissionLost()
        assertFalse(binding.liveContinuity()); assertNull(binding.installedSelectionV2())
        f.runtime.accept(f.receipt(proof))
        assertNull(binding.installedSelectionV2())
    }
    @Test fun changedNonceCannotOverwriteOutstandingSignedProof() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        val c = f.challenge()
        val altered = LineActivationV2IncomingFrames.SmsChallenge(c.challengeId, c.accountId, c.lineId, c.deviceId,
            c.generation, ByteArray(32) { 8 }, c.expiresAtMs)
        assertNull(f.runtime.accept(altered)); assertEquals(1, f.signCalls)
        assertEquals(proof.observationB64url, f.db.lineActivationsV2().find("sms", f.challengeId.toString())?.observationB64url)
        f.runtime.accept(f.receipt(proof)); assertNull(f.db.attempts().currentLineBinding())
    }

    @Test fun exactProofRetryResendsHeldBytesAndSelectionChangeCannotReprove() = LineActivationV2RuntimeFixture().use { f ->
        val first = checkNotNull(f.runtime.accept(f.challenge()))
        assertEquals(first, f.runtime.accept(f.challenge())); assertEquals(1, f.signCalls)
        f.selected = 8; f.owner.selectCurrent()
        assertNull(f.runtime.accept(f.challenge())); assertEquals(1, f.signCalls)
        assertNull(f.db.attempts().currentLineBinding())
    }

    @Test fun negativeOrWrongEpochSealedAckCannotPublishInstallation() = LineActivationV2RuntimeFixture(true).use { f ->
        f.acceptSealed(); val proof = f.proof(LineActivationV2Purpose.SEALED)
        f.runtime.accept(LineActivationV2IncomingFrames.SealedProofAck(f.epoch + 1, f.challengeId, true))
        assertEquals("signed", f.db.lineActivationsV2().find("sealed", f.challengeId.toString())?.state)
        assertNotNull(f.runtime.accept(f.receipt(proof)))
        f.runtime.accept(LineActivationV2IncomingFrames.SealedInstallAck(f.epoch, f.challengeId, false))
        val binding = checkNotNull(f.db.attempts().currentLineBinding())
        assertFalse(binding.liveContinuity())
        f.runtime.accept(LineActivationV2IncomingFrames.SealedInstallAck(f.epoch, f.challengeId, true))
        assertFalse(binding.liveContinuity())
        assertEquals("retired", f.db.lineActivationsV2().find("sealed", f.challengeId.toString())?.state)
    }

    @Test fun currentEpochColdReceiptReconcilesDispositionWithoutRestoringAuthority() = LineActivationV2RuntimeFixture(true).use { f ->
        f.acceptSealed(); val proof = f.proof(LineActivationV2Purpose.SEALED)
        assertNotNull(f.runtime.accept(f.receipt(proof)))
        val binding = checkNotNull(f.db.attempts().currentLineBinding())
        f.runtime.close(); f.owner.retireAtEntry(); SealedLineActivationMount.disable()
        f.newRuntime(f.epoch + 1).use { reconnected ->
            assertNull(reconnected.accept(f.receipt(proof)))
            val receipt = f.receipt(proof) as LineActivationV2IncomingFrames.SealedActivated
            val current = LineActivationV2IncomingFrames.SealedActivated(f.epoch + 1, receipt.challengeId,
                receipt.accountId, receipt.lineId, receipt.deviceId, receipt.generation,
                receipt.deviceStatementSha256(), receipt.deviceSignatureSha256())
            val output = checkNotNull(reconnected.accept(current))
            val installed = LineActivationV2IncomingFrames.parse(output.toByteArray(), LineActivationV2Purpose.SEALED)
                as LineActivationV2IncomingFrames.SealedInstalled
            assertEquals(f.epoch + 1, installed.connectionEpoch)
            reconnected.accept(LineActivationV2IncomingFrames.SealedInstallAck(f.epoch + 1, f.challengeId, true))
            assertTrue(checkNotNull(f.db.lineActivationsV2().find("sealed", f.challengeId.toString())).isInstalled())
            assertFalse(binding.liveContinuity()); assertNull(binding.installedSelectionV2()); assertEquals(1, f.signCalls)
        }
    }

    @Test fun sessionRetirementDuringSignerReadCannotCommitOrPublishFinal() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        f.pointHook = { f.active = false }
        f.runtime.accept(f.receipt(proof))
        assertNull(f.db.attempts().currentLineBinding())
    }

    @Test fun refusedExpiryCannotBecomeCurrentAfterClockRollsBack() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        f.now = proof.expiresAtMs + 900_000L
        assertNull(f.runtime.accept(f.receipt(proof)))
        f.now = 150_000L
        assertNull(f.runtime.accept(f.receipt(proof))); assertNull(f.db.attempts().currentLineBinding())
    }

    @Test fun rejectedSmsProofWithdrawsPendingBeforeFailingRoomRetirement() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof()
        f.db.openHelper.writableDatabase.execSQL("CREATE TRIGGER retire_fault BEFORE UPDATE ON line_activation_v2 WHEN NEW.state = 'retired' BEGIN SELECT RAISE(ABORT, 'synthetic retire fault'); END")
        assertNull(f.runtime.accept(LineActivationV2IncomingFrames.SmsProofAck(f.challengeId, false)))
        assertEquals("signed", f.db.lineActivationsV2().find("sms", f.challengeId.toString())?.state)
        f.db.openHelper.writableDatabase.execSQL("DROP TRIGGER retire_fault")
        assertNull(f.runtime.accept(f.receipt(proof)))
        assertNull(f.db.attempts().currentLineBinding())
        assertNull(f.runtime.accept(f.challenge())); assertEquals(1, f.signCalls)
    }

    @Test fun rejectedSealedInstallWithdrawsPendingBeforeFailingRoomRetirement() = LineActivationV2RuntimeFixture(true).use { f ->
        f.acceptSealed(); val proof = f.proof(LineActivationV2Purpose.SEALED)
        assertNotNull(f.runtime.accept(f.receipt(proof)))
        val binding = checkNotNull(f.db.attempts().currentLineBinding())
        f.db.openHelper.writableDatabase.execSQL("CREATE TRIGGER retire_fault BEFORE UPDATE ON line_activation_v2 WHEN NEW.state = 'retired' BEGIN SELECT RAISE(ABORT, 'synthetic retire fault'); END")
        assertNull(f.runtime.accept(LineActivationV2IncomingFrames.SealedInstallAck(f.epoch, f.challengeId, false)))
        assertEquals("final_recorded", f.db.lineActivationsV2().find("sealed", f.challengeId.toString())?.state)
        f.db.openHelper.writableDatabase.execSQL("DROP TRIGGER retire_fault")
        f.runtime.accept(LineActivationV2IncomingFrames.SealedInstallAck(f.epoch, f.challengeId, true))
        assertFalse(binding.liveContinuity()); assertNull(binding.installedSelectionV2())
        assertNull(f.runtime.accept(f.challenge(LineActivationV2Purpose.SEALED))); assertEquals(1, f.signCalls)
    }

    @Test fun conflictingChallengeWithdrawsOriginalProofBeforeFailingRoomRetirement() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof(); val c = f.challenge()
        f.db.openHelper.writableDatabase.execSQL("CREATE TRIGGER retire_fault BEFORE UPDATE ON line_activation_v2 WHEN NEW.state = 'retired' BEGIN SELECT RAISE(ABORT, 'synthetic retire fault'); END")
        assertNull(f.runtime.accept(LineActivationV2IncomingFrames.SmsChallenge(c.challengeId, c.accountId,
            c.lineId, c.deviceId, c.generation, ByteArray(32) { 8 }, c.expiresAtMs)))
        assertEquals("signed", f.db.lineActivationsV2().find("sms", f.challengeId.toString())?.state)
        f.db.openHelper.writableDatabase.execSQL("DROP TRIGGER retire_fault")
        f.runtime.accept(f.receipt(proof))
        assertNull(f.db.attempts().currentLineBinding()); assertEquals(1, f.signCalls)
    }

    @Test fun installedSmsAuthorityWithdrawsAtSessionLossBeforeObserverCleanupAndCannotCrossReconnect() =
        LineActivationV2RuntimeFixture().use { f ->
            val proof = f.proof(); f.runtime.accept(f.receipt(proof))
            val binding = checkNotNull(f.db.attempts().currentLineBinding())
            val installed = checkNotNull(binding.installedSelectionV2())
            val oldLease = installed.lease
            f.active = false
            assertFalse(installed.isCurrent()); assertNull(binding.installedSelectionV2())
            var cleaned = false
            f.closeHook = { assertFalse(installed.isCurrent()); assertFalse(oldLease.isCurrent()); cleaned = true }
            f.runtime.close(); assertTrue(cleaned)
            f.active = true
            f.owner.selectCurrent()
            val replacement = checkNotNull(f.owner.capture())
            assertNotSame(oldLease, replacement)
            assertFalse(oldLease.observation().bytes().contentEquals(replacement.observation().bytes()))
            f.runtime.close(); assertTrue(replacement.isCurrent()) // Obsolete duplicate cleanup cannot close the new registration.
            assertFalse(installed.isCurrent()); assertNull(binding.installedSelectionV2())
            assertEquals(1, LineActivationV2Negotiation.select(DeviceStatusPublisher.PROTOCOL_V2,
                LineActivationV2Negotiation.offer(true, false)).lineVersion)
            f.newRuntime(f.epoch + 1).use { newSession ->
                assertNull(newSession.accept(f.receipt(proof))); assertFalse(binding.liveContinuity())
            }
        }

    @Test fun finalProofUploadRefusesCallbackSelectionPermissionExpiryAndSessionLossAfterPreparation() {
        listOf("callback", "selection", "permission", "expiry", "session").forEach { loss ->
            LineActivationV2RuntimeFixture().use { f ->
                var writes = 0
                assertNull(f.runtime.acceptAndSend(f.challenge(), {
                    when (loss) {
                        "callback" -> f.callback()
                        "selection" -> { f.selected = 8; f.owner.selectCurrent() }
                        "permission" -> f.owner.permissionLost()
                        "expiry" -> f.now = 200_000L
                        "session" -> f.active = false
                    }
                    f.active
                }, { writes++; true }))
                assertEquals(1, f.signCalls); assertEquals(0, writes)
                assertNull(f.db.attempts().currentLineBinding())
            }
        }
    }

    @Test fun finalInstalledReceiptUploadRefusesCallbackOrExpiryAfterProvisionalWrite() {
        listOf("callback", "expiry").forEach { loss -> LineActivationV2RuntimeFixture(true).use { f ->
            f.acceptSealed(); val proof = f.proof(LineActivationV2Purpose.SEALED)
            var writes = 0
            assertNull(f.runtime.acceptAndSend(f.receipt(proof), {
                if (loss == "callback") f.callback() else f.now = proof.expiresAtMs + 900_000L
                true
            }, { writes++; true }))
            val binding = checkNotNull(f.db.attempts().currentLineBinding())
            assertEquals("final_recorded", f.db.lineActivationsV2().find("sealed", f.challengeId.toString())?.state)
            assertEquals(0, writes); assertFalse(binding.liveContinuity())
            f.runtime.accept(LineActivationV2IncomingFrames.SealedInstallAck(f.epoch, f.challengeId, true))
            assertFalse(binding.liveContinuity())
        } }
    }

    @Test fun sourceOwnedUploadUsesExactHeldProofRetryWithoutResigning() = LineActivationV2RuntimeFixture().use { f ->
        val frames = mutableListOf<String>()
        repeat(2) {
            assertEquals(true, f.runtime.acceptAndSend(f.challenge(), { f.active }, { output -> frames.add(output); true }))
        }
        assertEquals(2, frames.size); assertEquals(frames.first(), frames.last()); assertEquals(1, f.signCalls)
        assertEquals(f.epoch, LineActivationV2Frames.parseProof(JSONObject(frames.first()), LineActivationV2Purpose.SMS).connectionEpoch)
    }

    @Test fun uncertainSocketWriteReportsTransportLossWithoutInstalledAuthority() = LineActivationV2RuntimeFixture().use { f ->
        var writes = 0
        assertEquals(false, f.runtime.acceptAndSend(f.challenge(), { f.active }, {
            writes++; throw java.io.IOException("Synthetic uncertain socket write")
        }))
        assertEquals(1, writes); assertNull(f.db.attempts().currentLineBinding())
        f.runtime.close()
        assertFalse(f.runtime.isCurrent()); assertNull(f.runtime.accept(f.challenge()))
    }

    @Test fun serviceOptOutSigningFenceRefusesSenderProviderRetirementBeforeAnySignerCall() {
        listOf("callback", "session", "selection", "binding", "age", "clock").forEach { loss ->
            LineActivationV2RuntimeFixture().use { f ->
                val proof = f.proof(); f.runtime.accept(f.receipt(proof))
                val binding = checkNotNull(f.db.attempts().currentLineBinding())
                val dao = f.db.attempts()
                assertTrue(dao.recordLocalWithdrawal("a".repeat(64), "b".repeat(64), InboundClassification.OPT_OUT,
                    f.selected, f.cards(), f.now + 1, ByteArray(32) { 1 }, ByteArray(12) { 2 }))
                val entry = checkNotNull(dao.nextLineOptOut(f.now))
                val fence = LineOptOutSigningFence(binding, entry, f.account, f.device, dao::currentLineBinding,
                    { f.selected }, f::cards, { f.now }, { f.active })
                fence.requireCurrent()
                val recipient = LineOptOutSender.recover(entry, { _, _ ->
                    when (loss) {
                        "callback" -> f.callback()
                        "session" -> f.active = false
                        "selection" -> { f.selected = 8; f.owner.selectCurrent() }
                        "binding" -> f.db.openHelper.writableDatabase.execSQL("UPDATE local_line_binding SET generation = 2")
                        "age" -> f.now += java.util.concurrent.TimeUnit.DAYS.toMillis(7)
                        "clock" -> f.now--
                    }
                    "+12025550123"
                }, { entry.senderToken })
                assertNotNull(recipient)
                var signerCalls = 0
                assertThrows(IllegalStateException::class.java) { fence.sign { signerCalls++; ByteArray(8) } }
                assertEquals(0, signerCalls); assertNull(dao.lineOptOutByEventId(checkNotNull(entry.eventId))?.signatureDer)
            }
        }
    }

    @Test fun serviceOptOutSigningFenceUsesCurrentObjectAndRefusesPostSignerRetirement() = LineActivationV2RuntimeFixture().use { f ->
        val proof = f.proof(); f.runtime.accept(f.receipt(proof))
        val binding = checkNotNull(f.db.attempts().currentLineBinding()); val dao = f.db.attempts()
        assertTrue(dao.recordLocalWithdrawal("a".repeat(64), "b".repeat(64), InboundClassification.OPT_OUT,
            f.selected, f.cards(), f.now + 1, ByteArray(32) { 1 }, ByteArray(12) { 2 }))
        val entry = checkNotNull(dao.nextLineOptOut(f.now))
        val fence = LineOptOutSigningFence(binding, entry, f.account, f.device, dao::currentLineBinding,
            { f.selected }, f::cards, { f.now }, { f.active })
        var signerCalls = 0
        assertArrayEquals(ByteArray(8) { 3 }, fence.sign { signerCalls++; ByteArray(8) { 3 } })
        assertEquals(1, signerCalls)
        assertThrows(IllegalStateException::class.java) { fence.sign { signerCalls++; f.callback(); ByteArray(8) } }
        assertEquals(2, signerCalls); assertNull(dao.lineOptOutByEventId(checkNotNull(entry.eventId))?.signatureDer)
    }
}
