// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.UUID
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class) @Config(sdk = [34])
class ConversationExecutionCompositionTest {
    private val f = ConversationInputFixture
    private val message = UUID.randomUUID()
    private val attempt = UUID.randomUUID()
    private val reader = ByteArray(32) { 7 }
    private val binding = LocalLineBinding(accountId = f.scope.accountId, deviceId = f.scope.deviceId,
        lineId = f.scope.lineId, generation = 1, subscriptionId = 2, installedAtMs = 1, cardId = 3)
    private val local = SealedDispatchExecutor.Local(binding, reader, 1, 4, "55".repeat(32),
        Draft02OutboundPreparation.hash(f.scope.peer.toByteArray(Charsets.US_ASCII)))
    private val session = SealedDispatchExecutor.Session(f.session.account, f.session.device, 1, 1,
        f.session.session, f.session.originHash)
    private fun current(now: Long = 1000, deadline: Long = 15000) = ConversationExecutionCurrent(session, local, now, deadline)
    private fun fields() = SealedExecutionGrantValidator.Fields(f.session.account, f.session.device,
        UUID.fromString(f.scope.lineId), message, attempt, 1, ByteArray(32) { 8 }, 10000, 6,
        1, reader.copyOf(), 1, 1, 1, ByteArray(32) { 9 })

    @Test fun currentGrantRejectsIdentityReaderEpochAttemptGenerationAndDeadlineChanges() {
        val good = fields()
        fun verify(value: SealedExecutionGrantValidator.Fields, live: ConversationExecutionCurrent = current(),
            deadline: Long = 12000) = ConversationExecutionComposition.requireGrant(value, f.scope,
            message.toString(), attempt.toString(), deadline, live)
        verify(good)
        for (changed in listOf(good.copy(accountId = UUID.randomUUID()), good.copy(deviceId = UUID.randomUUID()),
            good.copy(lineId = UUID.randomUUID()), good.copy(messageId = UUID.randomUUID()),
            good.copy(attemptId = UUID.randomUUID()), good.copy(connectionEpoch = 2), good.copy(deploymentEpoch = 2),
            good.copy(bindingGeneration = 2), good.copy(attemptGeneration = 2), good.copy(readerRole = 2),
            good.copy(readerKeyId = ByteArray(32) { 6 }), good.copy(segmentCount = 7))) {
            assertThrows(IllegalStateException::class.java) { verify(changed) }
        }
        assertThrows(IllegalStateException::class.java) { verify(good, current(now = 10000)) }
        assertThrows(IllegalStateException::class.java) { verify(good, current(deadline = 9000)) }
        assertThrows(IllegalStateException::class.java) { verify(good, deadline = 9000) }
        assertThrows(IllegalStateException::class.java) { ConversationExecutionComposition.requireGrant(good,
            f.scope.copy(peer = "+13"), message.toString(), attempt.toString(), 12000, current()) }
    }
    @Test fun preparationRejectsSessionOriginSelectedCardAndManifestChanges() {
        val good = SealedDispatchExecutor.candidate(fields(), session, local)
        ConversationExecutionComposition.requirePreparation(good, f.scope, current())
        for (changed in listOf(good.copy(sessionId = UUID.randomUUID().toString()), good.copy(originHash = "66".repeat(32)),
            good.copy(subscriptionId = 4), good.copy(cardId = 5), good.copy(manifestGeneration = 2),
            good.copy(manifestVersion = 5), good.copy(manifestDigest = "66".repeat(32)),
            good.copy(recipientDigest = "66".repeat(32)), good.copy(expiresAtMs = 16000))) {
            assertThrows(IllegalStateException::class.java) {
                ConversationExecutionComposition.requirePreparation(changed, f.scope, current())
            }
        }
    }

    private fun proposal(): ConversationConnectionProposal {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { out ->
            fun id(text: String) { val value = UUID.fromString(text); out.writeLong(value.mostSignificantBits); out.writeLong(value.leastSignificantBits) }
            fun text(value: String) { val bytes = value.toByteArray(Charsets.US_ASCII); out.writeByte(bytes.size); out.write(bytes) }
            out.write(byteArrayOf(90,84,67,65,1)); id(f.scope.accountId); id(f.scope.deviceId); id(f.scope.lineId)
            out.writeLong(1); id(f.scope.intervalId); id(f.scope.receiptId); id(f.scope.initiatingSessionId)
            out.write(ByteArray(32) { 1 }); out.writeLong(200000); text(f.scope.peer); text("conversation-content-v1")
            out.write(hex(f.scope.disclosureDigest)); out.write(ByteArray(32) { 2 }); out.write(ByteArray(32) { 3 })
            out.writeLong(1); out.writeLong(1); out.write(ByteArray(32) { 4 }); out.writeLong(2); out.write(ByteArray(32) { 5 })
            out.writeLong(7); out.writeLong(3); text("fixture-site"); text("fixture-instance")
        }
        val bytes = output.toByteArray(); val scope = ConversationActivationCodec.decode(bytes).scope
        return ConversationConnectionProposal(bytes, ConversationPhoneReview(UUID.randomUUID().toString(),
            scope.intervalId, scope.lineId, 1, scope.peer, ConversationActivationCodec.DISCLOSURE,
            "conversation-content-v1", scope.disclosureDigest, 10000))
    }
    private fun factoryFixture(throws: Boolean) {
        val app = RuntimeEnvironment.getApplication()
        val capture = Room.inMemoryDatabaseBuilder(app, ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        val sends = Room.inMemoryDatabaseBuilder(app, ConversationSendDatabase::class.java).allowMainThreadQueries().build()
        val sms = Room.inMemoryDatabaseBuilder(app, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        assertNull(capture.journal().installation())
        val worker = Executors.newSingleThreadExecutor(); val mount = ConversationRuntimeMount()
        var releases = 0; var hooks = 0; var publications = 0; var sent = ""
        val socket = object : okhttp3.WebSocket {
            override fun request() = okhttp3.Request.Builder().url("https://example.org").build()
            override fun queueSize() = 0L
            override fun send(text: String): Boolean { sent = text; return true }
            override fun send(bytes: okio.ByteString): Boolean = error("No credential/time/radio action expected")
            override fun close(code: Int, reason: String?) = true
            override fun cancel() = Unit
        }
        val inputs = ConversationConnectionInputs(capture.journal(), sends.sends(), object : ConversationJournalProtection {
            override fun seal(value: String, aad: String): InboundVault.Sealed = error("No consent")
            override fun open(value: InboundVault.Sealed, aad: String): String = error("No proof")
        }, Draft02TrustStore(object : Draft02TrustStore.Storage {
            override fun <T> locked(action: Draft02TrustStore.Session.() -> T): T = error("No enrolled trust")
        }), DevicePayloadKeyStore("fixture-existing-payload"), DeviceSigningKeyStore(app, "fixture-existing-signing"),
            Executor { it.run() }, { _, _ -> error("No selected keys") }, { _, _ -> error("No authority") },
            { error("No decision") }, { null }, { null }, object : ConversationSendTransport {
                override fun submit(message: String, attempt: String, scope: ConversationCaptureScope, body: String) = error("No legacy fallback")
            }, { releases++ })
        val composition = ConversationExecutionComposition(app, sms) // Disabled without explicit opt-in.
        val factory = ConversationConnectionFactory("fixture-site", "fixture-instance", { 100L }, worker,
            { _, _ -> proposal() }, { inputs }, { value -> publications++; assertEquals(1, hooks); value.close() }, mount,
            dispatchForConnection = { connection ->
                hooks++; assertSame(inputs, connection.inputs); assertNull(connection.runtime.currentScope())
                assertFalse(connection.runtime.captureEligible()); assertNull(connection.runtime.trustedNowMs())
                assertEquals(connection.phone, connection.wire.currentSession())
                if (throws) error("Fixture constructor refusal")
                val dispatch = composition.dispatch(connection)
                assertEquals(ConversationSubmission.UNKNOWN, dispatch.submit(message.toString(), attempt.toString(), f.scope, "fixture"))
                val claim = ConversationClaimedEvidence(message.toString(), attempt.toString(), f.scope, "77".repeat(32), 10000, byteArrayOf(1))
                assertEquals(ConversationSubmission.UNKNOWN, (dispatch as ConversationClaimedEvidenceTransport).submitClaimed(claim))
                assertThrows(IllegalStateException::class.java) { claim.take() }
                dispatch
            })
        val negotiation = factory.create(socket, EvidenceIdentity(f.scope.accountId, f.scope.deviceId, f.session.originHash), 7)
        try {
            negotiation.start()
            negotiation.accept(JSONObject().put("v", 1).put("type", "conversation_session")
                .put("challenge", JSONObject(sent).getString("challenge")).put("account_id", f.scope.accountId)
                .put("device_id", f.scope.deviceId).put("phone_session", f.session.session.toString())
                .put("connection_epoch", 7).put("deployment_epoch", 3).put("origin_hash", f.session.originHash))
            worker.submit {}.get(5, TimeUnit.SECONDS)
            assertEquals(1, hooks); assertEquals(if (throws) 0 else 1, publications)
            assertEquals(1, releases); assertNull(negotiation.wire.currentSession()); assertNull(mount.firstReceipt())
        } finally { negotiation.close(); worker.shutdownNow(); capture.close(); sends.close(); sms.close() }
    }
    @Test fun disabledConcreteFactoryHookUsesActualRuntimeAndClosesEvidenceWithoutFallback() = factoryFixture(false)
    @Test fun hookRefusalClosesOwnedRuntimeAndResourcesWithoutPublication() = factoryFixture(true)

    @Test fun executionDeadlineSharesRealAdmissionAndDoesNotRenewAcrossWaitsOrLoss() {
        val app = RuntimeEnvironment.getApplication()
        val capture = Room.inMemoryDatabaseBuilder(app, ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        val sends = Room.inMemoryDatabaseBuilder(app, ConversationSendDatabase::class.java).allowMainThreadQueries().build()
        var elapsed = 0L; var phone: ConversationPhoneSession? = f.session; var delay = false
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val protection = object : ConversationJournalProtection {
            override fun seal(value: String, aad: String): InboundVault.Sealed = Cipher.getInstance("AES/GCM/NoPadding").let {
                it.init(Cipher.ENCRYPT_MODE, key); it.updateAAD(aad.toByteArray()); InboundVault.Sealed(it.doFinal(value.toByteArray()), it.iv)
            }
            override fun open(value: InboundVault.Sealed, aad: String): String = Cipher.getInstance("AES/GCM/NoPadding").let {
                it.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, value.nonce)); it.updateAAD(aad.toByteArray()); it.doFinal(value.ciphertext).toString(Charsets.UTF_8)
            }
        }
        val verifier = object : ConversationActivationVerifier {
            override fun verifiedPreparation(evidence: ByteArray) = f.scope
            override fun verifiedActiveLease(scope: ConversationCaptureScope, challenge: String, evidence: ByteArray) = 10000L
        }
        val wire = object : ConversationAuthenticatedWire {
            override fun currentSession() = phone
            override fun exchange(request: ByteArray): ConversationAuthenticatedWire.Reply {
                val time = ConversationChannelCodec.parseTimeRequest(request, checkNotNull(phone))
                return ConversationAuthenticatedWire.Reply(checkNotNull(phone), ConversationChannelCodec.timeReply(
                    ConversationTimeReply(checkNotNull(phone), time.challenge, 100000)))
            }
        }
        val direct = Executor { it.run() }
        val runtime = ConversationAuthenticatedRuntime(capture.journal(), sends.sends(), verifier, protection, wire,
            { elapsed }, { scope, _ -> check(scope == f.scope); if (delay) { delay = false; elapsed += 3000 } },
            { }, { byteArrayOf(2) }, direct, direct)
        try {
            assertNull(runtime.executionDeadline(f.scope))
            var snapshot: ConversationPresentationSnapshot? = null
            runtime.presentation.observe { snapshot = it }
            runtime.propose(f.review, byteArrayOf(1)); assertNull(runtime.executionDeadline(f.scope))
            runtime.presentation.approvePhoneReview(f.review.requestId, checkNotNull(snapshot).version)
            assertTrue(runtime.captureEligible()); assertEquals(110000L, runtime.executionDeadline(f.scope))
            delay = true; val shortened = checkNotNull(runtime.executionDeadline(f.scope))
            assertTrue(shortened <= 110000 && shortened > checkNotNull(runtime.trustedNowMs()))
            elapsed = 10000; assertNull(runtime.executionDeadline(f.scope))
            phone = null; assertNull(runtime.executionDeadline(f.scope))
        } finally { runtime.lifecycleLost(ConversationStopReason.WORKER_SHUTDOWN); capture.close(); sends.close() }
    }
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
