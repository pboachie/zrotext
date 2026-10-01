// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.KeyPairGenerator
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

@RunWith(RobolectricTestRunner::class) @Config(sdk = [28])
class ConversationUserSetupControllerTest {
    private var fixtureStatement = ByteArray(0)
    private val f = ConversationInputFixture
    private fun fixture(): Pair<ConversationUserSetupController.Selection, ConversationActivationCodec.Parsed> {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val public = key.public as java.security.interfaces.ECPublicKey
        fun coordinate(value: java.math.BigInteger) = value.toByteArray().takeLast(32).toByteArray().let {
            ByteArray(32 - it.size) + it
        }
        val point = byteArrayOf(4) + coordinate(public.w.affineX) + coordinate(public.w.affineY)
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { out ->
            fun id(value: String) { val parsed = UUID.fromString(value); out.writeLong(parsed.mostSignificantBits); out.writeLong(parsed.leastSignificantBits) }
            fun text(value: String) { val bytes = value.toByteArray(Charsets.US_ASCII); out.writeByte(bytes.size); out.write(bytes) }
            out.write(byteArrayOf(90,84,67,65,1)); id(f.scope.accountId); id(f.scope.deviceId); id(f.scope.lineId)
            out.writeLong(1); id(f.scope.intervalId); id(f.scope.receiptId); id(f.scope.initiatingSessionId)
            out.write(ByteArray(32) { 1 }); out.writeLong(200000); text(f.scope.peer); text("conversation-content-v1")
            out.write(java.security.MessageDigest.getInstance("SHA-256").digest(ConversationActivationCodec.DISCLOSURE.toByteArray(Charsets.UTF_8)))
            out.write(DevicePayloadKeyStore.keyId(point)); out.write(ByteArray(32) { 3 }); out.writeLong(1)
            out.writeLong(1); out.write(ByteArray(32) { 4 }); out.writeLong(2); out.write(ByteArray(32) { 5 })
            out.writeLong(f.session.connectionEpoch); out.writeLong(f.session.deploymentEpoch); text("fixture-site"); text("fixture-instance")
        }
        fixtureStatement = output.toByteArray()
        val parsed = ConversationActivationCodec.decode(fixtureStatement); val scope = parsed.scope
        return ConversationUserSetupController.Selection(EvidenceIdentity(scope.accountId, scope.deviceId, f.session.originHash),
            scope.intervalId, scope.lineId, scope.bindingGeneration, scope.peer,
            ConversationConnectionBindings(point, ByteArray(32)), "fixture-site", "fixture-instance") to parsed
    }
    private fun selection() = fixture().first
    @Test fun publicSetupDecodesExactUntrustedSelectionAndRejectsForeignIdentityOrTrailingBytes() {
        val selected = selection()
        val identity = selected.identity.copy(originHash = "01".repeat(32))
        val output=ByteArrayOutputStream()
        DataOutputStream(output).use { it.write(byteArrayOf(90,84,80,83,1)); it.writeShort(fixtureStatement.size)
            it.write(fixtureStatement); it.write(selected.bindings.archivePoint); it.write(ByteArray(32){7}) }
        val bytes=output.toByteArray()
        val decoded=ConversationUserSetupProvider.decodeSelection(bytes,identity).first
        assertEquals(selected.intervalId,decoded.intervalId)
        assertTrue(decoded.bindings.outboundSigner.all { it == 0.toByte() })
        assertThrows(Exception::class.java) { ConversationUserSetupProvider.decodeSelection(bytes+byteArrayOf(0),identity) }
        assertThrows(Exception::class.java) { ConversationUserSetupProvider.decodeSelection(bytes,identity.copy(deviceId=UUID.randomUUID().toString())) }
        assertThrows(Exception::class.java) { ConversationUserSetupProvider.decodeSelection(bytes.copyOf().also { it[it.size-40]=(it[it.size-40].toInt() xor 1).toByte() },identity) }
    }
    @Test fun replyFileIsBoundedImmutableCandidateAndPendingControllerCannotInstallAuthority() {
        val output=ByteArrayOutputStream()
        DataOutputStream(output).use { it.write(byteArrayOf(90,84,80,82,1)); it.writeShort(364)
            it.write(ByteArray(364){2}); it.write(ByteArray(32){3}) }
        val bytes=output.toByteArray(); val decoded=ConversationUserSetupProvider.decodeReplyAuthority(bytes)
        bytes.fill(0); assertEquals(2,decoded.signedSuccessor()[0].toInt())
        assertThrows(Exception::class.java) { ConversationUserSetupProvider.decodeReplyAuthority(output.toByteArray()+byteArrayOf(0)) }
        val app=RuntimeEnvironment.getApplication()
        val db=Room.inMemoryDatabaseBuilder(app,SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        val controller=ConversationUserSetupController(app,db.attempts(),"fixture-existing",Executor { it.run() },
            Executor { it.run() },ConversationExecutionComposition(app,db), { error("No publication") })
        try {
            var accepted=true
            controller.installReplyAuthority(decoded.signedSuccessor(),decoded.signerId()) { accepted=it }
            assertFalse(accepted)
            controller.close()
            controller.installReplyAuthority(decoded.signedSuccessor(),decoded.signerId()) { accepted=it }
            assertFalse(accepted)
        } finally { controller.close();db.close() }
    }
    @Test fun disabledSetupOpensNoResourceAndInstallsNoSocketFactory() {
        ConversationSocketComposition.clear()
        val app = RuntimeEnvironment.getApplication()
        val db = Room.inMemoryDatabaseBuilder(app, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        val controller = ConversationUserSetupController(app, db.attempts(), "fixture-existing", Executor { error("No worker") },
            Executor { error("No delivery") }, ConversationExecutionComposition(app, db), { error("No publication") })
        try {
            assertFalse(controller.begin(selection()))
            assertFalse(app.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(app.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
            assertNull(ConversationSocketComposition.create(socket(), EvidenceIdentity(f.scope.accountId, f.scope.deviceId, f.session.originHash), 1))
        } finally { controller.close(); db.close(); ConversationSocketComposition.clear() }
    }
    @Test fun selectionAcceptsNewNegotiatedSessionButRejectsForeignIdentityAndIntervalBeforeProvider() {
        val (selected, parsed) = fixture()
        ConversationUserSetupController.validateIdentity(selected, f.session.copy(session = UUID.randomUUID()))
        ConversationUserSetupController.validateProposalSelection(selected, parsed)
        assertThrows(IllegalStateException::class.java) {
            ConversationUserSetupController.validateIdentity(selected, f.session.copy(device = UUID.randomUUID()))
        }
        val changed = ConversationUserSetupController.Selection(selected.identity, UUID.randomUUID().toString(), selected.lineId,
            selected.bindingGeneration, selected.peer, selected.bindings, selected.site, selected.instance)
        assertThrows(IllegalStateException::class.java) { ConversationUserSetupController.validateProposalSelection(changed, parsed) }
    }
    @Test fun closeWhileNegotiatedReadyIsQueuedCannotOpenOrPublishInputs() {
        ConversationSocketComposition.clear()
        val app = RuntimeEnvironment.getApplication()
        val db = Room.inMemoryDatabaseBuilder(app, SmsJournalDatabase::class.java).allowMainThreadQueries().build()
        val queue = java.util.ArrayDeque<Runnable>(); var publications = 0; var sent = ""
        val controller = ConversationUserSetupController(app, db.attempts(), "fixture-existing", Executor { queue.add(it) },
            Executor { it.run() }, ConversationExecutionComposition(app, db), { publications++ }, { 100L })
        try {
            assertTrue(controller.begin(selection(), enabled = true))
            val negotiation = checkNotNull(ConversationSocketComposition.create(socket { sent = it },
                EvidenceIdentity(f.scope.accountId, f.scope.deviceId, f.session.originHash), 1))
            negotiation.start()
            negotiation.accept(JSONObject().put("v", 1).put("type", "conversation_session")
                .put("challenge", JSONObject(sent).getString("challenge")).put("account_id", f.scope.accountId)
                .put("device_id", f.scope.deviceId).put("phone_session", UUID.randomUUID().toString())
                .put("connection_epoch", 1).put("deployment_epoch", 1).put("origin_hash", f.session.originHash))
            assertEquals(1, queue.size)
            controller.close()
            val ready = Thread { queue.removeFirst().run() }; ready.start(); ready.join(2000)
            assertFalse(ready.isAlive); assertEquals(0, publications); assertNull(negotiation.wire.currentSession())
            assertFalse(app.getDatabasePath(ConversationJournalStores.CAPTURE_FILE).exists())
            assertFalse(app.getDatabasePath(ConversationJournalStores.SEND_FILE).exists())
        } finally { controller.close(); db.close(); ConversationSocketComposition.clear() }
    }
    @Test fun obsoleteInstallerCannotClearSuccessorAndReplacementIsRejected() {
        ConversationSocketComposition.clear()
        var first = 0; var second = 0
        val owner = checkNotNull(ConversationSocketComposition.installOwned({ _, _, _ -> first++; error("first") }, true))
        assertNull(ConversationSocketComposition.installOwned({ _, _, _ -> error("replacement") }, true))
        owner.close()
        val successor = checkNotNull(ConversationSocketComposition.installOwned({ _, _, _ -> second++; error("second") }, true))
        try {
            owner.close()
            assertThrows(IllegalStateException::class.java) {
                ConversationSocketComposition.create(socket(), EvidenceIdentity(f.scope.accountId, f.scope.deviceId, f.session.originHash), 1)
            }
            assertEquals(0, first); assertEquals(1, second)
        } finally { successor.close(); ConversationSocketComposition.clear() }
    }
    @Test fun wrapperRequiresActualObservedExactApprovalAndClosesLateActions() {
        val domain = ConversationDecisionPresentation(); var live = true; var approved = 0
        val decision = ConversationPhoneDecision(f.session, f.scope, f.review, 0, { 100L }, { f.session })
        val port = object : ConversationPresentationPort by domain {
            override fun approvePhoneReview(requestId: String, observedVersion: Long) { approved++; decision.consume(f.scope) }
        }
        val wrapper = ConversationUserSetupController.Presentation(port, decision) { check(live) }
        assertThrows(IllegalStateException::class.java) { wrapper.approvePhoneReview(f.review.requestId, 7) }
        decision.observePresentation(port); domain.review()
        assertThrows(IllegalStateException::class.java) { wrapper.approvePhoneReview(f.review.requestId, 6) }
        assertThrows(IllegalStateException::class.java) { wrapper.approvePhoneReview(UUID.randomUUID().toString(), 7) }
        wrapper.approvePhoneReview(f.review.requestId, 7); assertEquals(1, approved)
        assertThrows(IllegalStateException::class.java) { wrapper.approvePhoneReview(f.review.requestId, 7) }
        live = false
        assertThrows(IllegalStateException::class.java) { wrapper.refresh() }
        assertThrows(IllegalStateException::class.java) { wrapper.requestStop(f.scope.intervalId, 7) }
        decision.close()
    }
    @Test fun wrapperPreservesActualDurableStopFailureAndSynchronousAdmissionDisable() {
        var disabled = false
        val domain = object : ConversationPresentationDomain {
            override fun sample() = ConversationPresentationSnapshot(1, ConversationPresentationPhase.CONFIRMED_ACTIVE,
                f.scope.intervalId, f.scope.lineId, 1, 9000, true)
            override fun approve(review: ConversationPhoneReview, stillCurrent: () -> Boolean) = error("No approval")
            override fun decline(review: ConversationPhoneReview) = Unit
            override fun disableAdmission() { disabled = true }
            override fun stop(intervalId: String): ConversationPresentationSnapshot { check(disabled); error("Fixture durable write failure") }
        }
        val runtime = ConversationPresentationRuntime(Executor { it.run() }, Executor { it.run() }, domain)
        val decision = ConversationPhoneDecision(f.session, f.scope, f.review, 0, { 100L }, { f.session })
        val wrapper = ConversationUserSetupController.Presentation(runtime, decision) {}
        var snapshot: ConversationPresentationSnapshot? = null
        val observation = wrapper.observe { snapshot = it }
        wrapper.refresh(); wrapper.requestStop(f.scope.intervalId, checkNotNull(snapshot).version)
        assertTrue(disabled); assertEquals(ConversationPresentationPhase.FAILURE, snapshot?.phase)
        assertEquals(ConversationCloseOutcome.DISABLED_CLOSURE_FAILED, snapshot?.close); assertFalse(checkNotNull(snapshot).canStop)
        observation.close(); decision.close()
    }
    private fun socket(sent: (String) -> Unit = {}) = object : okhttp3.WebSocket {
        override fun request() = okhttp3.Request.Builder().url("https://example.org").build()
        override fun queueSize() = 0L
        override fun send(text: String): Boolean { sent(text); return true }
        override fun send(bytes: okio.ByteString): Boolean = error("No wire/time/provision/radio expected")
        override fun close(code: Int, reason: String?) = true
        override fun cancel() = Unit
    }
}
