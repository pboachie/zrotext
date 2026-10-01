// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import java.util.concurrent.Executor
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Compiled lifecycle/holder acceptance only. No keys, network, SIM, or radio providers.
 * Reflection constructs the actual private holder, not a fake Prepared implementation;
 * these tests do not establish hardware decryption or authorized radio execution.
 */
@RunWith(AndroidJUnit4::class)
class ConversationCompiledAcceptanceDeviceTest {
    private val account = UUID.randomUUID()
    private val device = UUID.randomUUID()
    private val identity = EvidenceIdentity(account.toString(), device.toString(), "11".repeat(32))
    private val queued = ArrayDeque<Runnable>()
    private val worker = Executor { queued.addLast(it) }
    private val mount = ConversationRuntimeMount()
    private var sent = ""
    private var providers = 0
    private var publications = 0
    private val connections = mutableListOf<ConversationSocketNegotiation>()
    private val socket = object : okhttp3.WebSocket {
        override fun request() = okhttp3.Request.Builder().url("https://example.org").build()
        override fun queueSize() = 0L
        override fun send(text: String): Boolean { sent = text; return true }
        override fun send(bytes: okio.ByteString): Boolean = error("No content or authority request permitted")
        override fun close(code: Int, reason: String?) = true
        override fun cancel() = Unit
    }
    private fun factory() = ConversationConnectionFactory("fixture-site", "fixture-instance", { 100L }, worker,
        { _, _ -> providers++; error("No enrolled proposal fixture") },
        { error("No hardware keys may be acquired") }, { publications++ }, mount)
    private fun begin(): ConversationSocketNegotiation = factory().create(socket, identity, 7).also {
        connections.add(it); it.start()
    }
    private fun frame() = JSONObject().put("v", 1).put("type", "conversation_session")
        .put("challenge", JSONObject(sent).getString("challenge"))
        .put("account_id", account.toString()).put("device_id", device.toString())
        .put("phone_session", UUID.randomUUID().toString()).put("connection_epoch", 7)
        .put("deployment_epoch", 3).put("origin_hash", identity.originHash)
    private fun drain() {
        // The real negotiation rejects provider execution on the socket-listener thread.
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val thread = Thread {
            try { while (queued.isNotEmpty()) queued.removeFirst().run() }
            catch (error: Throwable) { failure.set(error) }
        }
        thread.start(); thread.join(5000)
        assertFalse("Factory worker did not finish", thread.isAlive)
        failure.get()?.let { throw it }
    }
    @After fun cleanup() {
        connections.forEach { it.close() }; drain()
        mount.pause(ConversationStopReason.WORKER_SHUTDOWN)
        ConversationSocketComposition.clear()
    }
    @Test fun compiledFactoryStaysDisabledWithoutExplicitInstall() {
        ConversationSocketComposition.clear()
        assertFalse(factory().install())
        assertNull(ConversationSocketComposition.create(socket, identity, 7))
        assertEquals(0, providers); assertEquals(0, publications); assertTrue(queued.isEmpty())
        assertNull(mount.firstReceipt())
    }
    @Test fun closeBeforeQueuedAssemblyCannotAcquireProvidersOrPublish() {
        val connection = begin(); connection.accept(frame())
        assertEquals(1, queued.size)
        connection.close(); drain()
        assertEquals(0, providers); assertEquals(0, publications)
        assertNull(connection.wire.currentSession()); assertNull(mount.firstReceipt())
    }
    @Test fun missingProposalClosesActualFactorySessionWithoutAnyFallback() {
        val connection = begin(); connection.accept(frame()); drain()
        assertEquals(1, providers); assertEquals(0, publications)
        assertNull(connection.wire.currentSession()); assertNull(mount.firstReceipt())
    }
    @Test fun sessionForAnotherAccountNeverReachesFactoryProviders() {
        val connection = begin()
        assertThrows(IllegalStateException::class.java) {
            connection.accept(frame().put("account_id", UUID.randomUUID().toString()))
        }
        connection.close(); drain()
        assertEquals(0, providers); assertEquals(0, publications); assertNull(mount.firstReceipt())
    }
    private fun holder(chars: CharArray, recheck: () -> Unit): Draft02OutboundPreparation.Prepared {
        val type = Class.forName("org.zrotext.gateway.Draft02OutboundPreparation\$OwnedPrepared")
        val constructor = type.declaredConstructors.single().apply { isAccessible = true }
        return constructor.newInstance(chars, 1, recheck) as Draft02OutboundPreparation.Prepared
    }
    @Test fun realPreparedHolderConsumesOnceAndWipesEvenWhenConsumerThrows() {
        val chars = "Synthetic holder".toCharArray()
        var checks = 0; var calls = 0
        val prepared = holder(chars) { checks++ }
        assertThrows(IllegalStateException::class.java) {
            prepared.consume { calls++; assertEquals("Synthetic holder", String(it)); error("Interrupted consumer") }
        }
        assertEquals(1, checks); assertEquals(1, calls); assertTrue(chars.all { it == '\u0000' })
        assertThrows(IllegalStateException::class.java) { prepared.consume { calls++ } }
        prepared.close(); prepared.close(); assertEquals(1, calls)
    }
    @Test fun expiredPreparedGuardWipesHolderBeforeConsumerAndCannotRetry() {
        val chars = "Synthetic revoked holder".toCharArray()
        var calls = 0
        val prepared = holder(chars) { error("Authority revoked") }
        assertThrows(IllegalStateException::class.java) { prepared.consume { calls++ } }
        assertEquals(0, calls); assertTrue(chars.all { it == '\u0000' })
        assertThrows(IllegalStateException::class.java) { prepared.consume { calls++ } }
        assertEquals(0, calls)
    }
    @Test fun explicitlyClosedPreparedHolderCannotBeConsumedAfterRepeatedUiFlow() {
        val chars = "Synthetic cancelled holder".toCharArray()
        var calls = 0
        val prepared = holder(chars) { calls++ }
        prepared.close(); prepared.close()
        assertTrue(chars.all { it == '\u0000' })
        assertThrows(IllegalStateException::class.java) { prepared.consume { calls++ } }
        assertEquals(0, calls)
    }
    @Test fun typedTransportRealPreparedAckAndCasPermitExactlyOneSimulatedDriverCall() {
        ConversationCompiledRadioFixture().use { fixture ->
            val transport = fixture.transport()
            assertEquals(ConversationSubmission.SUBMITTED, transport.submitClaimed(fixture.claim()))
            assertEquals(1, fixture.intents); assertEquals(1, fixture.sends)
            assertEquals(AttemptState.RADIO_STARTED, fixture.db.attempts().getAttempt(fixture.attempt)!!.state)
            assertTrue(fixture.chars.all { it == '\u0000' })
            assertEquals(ConversationSubmission.UNKNOWN, transport.submitClaimed(fixture.claim()))
            assertEquals(ConversationSubmission.UNKNOWN, fixture.transport().submitClaimed(fixture.claim()))
            assertEquals(1, fixture.sends)
        }
    }
    @Test fun deniedWriterAckLeavesNoSimulatedDriverCallOrCas() {
        ConversationCompiledRadioFixture().use { fixture ->
            fixture.permitted = false
            assertEquals(ConversationSubmission.UNKNOWN, fixture.transport().submitClaimed(fixture.claim()))
            assertEquals(1, fixture.intents); assertEquals(0, fixture.sends); assertEquals(0, fixture.divisions)
            assertEquals(AttemptState.NOT_SUBMITTED, fixture.db.attempts().getAttempt(fixture.attempt)!!.state)
            assertTrue(fixture.chars.all { it == '\u0000' })
        }
    }
    @Test fun expiryDuringDriverPreparationPreventsFinalCasAndSimulatedSend() {
        ConversationCompiledRadioFixture().use { fixture ->
            fixture.prepareHook = { fixture.now = fixture.deadline }
            assertEquals(ConversationSubmission.UNKNOWN, fixture.transport().submitClaimed(fixture.claim()))
            assertEquals(1, fixture.intents); assertEquals(1, fixture.divisions); assertEquals(0, fixture.sends)
            assertNotEquals(AttemptState.RADIO_STARTED, fixture.db.attempts().getAttempt(fixture.attempt)!!.state)
            assertTrue(fixture.chars.all { it == '\u0000' }); assertEquals(1, fixture.driverClosed)
        }
    }
    @Test fun uncertainSimulatedDriverCallPersistsUnknownAndNeverReplays() {
        ConversationCompiledRadioFixture().use { fixture ->
            fixture.uncertain = true
            val transport = fixture.transport()
            assertEquals(ConversationSubmission.UNKNOWN, transport.submitClaimed(fixture.claim()))
            assertEquals(1, fixture.sends)
            assertEquals(AttemptState.UNKNOWN, fixture.db.attempts().getAttempt(fixture.attempt)!!.state)
            assertEquals(ConversationSubmission.UNKNOWN, transport.submitClaimed(fixture.claim()))
            assertEquals(ConversationSubmission.UNKNOWN, fixture.transport().submitClaimed(fixture.claim()))
            assertEquals(1, fixture.sends); assertTrue(fixture.chars.all { it == '\u0000' })
        }
    }
    @Test fun selectedLineProviderDelayCannotPassSignedDeadlineBeforeDivisionOrSend() {
        ConversationCompiledRadioFixture().use { fixture ->
            fixture.selectedHook = { fixture.now = fixture.deadline }
            assertEquals(ConversationSubmission.UNKNOWN, fixture.transport().submitClaimed(fixture.claim()))
            assertEquals(1, fixture.intents); assertEquals(0, fixture.divisions); assertEquals(0, fixture.sends)
            assertTrue(fixture.chars.all { it == '\u0000' })
        }
    }
    @Test fun suppressionKeyProviderDelayCannotPassSignedDeadlineBeforeDivisionOrSend() {
        ConversationCompiledRadioFixture().use { fixture ->
            fixture.suppressionHook = { fixture.now = fixture.deadline }
            assertEquals(ConversationSubmission.UNKNOWN, fixture.transport().submitClaimed(fixture.claim()))
            assertEquals(1, fixture.intents); assertEquals(0, fixture.divisions); assertEquals(0, fixture.sends)
            assertTrue(fixture.chars.all { it == '\u0000' })
        }
    }
}
