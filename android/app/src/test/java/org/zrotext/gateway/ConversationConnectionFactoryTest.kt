// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import androidx.room.Room
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class) @Config(sdk = [28])
class ConversationConnectionFactoryTest {
    private val account = UUID.randomUUID()
    private val device = UUID.randomUUID()
    private val line = UUID.randomUUID()
    private val interval = UUID.randomUUID()
    private val identity = EvidenceIdentity(account.toString(), device.toString(), "11".repeat(32))
    private val worker = Executors.newSingleThreadExecutor()
    private val mount = ConversationRuntimeMount()
    private val connections = mutableListOf<ConversationSocketNegotiation>()
    private val databases = mutableListOf<androidx.room.RoomDatabase>()
    private var sent = ""
    private var publications = 0
    private var providers = 0
    private val socket = object : okhttp3.WebSocket {
        override fun request() = okhttp3.Request.Builder().url("https://example.org").build()
        override fun queueSize() = 0L
        override fun send(text: String): Boolean { sent = text; return true }
        override fun send(bytes: okio.ByteString): Boolean = error("No approval/time/content request expected")
        override fun close(code: Int, reason: String?) = true
        override fun cancel() = Unit
    }
    private fun statement(): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { out ->
            fun id(value: UUID) { out.writeLong(value.mostSignificantBits); out.writeLong(value.leastSignificantBits) }
            fun text(value: String) { val bytes = value.toByteArray(Charsets.US_ASCII); out.writeByte(bytes.size); out.write(bytes) }
            out.write(byteArrayOf(90,84,67,65,1)); id(account); id(device); id(line); out.writeLong(1)
            id(interval); id(UUID.randomUUID()); id(UUID.randomUUID()); out.write(ByteArray(32) { 1 })
            out.writeLong(200000); text("+12"); text("conversation-content-v1")
            out.write(java.security.MessageDigest.getInstance("SHA-256").digest(ConversationActivationCodec.DISCLOSURE.toByteArray()))
            out.write(ByteArray(32) { 2 }); out.write(ByteArray(32) { 3 }); out.writeLong(1)
            out.writeLong(1); out.write(ByteArray(32) { 4 }); out.writeLong(2); out.write(ByteArray(32) { 5 })
            out.writeLong(7); out.writeLong(3); text("fixture-site"); text("fixture-instance")
        }
        return output.toByteArray()
    }
    private fun proposal(): ConversationConnectionProposal {
        val original = statement(); val scope = ConversationActivationCodec.decode(original).scope
        return ConversationConnectionProposal(original, ConversationPhoneReview(UUID.randomUUID().toString(),
            scope.intervalId, scope.lineId, scope.bindingGeneration, scope.peer, ConversationActivationCodec.DISCLOSURE,
            "conversation-content-v1", scope.disclosureDigest, 10000))
    }
    private fun session() = ConversationPhoneSession(account, device, UUID.randomUUID(), 7, 3, identity.originHash)
    private fun factory(proposal: (ConversationPhoneSession) -> ConversationConnectionProposal = { providers++; proposal() },
        inputs: (ConversationPhoneSession) -> ConversationConnectionInputs = { error("Missing verified providers") },
        publish: (ConversationConnectionFactory.Connection) -> Unit = { publications++ }) =
        ConversationConnectionFactory("fixture-site", "fixture-instance", { 100L }, worker, { session, _ -> proposal(session) }, inputs, publish, mount)
    private fun negotiate(factory: ConversationConnectionFactory): ConversationSocketNegotiation {
        val connection = factory.create(socket, identity, 7); connections.add(connection); connection.start()
        connection.accept(JSONObject().put("v",1).put("type","conversation_session")
            .put("challenge",JSONObject(sent).getString("challenge")).put("account_id",account.toString())
            .put("device_id",device.toString()).put("phone_session",UUID.randomUUID().toString())
            .put("connection_epoch",7).put("deployment_epoch",3).put("origin_hash",identity.originHash))
        return connection
    }
    private fun drain() { worker.submit {}.get(5, TimeUnit.SECONDS) }
    private fun inputs(releaseResources: () -> Unit = {}, loss: () -> ConversationStopReason? = { null }): ConversationConnectionInputs {
        val context = RuntimeEnvironment.getApplication()
        val capture = Room.inMemoryDatabaseBuilder(context, ConversationCaptureDatabase::class.java).allowMainThreadQueries().build()
        val sends = Room.inMemoryDatabaseBuilder(context, ConversationSendDatabase::class.java).allowMainThreadQueries().build()
        databases.add(capture); databases.add(sends)
        // Complete Room's cold schema/native initialization before timing publication races.
        // The production runtime still performs its own first installation read.
        assertNull(capture.journal().installation())
        val protection = object : ConversationJournalProtection {
            override fun seal(value: String, aad: String): InboundVault.Sealed = error("No consent")
            override fun open(value: InboundVault.Sealed, aad: String): String = error("No consent")
        }
        val trust = Draft02TrustStore(object : Draft02TrustStore.Storage {
            override fun <T> locked(action: Draft02TrustStore.Session.() -> T): T = error("No enrolled trust fixture")
        })
        return ConversationConnectionInputs(capture.journal(), sends.sends(), protection, trust,
            DevicePayloadKeyStore("fixture-existing-payload"), DeviceSigningKeyStore(context,"fixture-existing-signing"),
            java.util.concurrent.Executor { it.run() }, { _, _ -> error("No independently verified bindings") },
            { _, _ -> error("No authority") }, { error("No decision") }, { null }, loss,
            object : ConversationSendTransport {
                override fun submit(message: String, attempt: String, scope: ConversationCaptureScope, body: String): ConversationSubmission = error("No dispatch")
            }, releaseResources)
    }
    @After fun cleanup() {
        connections.forEach { it.close() }; mount.pause(ConversationStopReason.WORKER_SHUTDOWN)
        drain(); worker.shutdownNow(); databases.forEach { it.close() }; ConversationSocketComposition.clear()
    }
    @Test fun disabledFactoryNeverCallsProvidersOrCreatesConnection() {
        ConversationSocketComposition.clear()
        assertFalse(factory().install())
        assertNull(ConversationSocketComposition.create(socket, identity, 7))
        assertEquals(0, providers); assertEquals(0, publications); assertNull(mount.firstReceipt())
    }
    @Test fun canonicalProposalRequiresExactAccountDeviceEpochDeploymentAndReviewSelection() {
        val p = proposal(); val s = session()
        fun verify(session: ConversationPhoneSession = s, review: ConversationPhoneReview = p.review,
            site: String = "fixture-site", instance: String = "fixture-instance") =
            ConversationConnectionFactory.validateProposal(p.statement(), review, session, site, instance)
        assertEquals(interval.toString(), verify().scope.intervalId)
        for (changed in listOf(s.copy(account=UUID.randomUUID()), s.copy(device=UUID.randomUUID()),
            s.copy(connectionEpoch=8), s.copy(deploymentEpoch=4)))
            assertThrows(IllegalArgumentException::class.java) { verify(changed) }
        assertThrows(IllegalArgumentException::class.java) { verify(review=p.review.copy(peer="+13")) }
        assertThrows(IllegalArgumentException::class.java) { verify(review=p.review.copy(lineGeneration=2)) }
        assertThrows(IllegalArgumentException::class.java) { verify(site="other-site") }
        assertThrows(IllegalArgumentException::class.java) { verify(instance="other-instance") }
    }
    @Test fun lossWhileProposalProviderIsHeldCannotConstructOrPublish() {
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        var inputCalls = 0
        val connection = negotiate(factory(proposal={ entered.countDown(); check(release.await(5,TimeUnit.SECONDS)); proposal() },
            inputs={ inputCalls++; error("Must stay unreachable") }))
        try {
            assertTrue(entered.await(2,TimeUnit.SECONDS)); connection.close(); assertNull(connection.wire.currentSession())
        } finally { release.countDown() }
        drain(); assertEquals(0,inputCalls); assertEquals(0,publications); assertNull(mount.firstReceipt())
    }
    @Test fun missingVerifiedInputsCloseNegotiatedSessionWithoutPublication() {
        val connection = negotiate(factory()); drain()
        assertNull(connection.wire.currentSession()); assertEquals(1,providers); assertEquals(0,publications)
        assertNull(mount.firstReceipt())
    }
    @Test fun independentProviderLossRefusesAssemblyBeforeMountOrPublication() {
        var releases = 0
        val provided = inputs(releaseResources = { releases++ }) { ConversationStopReason.READER_CHANGED }
        val connection = negotiate(factory(inputs={ provided })); drain()
        assertNull(connection.wire.currentSession()); assertEquals(0,publications); assertNull(mount.firstReceipt()); assertEquals(1, releases)
    }
    @Test fun closeDuringPublicationClosesRealAssemblyBeforeAnyProposalOrKeyUse() {
        val releases = java.util.concurrent.atomic.AtomicInteger(0)
        val provided = inputs(releaseResources = { releases.incrementAndGet() })
        lateinit var connection: ConversationSocketNegotiation
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        var handle: ConversationConnectionFactory.Connection? = null
        connection = negotiate(factory(inputs={ provided }, publish={ value ->
            handle=value; publications++; entered.countDown(); check(release.await(5,TimeUnit.SECONDS))
            value.requireLive()
        }))
        try {
            assertTrue(entered.await(2,TimeUnit.SECONDS)); assertNotNull(mount.firstReceipt())
            val checked = CountDownLatch(1)
            val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
            val operation = Thread {
                try { checkNotNull(handle).requireLive() } catch (error: Throwable) { failure.set(error) }
                finally { checked.countDown() }
            }
            try {
                // A socket-loss owner may hold negotiation's monitor before closing admission.
                // Operational checks must not acquire it while their caller holds admission.
                synchronized(connection) {
                    operation.start(); assertTrue(checked.await(2,TimeUnit.SECONDS))
                }
                assertNull(failure.get())
            } finally { operation.join(2000) }
            connection.close(); assertEquals(0, releases.get()); assertNull(mount.firstReceipt()); assertNull(connection.wire.currentSession())
            assertThrows(IllegalStateException::class.java) { checkNotNull(handle).presentation }
        } finally { release.countDown() }
        drain(); assertEquals(1,publications); assertEquals(1, releases.get())
        connection.close(); drain(); assertEquals(1, releases.get())
    }
    @Test fun aClosedOldHandleCannotPauseReplacementAssembly() {
        val provided = inputs()
        val release = CountDownLatch(1); val published = CountDownLatch(1)
        val handles = java.util.concurrent.CopyOnWriteArrayList<ConversationConnectionFactory.Connection>()
        val factory = factory(inputs={ provided }, publish={ handles.add(it); published.countDown();
            // Return only after the test closes each negotiated owner, before any proposal.
            check(release.await(5,TimeUnit.SECONDS)) })
        val first = negotiate(factory)
        assertTrue(published.await(2,TimeUnit.SECONDS))
        first.close(); release.countDown(); drain()
        val secondEntered = CountDownLatch(1); val secondRelease = CountDownLatch(1)
        val second = negotiate(factory(inputs={ provided }, publish={ handles.add(it); secondEntered.countDown();
            check(secondRelease.await(5,TimeUnit.SECONDS)) }))
        try {
            assertTrue(secondEntered.await(2,TimeUnit.SECONDS)); val receipt = mount.firstReceipt(); assertNotNull(receipt)
            handles.first().close(); assertNotNull(mount.firstReceipt()); assertNotNull(second.wire.currentSession())
            second.close(); assertNull(mount.firstReceipt())
        } finally { secondRelease.countDown() }
        drain()
    }
    @Test fun concurrentCloseCannotReturnBeforeAdmissionFenceCompletes() {
        val provided = inputs()
        val published = CountDownLatch(1); val releasePublication = CountDownLatch(1)
        lateinit var handle: ConversationConnectionFactory.Connection
        val connection = negotiate(factory(inputs={ provided }, publish={
            handle=it; published.countDown(); check(releasePublication.await(5,TimeUnit.SECONDS))
        }))
        assertTrue(published.await(2,TimeUnit.SECONDS))
        // Hold the real content session's close monitor; no production callback or fake closer.
        val content = checkNotNull(handle.javaClass.getDeclaredField("content").apply { isAccessible=true }.get(handle))
        val closed = handle.javaClass.getDeclaredField("closed").apply { isAccessible=true }.get(handle) as java.util.concurrent.atomic.AtomicBoolean
        val firstDone = CountDownLatch(1); val secondDone = CountDownLatch(1)
        val first = Thread { try { handle.close() } finally { firstDone.countDown() } }
        val second = Thread { try { handle.close() } finally { secondDone.countDown() } }
        try {
            synchronized(content) {
                first.start()
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                while (!closed.get() && System.nanoTime() < deadline) Thread.sleep(1)
                assertTrue(closed.get()); assertNotNull(mount.firstReceipt())
                second.start()
                assertFalse(secondDone.await(100,TimeUnit.MILLISECONDS))
                assertFalse(firstDone.await(100,TimeUnit.MILLISECONDS))
            }
            assertTrue(firstDone.await(2,TimeUnit.SECONDS)); assertTrue(secondDone.await(2,TimeUnit.SECONDS))
            assertNull(mount.firstReceipt())
        } finally {
            releasePublication.countDown(); first.join(2000); if(second.state != Thread.State.NEW) second.join(2000)
            connection.close()
        }
        drain()
    }
}
