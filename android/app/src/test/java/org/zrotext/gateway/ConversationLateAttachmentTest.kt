// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class) @Config(sdk = [28])
class ConversationLateAttachmentTest {
    private val leases = mutableListOf<AutoCloseable>()
    @After fun cleanup() { leases.asReversed().forEach { it.close() }; ConversationSocketComposition.clear() }
    private class Host(val epoch: Long = 7, val publication: AtomicReference<ConversationSocketNegotiation?> = AtomicReference()) {
        val identity = EvidenceIdentity(UUID.randomUUID().toString(), UUID.randomUUID().toString(), "11".repeat(32))
        val queue = ConcurrentLinkedQueue<Runnable>()
        val sends = mutableListOf<JSONObject>()
        var live = true
        var beforeStart: (() -> Unit)? = null
        var onSend: ((JSONObject) -> Unit)? = null
        var creations = 0
        var losses = 0
        val socket = object : okhttp3.WebSocket {
            override fun request() = okhttp3.Request.Builder().url("https://example.org").build()
            override fun queueSize() = 0L
            override fun send(text: String): Boolean {
                val frame = JSONObject(text); sends.add(frame); onSend?.invoke(frame); return true
            }
            override fun send(bytes: okio.ByteString) = error("No content, time or radio request")
            override fun close(code: Int, reason: String?) = true
            override fun cancel() = Unit
        }
        fun register() = ConversationSocketComposition.registerAuthenticatedHost(socket, identity, epoch, Executor { queue.add(it) },
            { check(live) }, { candidate, guard ->
                guard(); check(publication.compareAndSet(null, candidate))
                beforeStart?.invoke(); candidate.startIfCurrent(guard); true
            }, { candidate -> publication.compareAndSet(candidate, null); Unit })
        fun install(beforeCreate: (() -> Unit)? = null): AutoCloseable = checkNotNull(ConversationSocketComposition.installOwned({ selected, owner, actualEpoch ->
            assertSame(socket, selected); assertEquals(identity, owner); assertEquals(epoch, actualEpoch)
            creations++; beforeCreate?.invoke()
            ConversationSocketNegotiation(selected, owner, actualEpoch, { 100L }, Executor { Thread(it).start() }, { _, guard -> guard() }, { losses++ })
        }, enabled = true))
        fun drain() { while (true) (queue.poll() ?: return).run() }
    }
    private fun keep(value: AutoCloseable) = value.also { leases.add(it) }
    @Test fun authenticatedHostBeforeLateInstallationPreservesExactSocketIdentityAndEpoch() {
        val host = Host(); keep(host.register())
        assertEquals(0, host.queue.size); assertTrue(host.sends.isEmpty())
        keep(host.install()); assertEquals(1, host.queue.size); host.drain()
        assertEquals(1, host.creations); assertEquals(1, host.sends.size)
        assertEquals(7L, host.sends.single().getLong("connection_epoch")); assertNotNull(host.publication.get())
    }
    @Test fun installerBeforeAuthenticatedHostPairsOnceAfterProofRegistration() {
        val host = Host(); keep(host.install()); assertEquals(0, host.queue.size)
        keep(host.register()); host.drain(); assertEquals(1, host.creations); assertEquals(1, host.sends.size)
    }
    @Test fun queuedAttachmentCanceledByInstallerCannotStartOrRetrySameHost() {
        val host = Host(); keep(host.register()); val installer = keep(host.install())
        installer.close(); host.drain()
        assertEquals(0, host.creations); assertTrue(host.sends.isEmpty()); assertNull(host.publication.get())
        assertNull(ConversationSocketComposition.installOwned({ _, _, _ -> error("No replacement") }, true))
    }
    @Test fun staleAuthenticatedGenerationCannotCreateOrPublishAfterQueueWait() {
        val host = Host(); keep(host.register()); keep(host.install()); host.live = false; host.drain()
        assertEquals(0, host.creations); assertTrue(host.sends.isEmpty()); assertNull(host.publication.get())
    }
    @Test fun closeAfterPublicationBeforeStartClosesCandidateAndEnqueuesNoReadiness() {
        val host = Host(); keep(host.register()); val installer = keep(host.install())
        host.beforeStart = { installer.close() }; host.drain()
        assertEquals(1, host.creations); assertEquals(1, host.losses); assertTrue(host.sends.isEmpty()); assertNull(host.publication.get())
    }
    @Test fun obsoleteHostAndHeldCreatorCannotClearSuccessorPublication() {
        val publication = AtomicReference<ConversationSocketNegotiation?>()
        val old = Host(publication = publication); val oldHost = keep(old.register())
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val oldInstaller = keep(old.install { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) })
        val delayed = Thread { old.drain() }; delayed.start()
        try {
            assertTrue(entered.await(2, TimeUnit.SECONDS)); oldHost.close(); oldInstaller.close()
            val successor = Host(9, publication); keep(successor.register()); keep(successor.install()); successor.drain()
            val current = publication.get(); assertNotNull(current)
            oldHost.close(); oldInstaller.close(); release.countDown(); delayed.join(2000)
            assertFalse(delayed.isAlive); assertSame(current, publication.get())
            assertTrue(old.sends.isEmpty()); assertEquals(1, old.losses); assertEquals(9L, successor.sends.single().getLong("connection_epoch"))
        } finally { release.countDown(); delayed.join(2000) }
    }
    @Test fun reconnectDoesNotAutomaticallyRetryPriorInstaller() {
        val old = Host(); val oldHost = keep(old.register()); val installer = keep(old.install()); old.drain(); oldHost.close()
        val current = Host(9); keep(current.register()); current.drain()
        assertEquals(0, current.creations); assertTrue(current.sends.isEmpty())
        installer.close(); keep(current.install()); current.drain(); assertEquals(1, current.creations)
    }
    @Test fun concurrentRegistrationAndInstallationScheduleExactlyOneAttempt() {
        val host = Host(); val go = CountDownLatch(1)
        val hostToken = AtomicReference<AutoCloseable>(); val factoryToken = AtomicReference<AutoCloseable>()
        val registrar = Thread { go.await(); hostToken.set(host.register()) }
        val installer = Thread { go.await(); factoryToken.set(host.install()) }
        registrar.start(); installer.start(); go.countDown(); registrar.join(2000); installer.join(2000)
        assertFalse(registrar.isAlive); assertFalse(installer.isAlive)
        keep(checkNotNull(hostToken.get())); keep(checkNotNull(factoryToken.get()))
        assertEquals(1, host.queue.size); host.drain(); assertEquals(1, host.creations); assertEquals(1, host.sends.size)
    }
    @Test fun publicationPrecedesFirstReadinessReplyRouting() {
        val host = Host(); keep(host.register()); keep(host.install())
        host.onSend = { request ->
            val candidate = checkNotNull(host.publication.get())
            candidate.accept(JSONObject().put("v", 1).put("type", "conversation_session")
                .put("challenge", request.getString("challenge")).put("account_id", host.identity.accountId)
                .put("device_id", host.identity.deviceId).put("phone_session", UUID.randomUUID().toString())
                .put("connection_epoch", host.epoch).put("deployment_epoch", 3).put("origin_hash", host.identity.originHash))
        }
        host.drain()
        assertEquals(host.epoch, checkNotNull(host.publication.get()?.wire?.currentSession()).connectionEpoch)
    }
}
