// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.content.Intent
import android.net.ConnectivityManager
import android.app.Service
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Delayed
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** Replacement lifecycle only: fake socket/host/timer, with no HTTP, SMS or Keystore use. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AuthenticatedGatewayServiceReplacementTest {
    private class FakeSocket : WebSocket {
        var cancellations = 0
        var sends = 0
        override fun request() = Request.Builder().url("https://owner.invalid").build()
        override fun queueSize() = 0L
        override fun send(text: String): Boolean { sends += 1; return false }
        override fun send(bytes: ByteString): Boolean { sends += 1; return false }
        override fun close(code: Int, reason: String?) = true
        override fun cancel() { cancellations += 1 }
    }

    private class FakeTimer : ScheduledFuture<String> {
        var cancellations = 0
        override fun cancel(mayInterruptIfRunning: Boolean): Boolean {
            assertFalse(mayInterruptIfRunning)
            cancellations += 1
            return true
        }
        override fun isCancelled() = cancellations > 0
        override fun isDone() = false
        override fun get() = "synthetic"
        override fun get(timeout: Long, unit: TimeUnit) = "synthetic"
        override fun getDelay(unit: TimeUnit) = 0L
        override fun compareTo(other: Delayed) = 0
    }

    private fun field(name: String) = AuthenticatedGatewayService::class.java
        .getDeclaredField(name).apply { isAccessible = true }
    private fun read(service: AuthenticatedGatewayService, name: String): Any? = field(name).get(service)
    private fun put(service: AuthenticatedGatewayService, name: String, value: Any?) = field(name).set(service, value)
    private fun generation(service: AuthenticatedGatewayService) = field("generation").getInt(service)
    private fun policy(service: AuthenticatedGatewayService) = read(service, "reconnect") as DeviceReconnectPolicy
    private fun identity(device: Long) = EvidenceIdentity(UUID(0, 1).toString(), UUID(0, device).toString(), "11".repeat(32))
    private fun replacementIntent() = Intent()
        .putExtra(AuthenticatedGatewayService.EXTRA_URL, "wss://owner.invalid/v1/device-stream")
        .putExtra(AuthenticatedGatewayService.EXTRA_DEVICE_ID, UUID(0, 3).toString())

    private fun withService(body: (AuthenticatedGatewayService) -> Unit) {
        val app = RuntimeEnvironment.getApplication()
        val connectivity = checkNotNull(app.getSystemService(ConnectivityManager::class.java))
        shadowOf(connectivity).setActiveNetworkInfo(null)
        // Prove the actual service will enter WaitForNetwork before seeding old in-memory state.
        assertNull(connectivity.activeNetwork)
        val controller = Robolectric.buildService(AuthenticatedGatewayService::class.java).create()
        try { body(controller.get()) } finally { controller.destroy() }
    }

    private fun seedOldSession(service: AuthenticatedGatewayService, socket: FakeSocket, host: AutoCloseable) {
        put(service, "generation", 41)
        put(service, "socket", socket)
        put(service, "sessionIdentity", identity(2))
        put(service, "conversationHost", host)
        assertEquals(DeviceReconnectPolicy.Action.Connect(DeviceReconnectPolicy.PilotMode.HEARTBEAT_ONLY),
            policy(service).start(true))
        policy(service).authenticated(1000L)
    }

    private fun assertNoClientTraffic(service: AuthenticatedGatewayService) {
        val client = read(service, "client") as OkHttpClient
        assertEquals(0, client.dispatcher.queuedCallsCount())
        assertEquals(0, client.dispatcher.runningCallsCount())
    }

    @Test fun replacementWithoutNetworkRetiresOldHostTimersAndIdentityWithoutReconnecting() {
        withService { service ->
            val oldSocket = FakeSocket()
            var oldHostCloses = 0
            val oldTimer = FakeTimer()
            seedOldSession(service, oldSocket, AutoCloseable { oldHostCloses += 1 })
            put(service, "heartbeat", oldTimer)
            put(service, "awaitingEventId", "synthetic-old-event")
            put(service, "awaitingEventSentAtNanos", 10L)
            put(service, "awaitingInboundId", "synthetic-old-inbound")
            put(service, "inboundSentAtNanos", 20L)
            put(service, "awaitingLineOptOutId", "synthetic-old-opt-out")
            put(service, "lineOptOutSentAtNanos", 30L)
            // These accepted-ACK caches intentionally retain their existing reconnect semantics.
            val installedChallenge = UUID(0, 4)
            put(service, "installedSmsLineChallenge", installedChallenge)
            put(service, "installedSmsLineIsEsim", true)

            assertEquals(Service.START_NOT_STICKY, service.onStartCommand(replacementIntent(), 0, 1))
            assertEquals(42, generation(service))
            assertEquals(1, oldHostCloses)
            assertEquals(1, oldSocket.cancellations)
            assertEquals(0, oldSocket.sends)
            assertEquals(1, oldTimer.cancellations)
            for (name in listOf("socket", "sessionIdentity", "conversationHost", "awaitingEventId",
                "awaitingInboundId", "awaitingLineOptOutId", "activeGrant")) assertNull(name, read(service, name))
            for (name in listOf("awaitingEventSentAtNanos", "inboundSentAtNanos", "lineOptOutSentAtNanos"))
                assertEquals(name, 0L, field(name).getLong(service))
            assertEquals(installedChallenge, read(service, "installedSmsLineChallenge"))
            assertEquals(true, read(service, "installedSmsLineIsEsim"))
            assertEquals("Waiting for network", AuthenticatedGatewayStatus.value)
            assertEquals(DeviceReconnectPolicy.Action.WaitForNetwork, policy(service).retryDue())
            assertNoClientTraffic(service)

            // The duplicate unavailable callback is NoChange; it cannot be relied on to retire the old host.
            AuthenticatedGatewayService::class.java.getDeclaredMethod("refreshNetwork")
                .apply { isAccessible = true }.invoke(service)
            assertEquals(42, generation(service))
            assertNull(read(service, "conversationHost"))
            assertNull(read(service, "socket"))
            assertNoClientTraffic(service)

            // A delayed old callback must not tear down a later in-memory replacement.
            val successorSocket = FakeSocket()
            var successorCloses = 0
            val successorHost = AutoCloseable { successorCloses += 1 }
            put(service, "generation", 43)
            put(service, "socket", successorSocket)
            put(service, "conversationHost", successorHost)
            AuthenticatedGatewayService::class.java.getDeclaredMethod("disconnect", Int::class.javaPrimitiveType,
                DeviceReconnectPolicy.Loss::class.java).apply { isAccessible = true }
                .invoke(service, 41, DeviceReconnectPolicy.Loss.TRANSPORT)
            assertEquals(43, generation(service))
            assertSame(successorSocket, read(service, "socket"))
            assertSame(successorHost, read(service, "conversationHost"))
            assertEquals(0, successorSocket.cancellations)
            assertEquals(0, successorCloses)
        }
    }

    @Test fun replacementFencesOldGenerationBeforeBlockingHostClosure() {
        withService { service ->
            val enteredClose = CountDownLatch(1)
            val releaseClose = CountDownLatch(1)
            val oldSocket = FakeSocket()
            val failure = AtomicReference<Throwable?>()
            val outcome = AtomicReference<Int?>()
            seedOldSession(service, oldSocket, AutoCloseable {
                enteredClose.countDown()
                check(releaseClose.await(5, TimeUnit.SECONDS))
            })
            val worker = thread(name = "synthetic-service-replacement") {
                try { outcome.set(service.onStartCommand(replacementIntent(), 0, 1)) }
                catch (error: Throwable) { failure.set(error) }
            }
            try {
                assertTrue("Host closure was not reached", enteredClose.await(5, TimeUnit.SECONDS))
                // The old socket still exists while closure waits, but its callback generation is already fenced.
                assertEquals(42, generation(service))
                assertSame(oldSocket, read(service, "socket"))
                assertEquals(0, oldSocket.cancellations)
            } finally {
                releaseClose.countDown()
                worker.join(5000L)
            }
            assertFalse("Replacement worker did not settle", worker.isAlive)
            assertNull(failure.get())
            assertEquals(Service.START_NOT_STICKY, outcome.get())
            assertNull(read(service, "socket"))
            assertNull(read(service, "sessionIdentity"))
            assertNull(read(service, "conversationHost"))
            assertEquals(1, oldSocket.cancellations)
            assertNoClientTraffic(service)
        }
    }
}
