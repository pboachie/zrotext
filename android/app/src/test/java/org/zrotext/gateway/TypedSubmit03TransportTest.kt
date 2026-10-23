// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import okhttp3.Request
import okhttp3.WebSocket
import okio.ByteString
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Actual one-use Room ticket and transport lifecycle. A valid ACK here remains only a
 * public candidate; the full current/installed-interval/recipient consumer is separate. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = android.app.Application::class)
class TypedSubmit03TransportTest {
    private class Harness : AutoCloseable {
        val f = TypedSubmit03WireTest.Fixture()
        val dao = f.f.line.db.typedSubmits03()
        val row = TypedSubmit03Record.candidateWithOrigin(f.command, Profile03ExecutionFixture.point(f.f.enrollment), f.f.origins.routingHash)
        private val request = TypedSubmit03Request(row.attemptId, row.eventId, row.commandSha256, f.f.session.connectionEpoch,
            TypedSubmit03Record.base(TypedSubmit03Wire.request(f.command, f.f.grant, f.f.session)))
        val live = AtomicBoolean(true)
        val session = AtomicReference(f.f.session)
        var sends = 0
        var onSend: () -> Unit = {}
        private val socket = object : WebSocket {
            override fun request() = Request.Builder().url(f.f.origins.protocolOrigin).build()
            override fun queueSize() = 0L
            override fun send(text: String): Boolean {
                assertArrayEquals(request.bytes(), text.toByteArray())
                assertEquals(request, dao.submitRequest(row.attemptId))
                sends++; onSend(); return true
            }
            override fun send(bytes: ByteString) = false
            override fun close(code: Int, reason: String?) = true
            override fun cancel() = Unit
        }
        val transport = TypedSubmit03Transport(socket, session::get, { check(live.get()) }, timeoutMs = 100)
        init { check(dao.reserveNewSubmit(row) {}) }
        fun entry() = checkNotNull(dao.enterSubmit(row, request) {})
        fun submit(beforeSend: () -> Unit = {}): TypedSubmit03Wire.Ack = transport.submit(entry(), f.f.grant, beforeSend)
        override fun close() { transport.close(); f.close() }
    }

    @Test fun withdrawalAfterActualRoomEntryButBeforeTransportEntrySendsNothingAndKeepsTheBurn() {
        Harness().use { h ->
            val entry = h.entry()
            var guards = 0
            assertThrows(IllegalStateException::class.java) {
                h.transport.submit(entry, h.f.f.grant) { guards++; if (guards == 2) h.live.set(false); check(h.live.get()) }
            }
            assertEquals(0, h.sends); assertNotNull(h.dao.submitRequest(h.row.attemptId))
            assertNull(h.dao.enterSubmit(h.row, checkNotNull(h.dao.submitRequest(h.row.attemptId))) {})
            assertThrows(IllegalStateException::class.java) { entry.consume() }
        }
    }
    @Test fun correlatedFirstAckIsOwnedAndDuplicateOrUnsolicitedAckCannotReplaceIt() {
        Harness().use { h ->
            assertFalse(h.transport.accept(h.f.ack().toString().toByteArray()))
            h.onSend = {
                assertTrue(h.transport.accept(h.f.ack().toString().toByteArray()))
                assertFalse(h.transport.accept(h.f.ack().toString().toByteArray()))
            }
            val ack = h.submit()
            assertTrue(ack.submitOnce); assertEquals(1, h.sends)
            assertFalse(h.transport.accept(h.f.ack().toString().toByteArray()))
            assertEquals("reserved", h.dao.get(h.row.attemptId)?.phase)
            assertNull(h.dao.get(h.row.attemptId)?.ackSha256)
        }
    }
    @Test fun aDifferentActualSessionObjectCannotDeliverAnAckForTheOriginalSocketWait() {
        Harness().use { h ->
            h.onSend = {
                val old = h.session.get()
                h.session.set(SealedDispatchExecutor.Session(old.accountId, old.deviceId, old.connectionEpoch,
                    old.deploymentEpoch, old.sessionId, old.originHash))
                assertThrows(IllegalStateException::class.java) { h.transport.accept(h.f.ack().toString().toByteArray()) }
            }
            assertThrows(IllegalStateException::class.java) { h.submit() }
            assertEquals(1, h.sends); assertNotNull(h.dao.submitRequest(h.row.attemptId))
            assertNull(h.dao.get(h.row.attemptId)?.ackSha256)
        }
    }
    @Test fun closeWhileWaitingReleasesTheCallerWithoutRetryOrAColdAckPermit() {
        Harness().use { h ->
            val sent = CountDownLatch(1)
            val finished = CountDownLatch(1)
            val failed = AtomicBoolean(false)
            h.onSend = { sent.countDown() }
            val thread = Thread {
                try { h.submit() } catch (_: Exception) { failed.set(true) } finally { finished.countDown() }
            }
            thread.start()
            assertTrue(sent.await(2, TimeUnit.SECONDS))
            h.transport.close()
            assertTrue(finished.await(2, TimeUnit.SECONDS)); thread.join(2_000)
            assertFalse(thread.isAlive); assertTrue(failed.get()); assertEquals(1, h.sends)
            assertNotNull(h.dao.submitRequest(h.row.attemptId))
            assertFalse(h.transport.accept(h.f.ack().toString().toByteArray()))
        }
    }
    @Test fun actualTypedTransportEnforcesTheExistingFullReplyByteBoundary() {
        Harness().use { h ->
            h.onSend = {
                val raw = h.f.ack().toString().toByteArray()
                val bounded = raw + ByteArray(Profile03Json.MAX_BYTES - raw.size) { 32 }
                assertEquals(192 * 1024, bounded.size)
                assertThrows(IllegalArgumentException::class.java) { h.transport.accept(bounded + byteArrayOf(32)) }
                assertTrue(h.transport.accept(bounded))
            }
            assertTrue(h.submit().submitOnce); assertEquals(1, h.sends)
        }
    }
}
