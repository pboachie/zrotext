// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.SystemClock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import okhttp3.WebSocket

/** Distinct passive port for the actual enrolled socket. Health, old owner/physical/content
 * lifetimes and AlphaPump are deliberately absent; this port cannot create an effect. */
internal object TypedHistory03Connections {
    private val current = AtomicReference<Host?>()
    fun register(socket: WebSocket, identity: EvidenceIdentity, epoch: Long, lineVersion: Int,
        handshakePoint: ByteArray, actorCurrent: () -> Unit, elapsedMs: () -> Long = SystemClock::elapsedRealtime): Host {
        actorCurrent(); require(epoch > 0 && lineVersion in 1..2)
        val host = Host(socket, identity.copy(), epoch, lineVersion, handshakePoint.copyOf(), actorCurrent, elapsedMs)
        current.getAndSet(host)?.close()
        return host.also { it.requireCurrent() }
    }
    fun current() = current.get()?.takeIf { try { it.requireCurrent(); true } catch (_: Exception) { false } }

    class Host internal constructor(private val socket: WebSocket, val identity: EvidenceIdentity,
        val epoch: Long, val lineVersion: Int, point: ByteArray, private val actorCurrent: () -> Unit,
        private val elapsed: () -> Long) : AutoCloseable {
        private val point = point.copyOf()
        private val pointB64url = TypedSubmit03Record.base(this.point)
        private val keyId = TypedSubmit03Record.hex(ProtectionOriginProof.signingKeyId(this.point))
        private val closed = AtomicBoolean(false)
        private class Pending(val request: TypedHistory03Request, val sent: Long,
            val future: CompletableFuture<Pair<TypedHistory03Wire.Reply, Pair<Long, ByteArray>>>)
        private val pending = AtomicReference<Pending?>()
        private class OutcomePending(val entry: TypedOutcome03Entry,
            val future: CompletableFuture<TypedOutcome03Wire.Ack>)
        private val outcomePending = AtomicReference<OutcomePending?>()
        private var observation: TypedHistory03Clock.Sample? = null
        private var primaryFloor = 0L
        fun elapsedMs() = elapsed()
        fun point() = point.copyOf()
        fun requireCurrent() { check(!closed.get() && current.get() === this); actorCurrent(); check(!closed.get()) }
        fun requireOriginal(row: TypedSubmit03Record) {
            requireCurrent()
            require(row.accountId == identity.accountId && row.deviceId == identity.deviceId &&
                row.originalOriginSha256 == identity.originHash && row.originalEnrolledPoint == pointB64url &&
                row.originalEnrolledKeyId == keyId && row.lastCallbackOrdinal != null)
            requireCurrent()
        }
        @Synchronized internal fun requireObservation(sample: TypedHistory03Clock.Sample) {
            requireCurrent(); check(observation === sample); requireCurrent()
        }

        /** The dedicated history worker must win its durable new-request entry CAS first.
         * Never wait here from Room, a key/storage lock, ingress gate, UI or socket listener. */
        fun request(expected: TypedSubmit03Record, entry: TypedHistory03Entry): TypedHistory03Clock.Sample {
            Capture03IngressGate.requireOutside()
            val request = entry.consume()
            requireOriginal(expected); request.requireOriginal(expected)
            require(request.entered && request.replyB64url == null && request.connectionEpoch == epoch &&
                request.lineVersion == lineVersion)
            val exactRequest = TypedSubmit03Record.unbase(request.requestB64url)
            val text = Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(exactRequest)).toString()
            val sent = elapsed()
            require(sent >= 0)
            val call = Pending(request, sent, CompletableFuture())
            check(pending.compareAndSet(null, call)) { "A passive history read is already pending" }
            try {
                requireCurrent()
                check(socket.send(text))
                val (reply, received) = call.future.get(10, TimeUnit.SECONDS)
                requireCurrent()
                require(received.first >= sent && received.first - sent <= 2000)
                val sample = TypedHistory03Clock.Sample(this, request, reply, received.first, received.first - sent,
                    received.second.copyOf())
                sample.requireLiveAtPublication()
                synchronized(this) {
                    requireCurrent(); check(pending.get() === call)
                    // Primary-to-primary floor, separate from conservative upper/RTT time.
                    require(reply.serverMs >= primaryFloor)
                    primaryFloor = reply.serverMs
                    observation = sample
                }
                requireObservation(sample)
                return sample
            } finally { pending.compareAndSet(call, null) }
        }

        fun accept(raw: ByteArray) {
            requireCurrent()
            val call = pending.get() ?: return
            val received = elapsed()
            val exact = raw.copyOf()
            try {
                val fields = Profile03Json.objectValue(exact)
                // An old read can arrive after its timeout while another nonce is pending.
                // It cannot publish a clock or change either floor.
                if (fields["request_id"] != call.request.requestId) return
                val reply = TypedHistory03Wire.decode(exact, call.request.query(), identity.accountId, identity.deviceId,
                    epoch, lineVersion, point)
                requireCurrent()
                call.future.complete(reply to (received to exact))
            } catch (failure: Exception) {
                call.future.completeExceptionally(failure)
                throw failure
            }
        }

        /** The same passive original actor, independent of effect-health withdrawal.
         * A committed report envelope enters only once and conveys no current clock. */
        fun report(entry: TypedOutcome03Entry): TypedOutcome03Wire.Ack {
            Capture03IngressGate.requireOutside()
            val bytes = entry.consume()
            requireOriginal(entry.original)
            require(entry.upload.connectionEpoch == epoch)
            val text = Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString()
            val call = OutcomePending(entry, CompletableFuture())
            check(outcomePending.compareAndSet(null, call)) { "A passive outcome report is already pending" }
            try {
                // Last actual same-socket/actor check follows writer and transport waits.
                requireOriginal(entry.original)
                check(socket.send(text))
                val ack = call.future.get(10, TimeUnit.SECONDS)
                requireOriginal(entry.original)
                return ack
            } finally { outcomePending.compareAndSet(call, null) }
        }

        fun acceptOutcome(raw: ByteArray) {
            requireCurrent()
            val call = outcomePending.get() ?: return
            val exact = raw.copyOf()
            try {
                val f = Profile03Json.outcomeAckObject(exact)
                // A late original reply must not fail or settle a different pending event.
                if (f["event_id"] != call.entry.upload.eventId) return
                val ack = TypedOutcome03Wire.Ack.decode(exact, call.entry.original.command(),
                    call.entry.upload.assertion(), epoch)
                // The wire correlates the immutable event, not an individual replay nonce.
                // A same-epoch late receipt for that SAME211 may confirm its original history;
                // this never claims fresh I/O acceptance, time or permission.
                requireOriginal(call.entry.original)
                call.future.complete(ack)
            } catch (failure: Exception) {
                call.future.completeExceptionally(failure)
                throw failure
            }
        }
        override fun close() {
            if (closed.compareAndSet(false, true)) {
                current.compareAndSet(this, null)
                synchronized(this) { observation = null }
                pending.getAndSet(null)?.future?.completeExceptionally(IllegalStateException("History actor connection ended"))
                outcomePending.getAndSet(null)?.future?.completeExceptionally(IllegalStateException("History actor connection ended"))
            }
        }
        override fun toString() = "TypedHistory03Host(passive-original-actor)"
    }
}
