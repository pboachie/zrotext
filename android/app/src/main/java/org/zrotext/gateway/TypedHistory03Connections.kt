// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.SystemClock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.WebSocket

/** Distinct passive port for the actual enrolled socket. Health, old owner/physical/content
 * lifetimes and AlphaPump are deliberately absent; this port cannot create an effect. */
internal object TypedHistory03Connections {
    private val current = AtomicReference<Host?>()
    // Notification ONLY. A collector always reads/rechecks the actual current Host;
    // this revision cannot authenticate an actor or become a time/permission snapshot.
    private val revisions = AtomicLong(0)
    private val changes = MutableStateFlow(0L)
    val hostChanges: StateFlow<Long> = changes.asStateFlow()
    private fun changed() { changes.value = revisions.incrementAndGet() }
    fun register(socket: WebSocket, identity: EvidenceIdentity, epoch: Long, lineVersion: Int,
        handshakePoint: ByteArray, actorCurrent: () -> Unit, elapsedMs: () -> Long = SystemClock::elapsedRealtime): Host {
        actorCurrent(); require(epoch > 0 && lineVersion in 1..2)
        val host = Host(socket, identity.copy(), epoch, lineVersion, handshakePoint.copyOf(), actorCurrent, elapsedMs)
        current.getAndSet(host)?.close()
        return host.also { it.requireCurrent(); changed() }
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
        private class ClosurePending(val entry: TypedNoSubmit03Entry, val future: CompletableFuture<ClosureReply>)
        private val closurePending = AtomicReference<ClosurePending?>()
        private var closureObservation: ClosureReply? = null
        class ClosureReply private constructor(private val owner: Host, val io: TypedNoSubmit03Io, private val raw: ByteArray) {
            fun bytes() = raw.copyOf()
            fun requireLiveStatus() {
                owner.requireCurrent()
                synchronized(owner) { check(owner.closureObservation === this) }
                require(io.kind == "status"); owner.requireCurrent()
            }
            companion object { internal fun returned(owner: Host, io: TypedNoSubmit03Io, raw: ByteArray) = ClosureReply(owner, io, raw.copyOf()) }
        }
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
        fun request(expected: TypedSubmit03Record, entry: TypedHistory03Entry, currentDecision: () -> Unit = {}): TypedHistory03Clock.Sample {
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
                requireCurrent(); currentDecision()
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
        /** One original-actor management invocation only after its writer entry. The
         * decision is checked at the actual send, after all storage/transport entry work. */
        fun exchangeClosure(entry: TypedNoSubmit03Entry, currentDecision: () -> Unit): ClosureReply {
            Capture03IngressGate.requireOutside()
            val raw = entry.consume(); requireOriginal(entry.original)
            require(entry.io.connectionEpoch == epoch)
            val text = Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(raw)).toString()
            val call = ClosurePending(entry, CompletableFuture())
            check(closurePending.compareAndSet(null, call))
            try {
                requireOriginal(entry.original); currentDecision(); check(socket.send(text))
                // A returned result remains candidate history after foreground withdrawal.
                // Its private live-status check is independently required for progress.
                return call.future.get(10, TimeUnit.SECONDS)
            } finally { closurePending.compareAndSet(call, null) }
        }
        fun acceptClosure(raw: ByteArray) {
            requireCurrent(); val call = closurePending.get() ?: return
            val exact = raw.copyOf()
            try {
                val f = Profile03Json.noSubmitObject(exact)
                val io = call.entry.io; val p = call.entry.proof; val row = call.entry.original
                val expectedType = when (io.kind) { "challenge" -> "payload_profile_no_submit_challenge03"
                    "status" -> "payload_profile_no_submit_status03"; "proof" -> "payload_profile_no_submit_ack03"; else -> error("Closure operation") }
                if (f["type"] != expectedType) return
                if (f["proof_request_id"] != p.requestId || io.kind == "status" && f["request_id"] != io.requestId) return
                when (io.kind) {
                    "challenge" -> TypedNoSubmit03Wire.decodeChallenge(exact, row, p, epoch)
                    "status" -> TypedNoSubmit03Wire.decodeStatus(exact, row, p, io.requestId, epoch)
                    "proof" -> TypedNoSubmit03Wire.decodeAck(exact, row, p, epoch)
                    else -> error("Closure operation")
                }
                requireOriginal(row)
                val reply = ClosureReply.returned(this, io, exact)
                synchronized(this) { requireCurrent(); check(closurePending.get() === call); closureObservation = reply }
                call.future.complete(reply)
            } catch (failure: Exception) { call.future.completeExceptionally(failure); throw failure }
        }
        override fun close() {
            if (closed.compareAndSet(false, true)) {
                if (current.compareAndSet(this, null)) changed()
                synchronized(this) { observation = null; closureObservation = null }
                pending.getAndSet(null)?.future?.completeExceptionally(IllegalStateException("History actor connection ended"))
                outcomePending.getAndSet(null)?.future?.completeExceptionally(IllegalStateException("History actor connection ended"))
                closurePending.getAndSet(null)?.future?.completeExceptionally(IllegalStateException("History actor connection ended"))
            }
        }
        override fun toString() = "TypedHistory03Host(passive-original-actor)"
    }
}
