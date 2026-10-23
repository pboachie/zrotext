// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import android.os.SystemClock
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import okhttp3.WebSocket

/** Actual ordinary authenticated socket ownership. It is registered only after that socket
 * proves the retained enrolled key and receives its session epoch. Conversation negotiation,
 * SMS permissions, selected SIM, suppression health and a positive protection pin are not
 * prerequisites for setup/passive history. None of these ports can send SMS or grant effects. */
internal object ProtectionOriginConnections {
    private val current = AtomicReference<Host?>()
    fun register(socket: WebSocket, identity: EvidenceIdentity, epoch: Long, handshakePoint: ByteArray,
        currentActor: () -> Unit): Host {
        currentActor(); require(epoch > 0)
        val host = Host(socket, identity.copy(), epoch, handshakePoint.copyOf(), currentActor)
        current.getAndSet(host)?.close()
        return host.also { it.requireCurrent() }
    }
    fun current(): Host? = current.get()?.takeIf { runCatching { it.requireCurrent() }.isSuccess }

    class Received internal constructor(val reply: ProtectionOriginWire.Reply,
        val sentElapsedMs: Long, val receivedElapsedMs: Long, private val owner: Host,
        private val originalBytes: ByteArray) {
        fun requireCurrent() = owner.requireObservation(this)
        fun bytes() = originalBytes.copyOf()
        val epoch get() = owner.epoch
        fun laterMissing(expected: ProtectionOriginAttempt): LaterMissing {
            return LaterMissing.create(this, expected)
        }
        override fun toString() = "ProtectionOriginControlReply(actual-socket-candidate)"
    }
    /** This witness can originate only from a nonce-correlated actual host RPC after a
     * strictly later claim. Raw status JSON/caller booleans cannot create it. It proves no
     * permission; SQL still independently arbitrates absence under its real actor locks. */
    class LaterMissing private constructor(private val received: Received, private val original: ProtectionOriginAttempt) {
        fun requireFor(expected: ProtectionOriginAttempt) { check(expected == original); received.requireCurrent() }
        fun epoch() = received.epoch
        fun bytes() = received.bytes()
        companion object {
            internal fun create(received: Received, expected: ProtectionOriginAttempt): LaterMissing {
                received.requireCurrent(); expected.requireShape()
                val status = received.reply as? ProtectionOriginWire.Status ?: error("Actual original status required")
                require(status.state == "not_found" && status.proofRequestId.toString() == expected.proofRequestId &&
                    received.epoch > checkNotNull(expected.requestEpoch) && expected.coreB64url == null &&
                    expected.deviceEnteredMs == null && expected.canaryEnteredMs == null && expected.bundleB64url == null &&
                    expected.previousProofRequestId == null && !expected.proofSubmitted && expected.acceptedMs == null)
                return LaterMissing(received, expected)
            }
        }
    }
    class Host internal constructor(private val socket: WebSocket, val identity: EvidenceIdentity,
        val epoch: Long, point: ByteArray, private val currentActor: () -> Unit) : AutoCloseable {
        private val originalPoint = point.copyOf().also { ProtectionOriginProof.signingKeyId(it) }
        private val closed = AtomicBoolean(false)
        private class Pending(val command: ProtectionSetupCommand, val association: ProtectionOriginProof.Association?,
            val expected: (ProtectionOriginWire.Reply) -> Boolean, val sent: Long,
            val future: CompletableFuture<Pair<ProtectionOriginWire.Reply, Pair<Long, ByteArray>>>)
        private val pending = AtomicReference<Pending?>()
        private val lastObservation = AtomicReference<Received?>()
        fun point() = originalPoint.copyOf()
        fun requireCurrent() { check(!closed.get() && current.get() === this); currentActor(); check(!closed.get()) }
        internal fun requireObservation(received: Received) {
            requireCurrent(); check(lastObservation.get() === received); requireCurrent()
        }
        fun requireOriginal(command: ProtectionSetupCommand) {
            requireCurrent(); command.requireShape()
            require(command.accountId == identity.accountId && command.deviceId == identity.deviceId &&
                command.originSha256 == identity.originHash &&
                command.enrolledSigningKeyId == Draft02OutboundPreparation.hex(ProtectionOriginProof.signingKeyId(originalPoint)))
            requireCurrent()
        }
        /** Dedicated setup worker only; never call this blocking wait from a Room transaction,
         * storage/key lock, ingress gate, OkHttp listener or the main/UI thread. */
        fun request(command: ProtectionSetupCommand, request: ByteArray,
            association: ProtectionOriginProof.Association? = null,
            expected: (ProtectionOriginWire.Reply) -> Boolean): Received {
            Capture03IngressGate.requireOutside()
            require(request.size <= ProtectionOriginJson.MAX_BYTES)
            val ownedRequest = request.copyOf()
            requireOriginal(command)
            val sent = SystemClock.elapsedRealtime()
            val call = Pending(command, association, expected, sent, CompletableFuture())
            check(pending.compareAndSet(null, call)) { "An original setup request is already pending" }
            try {
                requireCurrent()
                check(socket.send(Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(ownedRequest)).toString()))
                val (reply, received) = call.future.get(10, TimeUnit.SECONDS)
                requireCurrent()
                return Received(reply, sent, received.first, this, received.second).also { lastObservation.set(it) }
            } finally {
                pending.compareAndSet(call, null)
            }
        }
        /** Real listener supplies the ORIGINAL raw text after type routing, before a generic
         * JSONObject can erase duplicate fields. Unsolicited/late replies never publish state. */
        fun accept(raw: ByteArray) {
            requireCurrent()
            val call = pending.get() ?: return
            val received = SystemClock.elapsedRealtime()
            val owned = raw.copyOf()
            try {
                val reply = ProtectionOriginWire.decode(owned, call.command, epoch, originalPoint, call.association)
                // A delayed original response may arrive while an explicit status is pending.
                // It cannot satisfy that new nonce; ignore it without publishing any state.
                if (!call.expected(reply)) return
                requireCurrent()
                call.future.complete(reply to (received to owned))
            } catch (failure: Exception) {
                call.future.completeExceptionally(failure)
                throw failure
            }
        }
        override fun close() {
            if (closed.compareAndSet(false, true)) {
                current.compareAndSet(this, null)
                lastObservation.set(null)
                pending.getAndSet(null)?.future?.completeExceptionally(IllegalStateException("Original setup connection ended"))
            }
        }
        override fun toString() = "ProtectionOriginAuthenticatedHost(redacted)"
    }
}
