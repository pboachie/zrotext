// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.gateway

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import okhttp3.WebSocket

/** One exact public submit exchange on its original authenticated socket. Room supplies a
 * burned one-use send ticket; the returned ACK remains a candidate for full verification.
 * No status/retry API, legacy event, key operation or platform invocation exists here. */
internal class TypedSubmit03Transport(private val socket: WebSocket,
    private val session: () -> SealedDispatchExecutor.Session?, private val current: () -> Unit,
    private val timeoutMs: Long = 10_000) : AutoCloseable {
    private class Pending(val session: SealedDispatchExecutor.Session, val entry: TypedSubmit03TransportEntry,
        val grant: SealedDispatch03Frames.Grant) {
        val arrived = CountDownLatch(1)
        var ack: TypedSubmit03Wire.Ack? = null
    }
    private val lock = Any()
    @Volatile private var closed = false
    private var waiting: Pending? = null
    init { require(timeoutMs in 1..10_000) }

    /** beforeSend is the already-held RAM lifetime only; it must not acquire Room or key custody. */
    fun submit(entry: TypedSubmit03TransportEntry, input: SealedDispatch03Frames.Grant,
        beforeSend: () -> Unit): TypedSubmit03Wire.Ack {
        val raw = entry.consume() // A failed entry stays burned, including before socket.send.
        val grant = SealedDispatch03Frames.grant(input.json())
        current()
        val actual = checkNotNull(session())
        TypedSubmit03Wire.requireCommand(entry.original.command(), grant, actual)
        check(entry.request.connectionEpoch == actual.connectionEpoch)
        val pending = Pending(actual, entry, grant)
        synchronized(lock) { check(!closed && waiting == null && session() === actual); waiting = pending }
        try {
            current(); beforeSend()
            // All entry work and waits above precede this actual transport-entry guard.
            synchronized(lock) {
                check(!closed && waiting === pending && session() === actual)
                beforeSend(); current()
                check(socket.send(raw.toString(Charsets.UTF_8)))
            }
            check(pending.arrived.await(timeoutMs, TimeUnit.MILLISECONDS))
            current()
            return synchronized(lock) {
                check(!closed && waiting === pending && session() === actual)
                checkNotNull(pending.ack)
            }
        } finally {
            raw.fill(0)
            synchronized(lock) { if (waiting === pending) waiting = null }
        }
    }

    /** The actual source socket listener alone routes this typed frame here. Its original
     * session object and pending event must still be current after public decoding. */
    fun accept(raw: ByteArray): Boolean {
        val pending = synchronized(lock) {
            if (closed) return false
            waiting ?: return false
        }
        current()
        check(session() === pending.session)
        val decoded = TypedSubmit03Wire.Ack.decode(raw, pending.entry.original.command(), pending.grant, pending.session)
        current()
        return synchronized(lock) {
            if (closed || waiting !== pending || session() !== pending.session || pending.ack != null) false
            else { pending.ack = decoded; pending.arrived.countDown(); true }
        }
    }
    override fun close() { synchronized(lock) { closed = true; waiting?.arrived?.countDown() } }
    override fun toString() = "TypedSubmit03Transport(original-socket-only)"
}
